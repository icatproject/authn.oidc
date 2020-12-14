package org.icatproject.authn_oauth2;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;

import javax.annotation.PostConstruct;
import javax.ejb.Stateless;
import javax.json.Json;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;
import javax.json.stream.JsonGenerator;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

import org.icatproject.authentication.AuthnException;
import org.icatproject.utils.AddressChecker;
import org.icatproject.utils.AddressCheckerException;
import org.icatproject.utils.CheckedProperties;
import org.icatproject.utils.CheckedProperties.CheckedPropertyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

/* Mapped name is to avoid name clashes */
@Path("/")
@Stateless
public class OAUTH2_Authenticator {

	private static final Logger logger = LoggerFactory.getLogger(OAUTH2_Authenticator.class);
	private static final Marker fatal = MarkerFactory.getMarker("FATAL");

	private String icatUserClaim;
	private String icatUserFallbackName;
	private String icatUserFallbackMechanism;
	private AddressChecker addressChecker;
	private String mechanism;

	@PostConstruct
	private void init() {
		CheckedProperties props = new CheckedProperties();
		try {
			props.loadFromResource("run.properties");

			icatUserClaim = props.getString("icatUserClaim");

			if (props.has("icatUserFallback")) {
				String icatUserFallback = props.getString("icatUserFallback");

				String[] split = icatUserFallback.split("/");
				if (split.length == 2) {
					icatUserFallbackMechanism = split[0];
					icatUserFallbackName = split[1];
				} else {
					icatUserFallbackMechanism = null;
					icatUserFallbackName = icatUserFallback;
				}
			}

			if (props.has("ip")) {
				String authips = props.getString("ip");
				try {
					addressChecker = new AddressChecker(authips);
				} catch (Exception e) {
					String msg = "Problem creating AddressChecker with information from run.properties "
							+ e.getMessage();
					logger.error(fatal, msg);
					throw new IllegalStateException(msg);
				}
			}

			if (props.has("mechanism")) {
				mechanism = props.getString("mechanism");
			}

		} catch (CheckedPropertyException e) {
			logger.error(fatal, e.getMessage());
			throw new IllegalStateException(e.getMessage());
		}

		logger.info("Initialized OAUTH2_Authenticator");
	}

	@GET
	@Path("version")
	@Produces(MediaType.APPLICATION_JSON)
	public String getVersion() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		JsonGenerator gen = Json.createGenerator(baos);
		gen.writeStartObject().write("version", Constants.API_VERSION).writeEnd();
		gen.close();
		return baos.toString();
	}

	@POST
	@Path("authenticate")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public String authenticate(@FormParam("json") String jsonString) throws AuthnException {

		ByteArrayInputStream s = new ByteArrayInputStream(jsonString.getBytes());

		String token = null;
		String ip = null;
		try (JsonReader r = Json.createReader(s)) {
			JsonObject o = r.readObject();
			for (JsonValue c : o.getJsonArray("credentials")) {
				JsonObject credential = (JsonObject) c;
				if (credential.containsKey("token")) {
					token = credential.getString("token");
				}
			}
			if (o.containsKey("ip")) {
				ip = o.getString("ip");
			}
		}

		logger.debug("Login request: {}", token);

		if (token == null || token.isEmpty()) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token cannot be null or empty");
		}

		if (addressChecker != null) {
			try {
				if (!addressChecker.check(ip)) {
					throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN,
							"authn.oauth2 does not allow log in from your IP address " + ip);
				}
			} catch (AddressCheckerException e) {
				throw new AuthnException(HttpURLConnection.HTTP_INTERNAL_ERROR, e.getClass() + " " + e.getMessage());
			}
		}

		String icatUser;
		String icatMechanism;
		try {
			DecodedJWT decodedJWT = JWT.decode(token);
			String issuerUrl = decodedJWT.getClaim("iss").asString();
			String configUrl = issuerUrl + "/.well-known/openid-configuration";

			URL url = new URL(configUrl);
			HttpURLConnection con = (HttpURLConnection) url.openConnection();
			BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
			StringBuffer response = new StringBuffer();
			String inputLine;
			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}
			in.close();
			JsonReader jsonReader = Json.createReader(new StringReader(response.toString()));
			JsonObject jsonResponse = jsonReader.readObject();
			String jwkUrl = jsonResponse.getString("jwks_uri");

			JwkProvider provider = new JwkProviderBuilder(new URL(jwkUrl)).build();
			Jwk jwk = provider.get(decodedJWT.getKeyId());

			Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
			Verification verifier = JWT.require(algorithm);
			verifier.build().verify(decodedJWT);

			Claim claim = decodedJWT.getClaim(icatUserClaim);
			if (claim.isNull()) {
				if (icatUserFallbackName == null || icatUserFallbackName.isEmpty()) {
					throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN,
							"The token is missing an ICAT user name");
				} else {
					icatUser = icatUserFallbackName;
					icatMechanism = icatUserFallbackMechanism;
				}
			} else {
				icatUser = claim.asString();
				icatMechanism = mechanism;
			}
		} catch (JWTVerificationException | JwkException | IOException | JsonException e) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token is invalid");
		}

		logger.info("User logged in succesfully as {}{}", (icatMechanism != null ? icatMechanism + "/" : ""), icatUser);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (JsonGenerator gen = Json.createGenerator(baos)) {
			gen.writeStartObject().write("username", icatUser);
			if (icatMechanism != null) {
				gen.write("mechanism", icatMechanism);
			}
			gen.writeEnd();
		}
		return baos.toString();
	}

	@GET
	@Path("description")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public String getDescription() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (JsonGenerator gen = Json.createGenerator(baos)) {
			gen.writeStartObject().writeStartArray("keys");
			gen.writeStartObject().write("name", "token").write("hide", true).writeEnd();
			gen.writeEnd().writeEnd();
		}
		return baos.toString();
	}

}

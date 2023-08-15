package org.icatproject.authn_oidc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.ejb.Stateless;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonValue;
import jakarta.json.stream.JsonGenerator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
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
public class OIDC_Authenticator {

	private static final Logger logger = LoggerFactory.getLogger(OIDC_Authenticator.class);
	private static final Marker fatal = MarkerFactory.getMarker("FATAL");

	private OpenidConfigurationManager configurationManager;
	private String icatUserClaim;
	private boolean icatUserClaimException;
	private String requiredScope;
	private AddressChecker addressChecker;
	private String mechanism;
	private boolean icatUserPrependMechanism;

	@PostConstruct
	private void init() {
		CheckedProperties props = new CheckedProperties();
		try {
			props.loadFromResource("run.properties");

			String wellKnownUrl = props.getString("wellKnownUrl");
			String tokenIssuer = props.getString("tokenIssuer");

			try {
				configurationManager = new OpenidConfigurationManager(wellKnownUrl, tokenIssuer);
			} catch (MalformedURLException e) {
				String msg = "Invalid wellKnownUrl URL in run.properties: " + e.getMessage();
				logger.error(fatal, msg);
				throw new IllegalStateException(msg);
			}

			icatUserClaim = props.getString("icatUserClaim");

			icatUserClaimException = false;
			if (props.has("icatUserClaimException")) {
				if (props.getString("icatUserClaimException") == "true") {
					icatUserClaimException = true;
				}
			}

			if (props.has("requiredScope")) {
				requiredScope = props.getString("requiredScope");
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

			icatUserPrependMechanism = false;
			if (props.has("icatUserPrependMechanism")) {
				if (props.getString("icatUserPrependMechanism") == "true") {
					icatUserPrependMechanism = true;
				}
			}

		} catch (CheckedPropertyException e) {
			logger.error(fatal, e.getMessage());
			throw new IllegalStateException(e.getMessage());
		}

		logger.info("Initialized OIDC_Authenticator");
	}

	@PreDestroy
	public void exit() {
		configurationManager.exit();
	}

	@POST
	@Path("jwkupdate")
	public void jwkUpdate() {
		configurationManager.checkJwkProvider();
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
							"authn.oidc does not allow log in from your IP address " + ip);
				}
			} catch (AddressCheckerException e) {
				throw new AuthnException(HttpURLConnection.HTTP_INTERNAL_ERROR, e.getClass() + " " + e.getMessage());
			}
		}

		DecodedJWT decodedJWT;
		try {
			decodedJWT = JWT.decode(token);
		} catch (JWTDecodeException e) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token could not be decoded");
		}

		if (requiredScope != null) {
			Claim scope = decodedJWT.getClaim("scope");
			if (scope.isNull()) {
				throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token is missing the scope claim");
			}
			String[] scopes = scope.asString().split("\\s+");
			if (!Arrays.asList(scopes).contains(requiredScope)) {
				throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN,
						"The token is missing the required scope " + requiredScope);
			}
		}

		Claim iss = decodedJWT.getClaim("iss");
		if (iss.isNull()) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token is missing the iss claim");
		}
		if (!configurationManager.getTokenIssuer().equals(iss.asString())) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN,
					"The iss claim of the token does not match the configured issuer");
		}

		String kid = decodedJWT.getKeyId();
		if (kid == null) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token is missing a kid");
		}

		Jwk jwk;
		try {
			jwk = configurationManager.getJwkProvider().get(kid);
		} catch (JwkException e) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "Unable to find a public key matching the kid");
		} catch (NullPointerException e) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN,
					"The JWK configuration is not ready, try again in a few minutes");
		}

		try {
			Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
			Verification verifier = JWT.require(algorithm);
			verifier.build().verify(decodedJWT);
		} catch (TokenExpiredException e) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token has expired");
		} catch (JWTVerificationException | JwkException e) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token is invalid");
		}

		String icatUser;
		String icatMechanism;
		Claim claim = decodedJWT.getClaim(icatUserClaim);
		if (claim.isNull()) {
			if (icatUserClaimException) {
				throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token is missing an ICAT username");
			} else {
				icatUser = decodedJWT.getClaim("sub").asString();
				icatMechanism = mechanism;
			}
		} else {
			if (icatUserPrependMechanism) {
				icatUser = claim.asString();
				icatMechanism = mechanism;
			} else {
				String[] split = claim.asString().split("/");
				if (split.length == 2) {
					icatMechanism = split[0];
					icatUser = split[1];
				} else {
					icatMechanism = null;
					icatUser = claim.asString();
				}
			}
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

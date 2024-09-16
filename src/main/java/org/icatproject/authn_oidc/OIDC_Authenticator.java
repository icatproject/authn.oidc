package org.icatproject.authn_oidc;

import com.auth0.jwk.Jwk;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.stream.JsonGenerator;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.icatproject.authentication.AuthnException;
import org.jboss.logging.Logger;

import com.auth0.jwt.interfaces.DecodedJWT;

import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.util.Optional;

@Path("/authn.oidc")
@ApplicationScoped
public class OIDC_Authenticator {

    private static final Logger logger = Logger.getLogger(OIDC_Authenticator.class);

    @Inject
    @ConfigProperty(name = "quarkus.application.version")
    String projectVersion;

    @Inject
    @ConfigProperty(name = "icatUserClaim")
    String icatUserClaim;

    @Inject
    @ConfigProperty(name = "tokenIssuer")
    URL tokenIssuer;

    @Inject
    @ConfigProperty(name = "wellKnownUrl")
    URL wellKnownUrl;

    @Inject
    @ConfigProperty(name = "ip")
    Optional<String> ipAddresses;

    @Inject
    @ConfigProperty(name = "requiredScope")
    Optional<String> requiredScope;

    @Inject
    @ConfigProperty(name = "icatUserClaimException")
    Optional<Boolean> icatUserClaimException;

    @Inject
    @ConfigProperty(name = "mechanism")
    Optional<String> mechanism;

    @Inject
    @ConfigProperty(name = "icatUserPrependMechanism")
    Optional<Boolean> icatUserPrependMechanism;

    private KeyVerifier keyVerifier;
    private IPVerifier ipVerifier;

    @PostConstruct
    void init() {
        keyVerifier = new KeyVerifier(wellKnownUrl, tokenIssuer);
        ipVerifier = new IPVerifier(ipAddresses.orElse(null));
        logger.info("Initialised OIDC_Authenticator");
    }

    @POST
    @Path("/authenticate")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public String authenticate(@FormParam("json") String jsonString) throws AuthnException {

        // check the well known address is valid and we can read what we need to
        keyVerifier.checkJwkProvider();

        // Extract the token and IP from the JSON input and store them in the class
        Request request = new Request();
        request.getCredentials(jsonString);

        // Perform IP address checking if required
        ipVerifier.CheckIPs(request.getIps());

        // Create an instance of the TokenVerifier class
        TokenVerifier tokenVerifier = new TokenVerifier(
                requiredScope.orElse(null),             // OPTIONAL: Pass the actual value or null if not present
                icatUserClaim,                                // This is not optional, so pass it directly
                icatUserClaimException.orElse(false),   // OPTIONAL: Extract the boolean value or use a default
                icatUserPrependMechanism.orElse(false)  // OPTIONAL: Pass the actual value or null if not present
        );

        // Get the extracted token
        String token = request.getToken();
        // Decode the token using the tokenVerifier
        DecodedJWT decodedJWT = tokenVerifier.decodeToken(token);
        // Validate required scope
        tokenVerifier.validateScope(decodedJWT);
        // Validate issuer (optional)
        tokenVerifier.validateIssuer(decodedJWT, tokenIssuer);
        // Get the kid (optional if you need to verify it)
        String kid = tokenVerifier.getKid(decodedJWT);
        // Extract the ICAT user from any custom claims imposed on the JWT
        tokenVerifier.extractUserAndSetMechanism(decodedJWT, mechanism.orElse(null));

        Jwk jwk = keyVerifier.getJwk(kid);
        keyVerifier.validateAlgorithm(jwk,decodedJWT);

        String icatMechanism = tokenVerifier.getIcatMechanism();
        logger.info("User logged in successfully as " + (icatMechanism != null ? icatMechanism + "/" : "")
                + tokenVerifier.getIcatUser());

        // Build return JSON
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (JsonGenerator gen = Json.createGenerator(baos)) {
            gen.writeStartObject().write("username", tokenVerifier.getIcatUser());
            if (icatMechanism != null) {
                gen.write("mechanism", icatMechanism);
            }
            gen.writeEnd();
        }
        return baos.toString();
    }

    @POST
    @Path("jwkupdate")
    public void jwkUpdate() throws AuthnException {
        keyVerifier.checkJwkProvider();
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

    @GET
    @Path("version")
    @Produces(MediaType.APPLICATION_JSON)
    public String getVersion() {
        JsonObject versionJson = Json.createObjectBuilder()
                .add("version", projectVersion)
                .build();
        return versionJson.toString();
    }
}


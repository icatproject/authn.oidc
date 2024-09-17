package org.icatproject.authn_oidc;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.icatproject.authentication.AuthnException;
import org.jboss.logging.Logger;

import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;


/**
 * The {@code KeyVerifier} class is responsible for validating the JSON Web Key (JWK)
 * and verifying the algorithm used for signing a JWT.
 * It fetches the OpenID configuration from the well-known URL and extracts
 * necessary information such as the issuer and JWKS URI.
 * <p>
 * It also provides methods to fetch and verify the signing keys (JWK)
 * and the token's algorithm.
 * </p>
 */
@ApplicationScoped
public class KeyVerifier {

    private static final Logger logger = Logger.getLogger(KeyVerifier.class);

    private JwkProvider jwkProvider;

    @Inject
    @ConfigProperty(name = "wellKnownUrl")
    URL wellKnownUrl;

    @Inject
    @ConfigProperty(name = "tokenIssuer")
    URL tokenIssuer;

    /** Method that checks the JWK provider every 24h */
    @Scheduled(every = "24h")
    void scheduledJwkUpdate() {
        try {
            logger.info("Scheduled automatic JWK update started");
            this.checkJwkProvider();
        } catch (AuthnException e) {
            logger.error("Scheduled JWK update failed", e);
        }
    }

    /** Method that gets the well known url from the config,
     * checks certain tags are present and sets the class variable jwkProvider */
    public void checkJwkProvider() throws AuthnException {
        try {
            // Create the HTTP client
            HttpResponse<String> response;
            try (HttpClient client = HttpClient.newHttpClient()) {

                // Build the request to fetch the OpenID configuration
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(wellKnownUrl.toURI())
                        .GET()
                        .build();

                // Send the request and receive the response
                response = client.send(request, HttpResponse.BodyHandlers.ofString());
            }

            // Parse the JSON response
            JsonReader jsonReader = Json.createReader(new StringReader(response.body()));
            JsonObject jsonResponse = jsonReader.readObject();

            // Extract JWKS URI and issuer, makes it optional but then checks it for null
            String jwksUrl = Optional.ofNullable(jsonResponse.getString("jwks_uri", null))
                    .orElseThrow(() -> new RuntimeException("jwks_uri not found in well known url"));

            String issuer = Optional.ofNullable(jsonResponse.getString("issuer", null))
                    .orElseThrow(() -> new RuntimeException("issuer not found in well known url"));

            // Validate issuer matches the token issuer
            if (!tokenIssuer.toString().equals(issuer)) {
                throw new RuntimeException("The issuer in the well-known configuration does not match the tokenIssuer.");
            }

            // Create and set JWK provider
            // Create a URI and then convert it to URL
            URI jwksUri = new URI(jwksUrl);
            jwkProvider = new JwkProviderBuilder(jwksUri.toURL()).build();

            logger.info("jwkProvider updated successfully");

        } catch (Exception e) {
            String msg = "Unable to obtain information from the wellKnownUrl: " + e.getMessage();
            throw new AuthnException(HttpURLConnection.HTTP_BAD_REQUEST, msg);
        }
    }

    /** Method that gets the jwk from the provider */
    public Jwk getJwk(String kid) throws AuthnException {
        logger.info("Getting JWK");
        Jwk jwk;
        try {
            jwk = jwkProvider.get(kid);
        } catch (JwkException e) {
            throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN,
                    "Unable to find a public key matching the kid");
        } catch (NullPointerException e) {
            throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN,
                    "The JWK configuration is not ready, try again in a few minutes");
        }
        return jwk;
    }

    public void validateAlgorithm(Jwk jwk, DecodedJWT decodedJWT) throws AuthnException {
        logger.info("Validating Algorithm");
        try {
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
            Verification verifier = JWT.require(algorithm);
            verifier.build().verify(decodedJWT);
        } catch (TokenExpiredException e) {
            throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token has expired");
        } catch (JWTVerificationException | JwkException e) {
            throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token is invalid");
        }
    }
}

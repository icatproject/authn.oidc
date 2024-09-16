package org.icatproject.authn_oidc;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.icatproject.authentication.AuthnException;
import org.jboss.logging.Logger;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;


/**
 * The {@code TokenVerifier} class is responsible for verifying and validating
 * the claims within a JWT token, such as the scope, issuer, and ICAT user claim.
 *
 * <p>This class also extracts the user information and mechanism from the token
 * for further processing. In doing so, it checks whether a user name in the claim
 * has the mechanism appended to it.</p>
 *
 * <p>The following values are used, which are configured in the {@code application.properties}:</p>
 * <ul>
 *   <li>{@code requiredScope}: OPTIONAL: default = {@code null}.</li>
 *   <li>{@code icatUserClaim}: The value set in the application.properties.</li>
 *   <li>{@code icatUserClaimException}: OPTIONAL: default = {@code false}.</li>
 *   <li>{@code icatUserPrependMechanism}: OPTIONAL: default = {@code false}.</li>
 * </ul>
 */
public class TokenVerifier {

    private static final Logger logger = Logger.getLogger(TokenVerifier.class);

    private final String requiredScope;
    private final String icatUserClaim;
    private final boolean icatUserClaimException;
    private final boolean icatUserPrependMechanism;

    // Instance variables to store after validation
    private String icatUser;
    private String icatMechanism;

    /**  Constructor that sets class variables for later validation */
    public TokenVerifier(String requiredScope, String icatUserClaim,
                         boolean icatUserClaimException,
                         boolean icatUserPrependMechanism) {
        this.requiredScope = requiredScope;
        this.icatUserClaim = icatUserClaim;
        this.icatUserClaimException = icatUserClaimException;
        this.icatUserPrependMechanism = icatUserPrependMechanism;
    }

    /**  Method that returns the decoded token */
    public DecodedJWT decodeToken(String token) throws AuthnException {
        try {
            logger.info("Decoding token: " + token);
            return JWT.decode(token);
        } catch (JWTDecodeException e) {
            throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token could not be decoded");
        }
    }

    /** Method that checks the scope exists in the token */
    public void validateScope(DecodedJWT decodedJWT) throws AuthnException {
        if (requiredScope != null) {
            Claim scope = decodedJWT.getClaim("scope");
            logger.info("Validating scope: " + scope.asString());
            if (scope.isNull()) {
                throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token is missing the scope claim");
            }
            String[] scopes = scope.asString().split("\\s+");

            if (!Arrays.asList(scopes).contains(requiredScope)) {
                throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token is missing the required scope "
                        + requiredScope);
            }
        }
    }

    /** Method that checks the issuer in the token is that set out in the config */
    public void validateIssuer(DecodedJWT decodedJWT, URL tokenIssuer) throws AuthnException {
        logger.info("Vaildating issuer");
        Claim iss = decodedJWT.getClaim("iss");
        if (iss.isNull()) {
            throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token is missing the iss claim");
        }
         // compare with a tokenIssuer in config
         if (!tokenIssuer.toExternalForm().equals(iss.asString())) {
             throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The iss claim of the token does not " +
                     "match the configured issuer");
         }
    }

    public String getKid(DecodedJWT decodedJWT) throws AuthnException {
        logger.info("Getting KID");
        String kid = decodedJWT.getKeyId();
        if (kid == null) {
            throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token is missing a kid");
        }
        return kid;
    }

    /**  Method that checks the claim in the config exists (if set) in the token.
     * If not, the fallback is to use the tokens subject as the username.
     * It then checks to see if the mechanism is appended to the username and splits them */
    public void extractUserAndSetMechanism(DecodedJWT decodedJWT, String mechanism) throws AuthnException {
        logger.info("Getting user claim and setting mechanism");
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
    }

    /**  Getter for icatUser */
    public String getIcatUser() {
        return icatUser;
    }

    /**  Getter for mechanism */
    public String getIcatMechanism() {
        return icatMechanism;
    }
}

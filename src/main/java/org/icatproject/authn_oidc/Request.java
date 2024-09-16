package org.icatproject.authn_oidc;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonValue;
import org.icatproject.authentication.AuthnException;
import org.jboss.logging.Logger;

import java.io.ByteArrayInputStream;
import java.net.HttpURLConnection;

/**
 * The {@code Request} class is responsible for extracting credentials from a
 * JSON string, including a token and an optional IP address.
 * <p>
 * This class provides methods to retrieve the extracted token and IP address,
 * and checks that the token is not null or empty.
 * </p>
 */
public class Request {

    private static final Logger logger = Logger.getLogger(Request.class);

    private String token;
    private String ips;

    public Request() {
        this.token = null;  // Default to null
        this.ips = null;     // Default to null
    }

    public String getToken() {
        return this.token;
    }

    public String getIps() {
        return this.ips;
    }

    /** Method that pulls credentials out of json string */
    public void getCredentials(String jsonString) throws AuthnException {
        logger.info("Unpacking request to extract credentials");
        ByteArrayInputStream stream = new ByteArrayInputStream(jsonString.getBytes());
        try (JsonReader r = Json.createReader(stream)) {
            JsonObject o = r.readObject();
            for (JsonValue c : o.getJsonArray("credentials")) {
                JsonObject credential = (JsonObject) c;
                if (credential.containsKey("token")) {
                    this.token = credential.getString("token");
                }
            }
            if (o.containsKey("ip")) {
                logger.info("Found IPs");
                this.ips = o.getString("ip");
            }
        }

        if (this.token == null || this.token.isEmpty()) {
            throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The token cannot be null or empty");
        }
    }
}

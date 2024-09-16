package org.icatproject.authn_oidc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class KeycloakTokenFetcher {

    // These values should match what's in the keycloak config, reals-export.json.
    // These get loaded into our test keycloak instance thorough the docker-compose file.
    private static final String SERVER_URL = "http://localhost:5050";
    private static final String REALM = "icat";
    private static final String CLIENT_ID = "my-client";
    private static final String CLIENT_SECRET = "my-client-secret";
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String SCOPE = "icat_login";

    public static String getJwtToken() throws Exception {
        String body = "client_id=" + URLEncoder.encode(CLIENT_ID, StandardCharsets.UTF_8)
                + "&client_secret=" + URLEncoder.encode(CLIENT_SECRET, StandardCharsets.UTF_8)
                + "&grant_type=password"
                + "&username=" + URLEncoder.encode(USERNAME, StandardCharsets.UTF_8)
                + "&password=" + URLEncoder.encode(PASSWORD, StandardCharsets.UTF_8)
                + "&scope=" + URLEncoder.encode(SCOPE, StandardCharsets.UTF_8);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(SERVER_URL + "/realms/" + REALM + "/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response;
        try (HttpClient client = HttpClient.newHttpClient()) {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        }

        // Parse the response to extract the token
        String responseBody = response.body();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readTree(responseBody);

        return jsonNode.get("access_token").asText();
    }
}

package org.icatproject.authn_oidc;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import javax.json.Json;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonReader;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;

public class OpenidConfigurationManager {

    private URL openidConfigurationUrl;
    private String tokenIssuer;
    private JwkProvider jwkProvider;

    public OpenidConfigurationManager(String wellKnownUrl, String issuer) {
        try {
            openidConfigurationUrl = new URL(wellKnownUrl);
        } catch (MalformedURLException e) {
            String msg = "Invalid wellKnownUrl URL in run.properties: " + e.getMessage();
            throw new IllegalArgumentException(msg);
        }
        tokenIssuer = issuer;
    }

    public String getTokenIssuer() {
        return tokenIssuer;
    }

    public JwkProvider getJwkProvider() {

        JsonObject jsonResponse;
        try {
            HttpURLConnection con = (HttpURLConnection) openidConfigurationUrl.openConnection();
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            StringBuffer response = new StringBuffer();
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            JsonReader jsonReader = Json.createReader(new StringReader(response.toString()));
            jsonResponse = jsonReader.readObject();
        } catch (IOException | JsonException e) {
            String msg = "Unable to obtain information from the wellKnownUrl in run.properties: " + e.getMessage();
            throw new IllegalArgumentException(msg);
        }

        String issuer;
        try {
            String jwksUrl = jsonResponse.getString("jwks_uri");
            jwkProvider = new JwkProviderBuilder(new URL(jwksUrl)).build();
            issuer = jsonResponse.getString("issuer");
        } catch (NullPointerException | MalformedURLException e) {
            String msg = "Unable to obtain jwk provider or issuer: " + e.getMessage();
            throw new IllegalArgumentException(msg);
        }

        if (!tokenIssuer.equals(issuer)) {
            String msg = "The issuer in the well-known configuration does not match the tokenIssuer in run.properties.";
            throw new IllegalArgumentException(msg);
        }

        return jwkProvider;
    }

}

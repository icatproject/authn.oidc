package org.icatproject.authn_oidc;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Scanner;

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
    private File timestampFile;

    public OpenidConfigurationManager(String wellKnownUrl, String issuer) {
        try {
            openidConfigurationUrl = new URL(wellKnownUrl);
        } catch (MalformedURLException e) {
            String msg = "Invalid wellKnownUrl URL in run.properties: " + e.getMessage();
            throw new IllegalArgumentException(msg);
        }
        tokenIssuer = issuer;

        timestampFile = new File("auth.oidc-timestamp");
        readTimestampFile();
    }

    public String getTokenIssuer() {
        return tokenIssuer;
    }

    public JwkProvider getJwkProvider() {
        long lastTimestamp = readTimestampFile();
        long timestamp = Instant.now().minus(1, ChronoUnit.DAYS).getEpochSecond();
        if (timestamp > lastTimestamp) {
            checkJwkProvider();
            writeTimestampFile(Instant.now().getEpochSecond());
        }
        return jwkProvider;
    }

    private void checkJwkProvider() {
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
    }

    private long readTimestampFile() {
        long timestamp = 0L;
        Scanner scan;
        try {
            scan = new Scanner(timestampFile);
            if (scan.hasNextLong()) {
                timestamp = scan.nextLong();
            }
            scan.close();
        } catch (FileNotFoundException e) {
            writeTimestampFile(timestamp);
        }
        return timestamp;
    }

    private void writeTimestampFile(long timestamp) {
        String str = String.valueOf(timestamp);
        FileWriter writer;
        try {
            writer = new FileWriter(timestampFile);
            writer.write(str);
            writer.close();
        } catch (IOException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

}

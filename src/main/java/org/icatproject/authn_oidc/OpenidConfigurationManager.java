package org.icatproject.authn_oidc;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Timer;
import java.util.TimerTask;

import javax.json.Json;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonReader;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OpenidConfigurationManager {

    public class Action extends TimerTask {

        @Override
        public void run() {
            Thread.currentThread().setPriority(Thread.MAX_PRIORITY);
            try {
                checkJwkProvider();
            } catch (RuntimeException e) {
                logger.error(e.getMessage());
                timer.schedule(new Action(), shortIntervalMillis);
            } finally {
                timer.schedule(new Action(), intervalMillis);
            }
        }
    }

    private static final Logger logger = LoggerFactory.getLogger(OpenidConfigurationManager.class);

    private URL openidConfigurationUrl;
    private String tokenIssuer;
    private JwkProvider jwkProvider;

    private long intervalMillis = 86400000L; // every 24 hours
    private long shortIntervalMillis = 60000L; // every minute
    private Timer timer = new Timer();

    public OpenidConfigurationManager(String wellKnownUrl, String issuer) throws MalformedURLException {
        openidConfigurationUrl = new URL(wellKnownUrl);
        tokenIssuer = issuer;

        timer.schedule(new Action(), shortIntervalMillis);
    }

    public String getTokenIssuer() {
        return tokenIssuer;
    }

    public JwkProvider getJwkProvider() {
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
            throw new RuntimeException(msg);
        }

        String issuer;
        try {
            String jwksUrl = jsonResponse.getString("jwks_uri");
            jwkProvider = new JwkProviderBuilder(new URL(jwksUrl)).build();
            issuer = jsonResponse.getString("issuer");
        } catch (NullPointerException | MalformedURLException e) {
            String msg = "Unable to obtain jwk provider or issuer: " + e.getMessage();
            throw new RuntimeException(msg);
        }

        if (!tokenIssuer.equals(issuer)) {
            String msg = "The issuer in the well-known configuration does not match the tokenIssuer in run.properties.";
            throw new RuntimeException(msg);
        }
    }

}

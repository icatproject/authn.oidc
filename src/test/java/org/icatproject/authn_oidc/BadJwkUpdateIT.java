package org.icatproject.authn_oidc;

import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import org.icatproject.authn_oidc.TestProfiles.WellKnownTestProfile;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.equalTo;

@QuarkusIntegrationTest
@TestProfile(WellKnownTestProfile.class)
public class BadJwkUpdateIT {

    @Test
    public void jwkUpdate() {
        RestAssured.given()
                .when().post("/authn.oidc/jwkupdate")
                .then()
                .statusCode(400)
                .body("message", equalTo("Unable to obtain information from the wellKnownUrl: " +
                        "jwks_uri not found in well known url"));
    }
}
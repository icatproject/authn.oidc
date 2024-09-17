package org.icatproject.authn_oidc;

import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.equalTo;

@QuarkusIntegrationTest
public class GoodJwkUpdateIT {

    @Test
    public void jwkUpdate() {
        RestAssured.given()
                .when().post("/authn.oidc/jwkupdate")
                .then()
                .statusCode(200)
                .body(equalTo("JWK update completed successfully."));
    }
}
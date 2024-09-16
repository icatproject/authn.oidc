package org.icatproject.authn_oidc;

import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.ws.rs.core.Response;
import org.icatproject.authn_oidc.TestProfiles.WellKnownTestProfile;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@QuarkusIntegrationTest
@TestProfile(WellKnownTestProfile.class)
public class WellKnownIT {
	@Test
	public void WellKnownTest() {

		// Perform an HTTP POST request and expect an exception during the JWK provider initialization
			given()
					.header("Content-Type", "application/x-www-form-urlencoded")
					.when()
					.post("/authn.oidc/authenticate")
					.then()
					.statusCode(Response.Status.BAD_REQUEST.getStatusCode())  // Expect 400 Bad Request
					.body("message", equalTo("Unable to obtain information from the wellKnownUrl: " +
							"jwks_uri not found in well known url"));
		}
}



package org.icatproject.authn_oidc;

import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.ws.rs.core.Response;
import org.icatproject.authn_oidc.TestProfiles.ClaimTestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.matchesPattern;
import static org.icatproject.authn_oidc.KeycloakTokenFetcher.getJwtToken;

@QuarkusIntegrationTest
@TestProfile(ClaimTestProfile.class)
public class ClaimIT {

	private static String validJWT;

	@BeforeAll
	public static void getJWK() throws Exception {
		validJWT = getJwtToken();
	}

	@Test
	public void IssuerTest() {
		String jsonString = "{\"credentials\":[{\"token\":\"" + validJWT + "\"}]}";
		String uuidPattern = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";

		// If the claim name can't be found, then the fallback is to use the "sub" as a username.
		// In our case, this will be a UUID
			given()
					.header("Content-Type", "application/x-www-form-urlencoded")
					.formParam("json", jsonString)
					.when()
					.post("/authn.oidc/authenticate")
					.then()
					.statusCode(Response.Status.OK.getStatusCode())
					.body("username", matchesPattern(uuidPattern));
		}
}



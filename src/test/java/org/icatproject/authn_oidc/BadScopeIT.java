package org.icatproject.authn_oidc;

import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.ws.rs.core.Response;
import org.icatproject.authn_oidc.TestProfiles.BadScopeTestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.icatproject.authn_oidc.KeycloakTokenFetcher.getJwtToken;

@QuarkusIntegrationTest
@TestProfile(BadScopeTestProfile.class)
public class BadScopeIT {

	private static String validJWT;

	@BeforeAll
	public static void getJWK() throws Exception {
		validJWT = getJwtToken();
	}

	@Test
	public void badScopeTest() {
		String jsonString = "{\"credentials\":[{\"token\":\"" + validJWT + "\"}]}";

		given()
				.header("Content-Type", "application/x-www-form-urlencoded")
				.formParam("json", jsonString)
				.when()
				.post("/authn.oidc/authenticate")
				.then()
				.statusCode(Response.Status.FORBIDDEN.getStatusCode())
				.body("message", equalTo("The token is missing the required scope someOtherScope"));
	}
}

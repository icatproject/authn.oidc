package org.icatproject.authn_oidc;

import io.quarkus.test.junit.QuarkusIntegrationTest;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.icatproject.authn_oidc.KeycloakTokenFetcher.getJwtToken;

@QuarkusIntegrationTest
public class AuthenticateIT {

	private static String validJWT;

	@BeforeAll
	public static void getJWK() throws Exception {
		validJWT = getJwtToken();
	}

	@Test
	public void testValidLoginUser() {
		// JSON string to be sent as form data
		String jsonString = "{\"credentials\":[{\"token\":\"" + validJWT + "\"}]}";

		given()
				.header("Content-Type", "application/x-www-form-urlencoded")
				.formParam("json", jsonString)
				.when()
				.post("/authn.oidc/authenticate")
				.then()
				.statusCode(Response.Status.OK.getStatusCode())
				.body("username", equalTo("user1"));
	}
}

package org.icatproject.authn_oidc;

import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.ws.rs.core.Response;
import org.icatproject.authn_oidc.TestProfiles.IPTestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.icatproject.authn_oidc.KeycloakTokenFetcher.getJwtToken;

@QuarkusIntegrationTest
@TestProfile(IPTestProfile.class)
public class IPTestsIT {

	private static String validJWT;

	@BeforeAll
	public static void getJWK() throws Exception {
		validJWT = getJwtToken();
	}

	@Test
	public void testNoIpInRequest() {
		String jsonString = "{\"credentials\":[{\"token\":\"" + validJWT + "\"}]}";

		// Perform an HTTP POST request without IP in the request body
		given()
				.header("Content-Type", "application/x-www-form-urlencoded")
				.formParam("json", jsonString)
				.when()
				.post("/authn.oidc/authenticate")
				.then()
				.statusCode(Response.Status.BAD_REQUEST.getStatusCode())
				.body("message", equalTo("An IP address must be provided"));
	}

	@Test
	public void badIpInRequest() {
		String jsonString = "{\"credentials\":[{\"token\":\"" + validJWT + "\"}], \"ip\":\"192.167.0.125\"}";

		// Perform an HTTP POST request with a bad IP address
		given()
				.header("Content-Type", "application/x-www-form-urlencoded")
				.formParam("json", jsonString)
				.when()
				.post("/authn.oidc/authenticate")
				.then()
				.statusCode(Response.Status.FORBIDDEN.getStatusCode())
				.body("message", equalTo("authn_oidc does not allow log in from your IP address 192.167.0.125"));
	}

	@Test
	public void goodIpInRequest() {
		String jsonString = "{\"credentials\":[{\"token\":\"" + validJWT + "\"}], \"ip\":\"192.168.0.125\"}";

		// Perform an HTTP POST request with a valid IP address
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

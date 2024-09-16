package org.icatproject.authn_oidc;

import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.ws.rs.core.Response;
import org.icatproject.authn_oidc.TestProfiles.IssuerTestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.icatproject.authn_oidc.KeycloakTokenFetcher.getJwtToken;

@QuarkusIntegrationTest
@TestProfile(IssuerTestProfile.class)
public class IssuerIT {

	private static String validJWT;

	@BeforeAll
	public static void getJWK() throws Exception {
		validJWT = getJwtToken();
	}

	@Test
	public void IssuerTest() {
		String jsonString = "{\"credentials\":[{\"token\":\"" + validJWT + "\"}]}";

		// Perform an HTTP POST request and expect an exception during the JWK provider initialization
			given()
					.header("Content-Type", "application/x-www-form-urlencoded")
					.formParam("json", jsonString)
					.when()
					.post("/authn.oidc/authenticate")
					.then()
					.statusCode(Response.Status.BAD_REQUEST.getStatusCode())
					.body("message", equalTo("Unable to obtain information from the wellKnownUrl: " +
							"The issuer in the well-known configuration does not match the tokenIssuer."));
		}
}



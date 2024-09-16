package org.icatproject.authn_oidc;

import io.quarkus.test.junit.QuarkusIntegrationTest;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@QuarkusIntegrationTest
public class VersionIT {

    @Test
    public void testVersion() throws Exception {

        // Get the version from the pom.xml
        String expectedVersion = getVersionFromPom();

        given()
                .when()
                .get("/authn.oidc/version")
                .then()
                .statusCode(Response.Status.OK.getStatusCode())
                .body("version", equalTo(expectedVersion));
    }

    // Helper method to load the version from the pom.xml
    private String getVersionFromPom() throws Exception {
        File pomFile = new File("pom.xml");
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(pomFile);
        doc.getDocumentElement().normalize();
        Element versionElement = (Element) doc.getElementsByTagName("version").item(0);
        return versionElement.getTextContent();
    }
}

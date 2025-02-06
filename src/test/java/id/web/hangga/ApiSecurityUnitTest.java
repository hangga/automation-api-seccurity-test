package id.web.hangga;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.restassured.RestAssured;
import io.restassured.response.Response;

public class ApiSecurityUnitTest {

    private static WireMockServer wireMockServer;

    @BeforeAll
    public static void setup() {
        wireMockServer = new WireMockServer(8080);
        wireMockServer.start();

        // Set the base URL for RestAssured to WireMock server
        RestAssured.baseURI = "http://localhost:8080";
        RestAssured.defaultParser = io.restassured.parsing.Parser.JSON;

        // Setup WireMock stubs
        setupStubs();
    }

    @AfterAll
    public static void teardown() {
        // Stop WireMock server
        wireMockServer.stop();
    }

    private static void setupStubs() {
        // Stub for unauthorized access
        stubFor(get(urlEqualTo("/private-endpoint"))
            .willReturn(aResponse().withStatus(401)
            .withHeader("Content-Type", "application/json")
            .withBody("{\"message\":\"Unauthorized\"}")));

        // Stub for SQL injection test
        stubFor(get(urlMatching("/posts.*"))
            .willReturn(aResponse().withStatus(500)
            .withHeader("Content-Type", "application/json")
            .withBody("[]")));

        // Stub for XSS test
        stubFor(post(urlEqualTo("/posts"))
            .withRequestBody(containing("<script>alert('XSS')</script>"))
            .willReturn(aResponse().withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"body\":\"<script>alert('XSS')</script>\"}")));

        // Stub for rate limiting test
        stubFor(get(urlEqualTo("/rate-limited-endpoint"))
            .inScenario("Rate Limiting Scenario")
            .whenScenarioStateIs(STARTED)
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("[]"))
            .willSetStateTo("Rate Limit Exceeded"));

        stubFor(get(urlEqualTo("/rate-limited-endpoint"))
            .inScenario("Rate Limiting Scenario")
            .whenScenarioStateIs("Rate Limit Exceeded")
            .willReturn(aResponse()
                .withStatus(429)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"error\":\"Too Many Requests\"}")));

        // Stub for CSRF protection test
        stubFor(post(urlEqualTo("/posts"))
            .withHeader("X-CSRF-Token", containing("invalid-token"))
            .willReturn(aResponse().withStatus(403)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"error\":\"Invalid CSRF token\"}")));

        // Stub for missing authentication token
        stubFor(get(urlEqualTo("/private-endpoint"))
            .willReturn(aResponse().withStatus(401)
            .withHeader("Content-Type", "application/json")
            .withBody("{\"message\":\"Unauthorized\"}")));


        // Stub for invalid data test
        stubFor(post(urlEqualTo("/posts"))
            .withRequestBody(containing("-"))
            .willReturn(aResponse()
                .withStatus(403)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"error\":\"Invalid input\"}")));

        // Stub for sensitive data exposure test
        stubFor(get(urlEqualTo("/users/1"))
            .willReturn(aResponse().withStatus(200)
            .withHeader("Content-Type", "application/json")
            .withBody("{\"email\":\"user@example.com\"}")));

        // Stub for security headers test
        stubFor(get(urlEqualTo("/posts")).willReturn(aResponse().withStatus(200)
            .withHeader("Content-Security-Policy", "default-src 'self'")
            .withHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            .withBody("[]")));

        // Stub for HTTPS only test (not applicable in WireMock setup, so omitted)
    }

    @Test
    public void testUnauthorizedAccess() {
        given().when()
            .get("/private-endpoint")
            .then()
            .statusCode(401)
            .body("message", equalTo("Unauthorized"));
    }

    @Test
    public void testSQLInjection() {
        String maliciousInput = "' OR '1'='1";

        given().param("q", maliciousInput)
            .when()
            .get("/posts")
            .then()
            .statusCode(500);
    }

    @Test
    public void testXSS() {
        String xssPayload = "<script>alert('XSS')</script>";

        given()
            .body("{\"body\":\"" + xssPayload + "\"}")
            .when()
            .post("/posts")
            .then()
            .statusCode(201)
            .body("body", equalTo(xssPayload));
    }

    @Test
    public void testRateLimiting() {
        for (int i = 0; i < 3; i++) {
            Response response = given()
                .when()
                .get("/rate-limited-endpoint")
                .then()
                .extract()
                .response();

            if (i > 0) {
                response.then().statusCode(429).body("error", equalTo("Too Many Requests"));
            } else {
                response.then().statusCode(200);
            }
        }
    }

    @Test
    public void testCSRFProtection() {
        given().header("X-CSRF-Token", "invalid-token")
            .when()
            .post("/posts")
            .then()
            .statusCode(403)
            .body("error", equalTo("Invalid CSRF token"));
    }

    @Test
    public void testMissingAuthenticationToken() {
        given().when()
            .get("/private-endpoint")
            .then()
            .statusCode(401)
            .body("message", equalTo("Unauthorized"));
    }

    @Test
    public void testInvalidData() {

        given()
            .body("-")
            .when()
            .post("/posts")
            .then()
            .statusCode(403)
            .body("error", equalTo("Invalid input"));
    }

    @Test
    public void testSensitiveDataExposure() {
        given().when()
            .get("/users/1")
            .then()
            .statusCode(200)
            .body("email", containsString("@example.com"));
    }

    @Test
    public void testSecurityHeaders() {
        given().when()
            .get("/posts")
            .then()
            .statusCode(200)
            .header("Content-Security-Policy", notNullValue())
            .header("Strict-Transport-Security", notNullValue());
    }
}

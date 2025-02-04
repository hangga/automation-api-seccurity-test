package id.web.hangga;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.util.Arrays;
import java.util.stream.IntStream;

import org.eclipse.jetty.http.HttpMethod;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;

public class ApiSecurityUnitTest {

    private static final String API_URL = "http://localhost:8080/";

    private static WireMockServer wireMockServer;

    @BeforeAll
    public static void setUp() {
        wireMockServer = new WireMockServer(8080);
        wireMockServer.start();
        configureFor("localhost", 8080);
        RestAssured.baseURI = API_URL;
    }

//    @BeforeAll
//    public static void setUp() {
//        wireMockServer = new WireMockServer(8080);
//        wireMockServer.start();
//        configureFor("localhost", 8080);
//
//        stubFor(post("/auth/login").withHeader("Content-Type", containing("application/json"))
//            .willReturn(aResponse().withStatus(200)
//                .withHeader("X-Content-Type-Options", "nosniff")
//                .withHeader("Content-Type", "application/json")));
//
//        stubFor(post("/auth/login").withHeader("Content-Type", containing("application/json"))
//            .inScenario("Brute Force")
//            .whenScenarioStateIs(STARTED)
//            .willReturn(aResponse().withStatus(401)
//                .withHeader("X-Content-Type-Options", "nosniff"))
//            .willSetStateTo("BLOCKED"));
//
//        stubFor(post("/auth/login").withHeader("Content-Type", containing("application/json"))
//            .inScenario("Brute Force")
//            .whenScenarioStateIs("BLOCKED")
//            .willReturn(aResponse().withStatus(401)
//                .withHeader("X-Content-Type-Options", "nosniff")
//                .withBody("{ \"message\": \"Too many failed attempts\" }")));
//
//        stubFor(post("/auth/login").withHeader("Content-Type", containing("application/json"))
//            .withRequestBody(containing("' OR '1'='1"))
//            .willReturn(aResponse().withStatus(422)
//                .withHeader("X-Content-Type-Options", "nosniff")
//                .withBody("{ \"message\": \"SQL Injection attempt detected\" }")));
//
//        stubFor(post("/auth/login")
//            .withHeader("Content-Type", containing("application/json"))
//            .withRequestBody(equalToJson("{\"username\": \"validuser\", \"password\": \"correctpassword\", \"email\" : \"valid@example.com\"}"))
//            .willReturn(aResponse().withStatus(200)
//                .withHeader("Content-Type", "application/json")
//                .withHeader("X-Content-Type-Options", "nosniff")
//                .withBody("{ \"token\": \"valid-jwt-token\" }")));
//
//        stubFor(post("/auth/signup").withHeader("Content-Type", containing("application/json"))
//            .willReturn(aResponse().withStatus(201)
//                .withHeader("Content-Type", "application/json")
//                .withHeader("X-Content-Type-Options", "nosniff")
//                .withBody("{ \"message\": \"User created successfully\" }")));
//
//        stubFor(post("/auth/signup").withRequestBody(
//                equalToJson("{\"username\": \"existinguser\", \"password\": \"password123\", \"email\": \"existing@example.com\"}"))
//            .willReturn(aResponse().withStatus(409)
//                .withHeader("Content-Type", "application/json")
//                .withHeader("X-Content-Type-Options", "nosniff")
//                .withBody("{ \"message\": \"Username already exists\" }")));
//
//        stubFor(post("/auth/signup").withRequestBody(matchingJsonPath("$.email", matching("^[^@]+$")))
//            .willReturn(aResponse().withStatus(400)
//                .withHeader("X-Content-Type-Options", "nosniff")
//                .withBody("{ \"message\": \"Invalid email format\" }")));
//
//        stubFor(post("/auth/signup").withRequestBody(matchingJsonPath("$.username", matching("^\\s*$")))
//            .willReturn(aResponse().withStatus(400)
//                .withHeader("X-Content-Type-Options", "nosniff")
//                .withBody("{ \"message\": \"Username cannot be empty\" }")));
//
//        stubFor(post("/auth/signup").withRequestBody(matchingJsonPath("$.password", matching("^\\s*$")))
//            .willReturn(aResponse().withStatus(400)
//                .withHeader("X-Content-Type-Options", "nosniff")
//                .withBody("{ \"message\": \"Password cannot be empty\" }")));
//
//        stubFor(post("/auth/signup").withRequestBody(matchingJsonPath("$.email", matching("^\\s*$")))
//            .willReturn(aResponse().withStatus(400)
//                .withHeader("X-Content-Type-Options", "nosniff")
//                .withBody("{ \"message\": \"Email cannot be empty\" }")));
//    }

    @AfterAll
    public static void teardown() {
        wireMockServer.stop();
    }

    // 1. Authentication Bypass Attempt
    @Test
    public void testAuthenticationBypass() {
        given()
            .contentType(ContentType.JSON)
            .body("{ \"username\": \"admin\", \"password\": \"' OR '1'='1\" }")
            .when()
            .post("/auth/login")
            .then()
            .statusCode(401) // Unauthorized
            .body("error", equalTo("invalid_credentials"))
            .header("WWW-Authenticate", notNullValue());
    }

    // 2. Brute Force Attack Protection
    @Test
    public void testBruteForceProtection() {
        IntStream.rangeClosed(1, 5).forEach(i -> {
            given()
                .contentType(ContentType.JSON)
                .body("{ \"username\": \"user\", \"password\": \"wrongpass\" }")
                .when()
                .post("/auth/login")
                .then()
                .statusCode(i < 3 ? 401 : 429); // Threshold 3 attempts
        });
    }

    // 3. SQL Injection Attempt
    @Test
    public void testSQLInjectionProtection() {
        given()
            .contentType(ContentType.JSON)
            .body("{ \"email\": \"'; DROP TABLE users;--\" }")
            .when()
            .post("/auth/login")
            .then()
            .statusCode(422) // Unprocessable Entity
            .body("error", equalTo("invalid_input"));
    }

    // 4. XSS Attack Attempt
    @Test
    public void testXSSProtection() {
        given()
            .contentType(ContentType.JSON)
            .body("{ \"comment\": \"<script>alert('XSS')</script>\" }")
            .when()
            .post("/api/comments")
            .then()
            .statusCode(400) // Bad Request
            .body("error", equalTo("invalid_input_format"));
    }

    // 5. Insecure Direct Object Reference
    @Test
    public void testInsecureDirectObjectReference() {
        given()
            .header("Authorization", "Bearer valid-token")
            .when()
            .get("/api/users/12345/orders")
            .then()
            .statusCode(403) // Forbidden
            .body("error", equalTo("access_denied"));
    }

    // 6. Mass Assignment Vulnerability
    @Test
    public void testMassAssignmentProtection() {
        given()
            .contentType(ContentType.JSON)
            .body("{ \"username\": \"user\", \"role\": \"admin\" }")
            .when()
            .post("/auth/signup")
            .then()
            .statusCode(400) // Bad Request
            .body("error", equalTo("invalid_field"));
    }

    // 7. Sensitive Data Exposure
    @Test
    public void testSensitiveDataExposure() {
        given()
            .header("Authorization", "Bearer valid-token")
            .when()
            .get("/api/users/me")
            .then()
            .statusCode(200)
            .body("password", nullValue())
            .body("creditCard", nullValue())
            .body("ssn", nullValue());
    }

    // 8. CORS Misconfiguration
    @Test
    public void testCORSValidation() {
        given()
            .header("Origin", "https://malicious-site.com")
            .header("Access-Control-Request-Method", "POST")
            .when()
            .options("/auth/login")
            .then()
            .statusCode(403) // Forbidden
            .header("Access-Control-Allow-Origin", nullValue());
    }

    // 9. HTTP Method Fuzzing
    @Test
    public void testUnsupportedHttpMethods() {
        Arrays.asList(HttpMethod.PUT, HttpMethod.DELETE, HttpMethod.PATCH)
            .forEach(method -> {
                given()
                    .request(method.name(), "/auth/login")
                    .then()
                    .statusCode(405); // Method Not Allowed
            });
    }

    // 10. Input Validation Testing
    @Test
    public void testInputValidation() {
        given()
            .contentType(ContentType.JSON)
            .body("{ \"email\": \"invalid-email\", \"password\": \" \" }")
            .when()
            .post("/auth/signup")
            .then()
            .statusCode(422) // Unprocessable Entity
            .body("errors.size()", equalTo(2))
            .body("errors", hasItems("invalid_email_format", "password_required"));
    }

    // 11. JWT Token Validation
    @Test
    public void testJWTValidation() {
        given()
            .header("Authorization", "Bearer invalid.token.here")
            .when()
            .get("/api/users/me")
            .then()
            .statusCode(401) // Unauthorized
            .body("error", equalTo("invalid_token"));
    }

    // 12. Rate Limiting Protection
    @Test
    public void testRateLimiting() {
        IntStream.rangeClosed(1, 100).forEach(i -> {
            ValidatableResponse response = given()
                .when()
                .get("/api/public/data")
                .then()
                .statusCode(i <= 60 ? 200 : 429); // 60 requests/minute

            if(i > 60) {
                response.header("Retry-After", notNullValue());
            }
        });
    }

    // 13. CSRF Protection
    @Test
    public void testCSRFProtection() {
        given()
            .contentType(ContentType.JSON)
            .body("{ \"email\": \"user@example.com\" }")
            .when()
            .post("/api/password-reset")
            .then()
            .statusCode(403) // Forbidden
            .body("error", equalTo("missing_csrf_token"));
    }

    // 14. Content Type Validation
    @Test
    public void testInvalidContentType() {
        given()
            .contentType(ContentType.TEXT)
            .body("plain text")
            .when()
            .post("/auth/login")
            .then()
            .statusCode(415) // Unsupported Media Type
            .body("error", equalTo("unsupported_content_type"));
    }

    // 15. Error Handling Information Leak
    @Test
    public void testErrorHandling() {
        given()
            .when()
            .get("/api/nonexistent-endpoint")
            .then()
            .statusCode(404)
            .body("error", equalTo("not_found"))
            .body("stackTrace", nullValue());
    }

    private String createJson(String username, String password, String email) {
        return String.format("{\"username\": \"%s\", \"password\": \"%s\", \"email\": \"%s\"}", username, password, email);
    }
}

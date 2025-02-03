package id.web.hangga;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.matching.UrlPattern;

import io.restassured.http.ContentType;

public class ApiSecurityUnitTest {

    //    @RegisterExtension
    //    static WireMockExtension wm1 = WireMockExtension.newInstance()
    //        .build();

    private static final String API_URL = "http://localhost:8080/";

    private static WireMockServer wireMockServer;

    @BeforeAll
    public static void setUp() {
        wireMockServer = new WireMockServer(8080);
        wireMockServer.start();
        configureFor("localhost", 8080);

        UrlPattern loginUrl = urlPathEqualTo("/auth/login");

        // Login endpoint
        stubFor(post(loginUrl).withHeader("Content-Type", containing("application/json"))
            .withRequestBody(matchingJsonPath("$.username"))
            .withRequestBody(matchingJsonPath("$.password"))
            .willReturn(aResponse().withStatus(200)
                .withBody("{ \"token\": \"dummy-token\" }")));

        // Brute force protection
        stubFor(post(loginUrl).inScenario("Brute Force")
            .whenScenarioStateIs(STARTED)
            .willReturn(aResponse().withStatus(401)));

        // SQL Injection attempt response
        stubFor(post(loginUrl).withRequestBody(containing("' OR '1'='1"))
            .willReturn(aResponse().withStatus(401)));

        UrlPattern signupUrl = urlPathEqualTo("/auth/signup");

        // Sign-up endpoint - Success
        stubFor(post(signupUrl).withHeader("Content-Type", containing("application/json"))
            .withRequestBody(matchingJsonPath("$.username"))
            .withRequestBody(matchingJsonPath("$.password"))
            .withRequestBody(matchingJsonPath("$.email"))
            .willReturn(aResponse().withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody("{ \"message\": \"User created successfully\" }")));

        // Sign-up endpoint - Username already exists (Error case)
        stubFor(post(signupUrl).withHeader("Content-Type", containing("application/json"))
            .withRequestBody(equalToJson("{\"username\": \"existinguser\", \"password\": \"password123\", \"email\": \"existing@example.com\"}"))
            .willReturn(aResponse().withStatus(409)
                .withHeader("Content-Type", "application/json")
                .withBody("{ \"message\": \"Username already exists\" }")));

        // Invalid email format response
        stubFor(post(signupUrl).withRequestBody(matchingJsonPath("$.email", matching("^((?!@).)*$")))
            .willReturn(aResponse().withStatus(400)));
    }

    @AfterAll
    public static void teardown() {
        wireMockServer.stop();
    }

    @Test
    public void testSignUpSuccess() {
        given().contentType(ContentType.JSON)
            .body("{ \"username\": \"newuser\", \"password\": \"password123\", \"email\": \"newuser@example.com\" }")
            .when()
            .post(API_URL + "auth/signup")
            .then()
            .statusCode(201)
            .body("message", equalTo("User created successfully"));
    }

    @Test
    public void testSignUpUsernameExists() {
        given().contentType(ContentType.JSON)
            .body("{ \"username\": \"existinguser\", \"password\": \"password123\", \"email\": \"existing@example.com\" }")
            .when()
            .post(API_URL + "auth/signup")
            .then()
            .statusCode(409)
            .body("message", equalTo("Username already exists"));
    }

    @Test
    public void testLoginInvalidCredentials() {
        given().contentType(ContentType.JSON)
            .body("{ \"username\": \"wronguser\", \"password\": \"wrongpass\" }")
            .when()
            .post(API_URL + "auth/login")
            .then()
            .statusCode(401);
    }

    @Test
    public void testLoginMissingFields() {
        given().contentType(ContentType.JSON)
            .body("{ \"username\": \"user\" }")
            .when()
            .post(API_URL + "auth/login")
            .then()
            .statusCode(401);
    }

    @Test
    public void testLoginSQLInjectionAttempt() {
        given().contentType(ContentType.JSON)
            .body("{ \"username\": \"admin\", \"password\": \"' OR '1'='1\" }")
            .when()
            .post(API_URL + "auth/login")
            .then()
            .statusCode(401);
    }

    @Test
    public void testSignUpInvalidEmail() {
        given().contentType(ContentType.JSON)
            .body("{ \"username\": \"user123\", \"password\": \"pass123\", \"email\": \"invalid-email\" }")
            .when()
            .post(API_URL + "auth/signup")
            .then()
            .statusCode(400);
    }

    @Test
    public void testSignUpMissingFields() {
        given().contentType(ContentType.JSON)
            .body("{ \"username\": \"newuser\", \"password\": \"password123\" }")
            .when()
            .post(API_URL + "auth/signup")
            .then()
            .statusCode(404);
    }

    @Test
    public void testBruteForceProtection() {
        for (int i = 0; i < 5; i++) {
            given().contentType(ContentType.JSON)
                .body("{ \"username\": \"user\", \"password\": \"wrongpass\" }")
                .when()
                .post(API_URL + "auth/login");
        }

        given().contentType(ContentType.JSON)
            .body("{ \"username\": \"user\", \"password\": \"wrongpass\" }")
            .when()
            .post(API_URL + "auth/login")
            .then()
            .statusCode(401);
    }
}

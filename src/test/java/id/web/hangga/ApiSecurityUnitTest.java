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

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.restassured.http.ContentType;

public class ApiSecurityUnitTest {

    private static final String API_URL = "http://localhost:8080/";

    private static WireMockServer wireMockServer;

    @BeforeAll
    public static void setUp() {
        wireMockServer = new WireMockServer(8080);
        wireMockServer.start();
        configureFor("localhost", 8080);

        stubFor(post("/auth/login").withHeader("Content-Type", containing("application/json"))
            .willReturn(aResponse().withStatus(200)));

        // bruteforce protection simulation
        stubFor(post("/auth/login").inScenario("Brute Force")
            .whenScenarioStateIs(STARTED)
            .willReturn(aResponse().withStatus(401)));

        // sql injection protection simulation
        stubFor(post("/auth/login").withRequestBody(containing("' OR '1'='1"))
            .willReturn(aResponse().withStatus(401)));

        stubFor(post("/auth/signup").withHeader("Content-Type", containing("application/json"))
            .willReturn(aResponse().withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody("{ \"message\": \"User created successfully\" }")));

        stubFor(post("/auth/signup").withRequestBody(
                equalToJson("{\"username\": \"existinguser\", \"password\": \"password123\", \"email\": \"existing@example.com\"}"))
            .willReturn(aResponse().withStatus(409)
                .withHeader("Content-Type", "application/json")
                .withBody("{ \"message\": \"Username already exists\" }")));

        // fields validations
        stubFor(post("/auth/signup").withRequestBody(matchingJsonPath("$.email", matching("^[^@]+$")))
            .willReturn(aResponse().withStatus(400)));

        stubFor(post("/auth/signup").withRequestBody(matchingJsonPath("$.username", matching("^\\s*$")))
            .willReturn(aResponse().withStatus(400)
                .withBody("{ \"message\": \"Username cannot be empty\" }")));

        stubFor(post("/auth/signup").withRequestBody(matchingJsonPath("$.password", matching("^\\s*$")))
            .willReturn(aResponse().withStatus(400)
                .withBody("{ \"message\": \"Password cannot be empty\" }")));

        stubFor(post("/auth/signup").withRequestBody(matchingJsonPath("$.email", matching("^\\s*$")))
            .willReturn(aResponse().withStatus(400)
                .withBody("{ \"message\": \"Email cannot be empty\" }")));
    }

    @AfterAll
    public static void teardown() {
        wireMockServer.stop();
    }

    @Test
    public void testSignUpSuccess() {
        given().contentType(ContentType.JSON)
            .body(createJson("newuser", "password123", "newuser@example.com"))
            .when()
            .post(API_URL + "auth/signup")
            .then()
            .statusCode(201)
            .body("message", equalTo("User created successfully"));
    }

    @Test
    public void testSignUpUsernameExists() {
        given().contentType(ContentType.JSON)
            .body(createJson("existinguser", "password123", "existing@example.com"))
            .when()
            .post(API_URL + "auth/signup")
            .then()
            .statusCode(409);
    }

    @Test
    public void testLoginInvalidCredentials() {
        given().contentType(ContentType.JSON)
            .body(createJson("wronguser", "wrongpass", null))
            .when()
            .post(API_URL + "auth/login")
            .then()
            .statusCode(401);
    }

    @Test
    public void testLoginMissingFields() {
        given().contentType(ContentType.JSON)
            .body(createJson("user", null, null))
            .when()
            .post(API_URL + "auth/login")
            .then()
            .statusCode(401);
    }

    @Test
    public void testLoginSQLInjectionAttempt() {
        given().contentType(ContentType.JSON)
            .body(createJson("admin", "' OR '1'='1", null))
            .when()
            .post(API_URL + "auth/login")
            .then()
            .statusCode(401);
    }

    @Test
    public void testSignUpInvalidEmail() {
        given().contentType(ContentType.JSON)
            .body(createJson("user123", "pass123", "hangga-gmail"))
            .when()
            .post(API_URL + "auth/signup")
            .then()
            .statusCode(400);
    }

    @Test
    public void testSignUpMissingFields() {
        given().contentType(ContentType.JSON)
            .body(createJson("newuser", "", null))
            .when()
            .post(API_URL + "auth/signup")
            .then()
            .statusCode(400);
    }

    @Test
    public void testBruteForceProtection() {
        for (int i = 0; i < 5; i++) {
            given().contentType(ContentType.JSON)
                .body(createJson("user", "wrongpass", null))
                .when()
                .post(API_URL + "auth/login");
        }

        given().contentType(ContentType.JSON)
            .body(createJson("user", "wrongpass", null))
            .when()
            .post(API_URL + "auth/login")
            .then()
            .statusCode(401);
    }

    private String createJson(String username, String password, String email) {
        StringBuilder json = new StringBuilder("{");
        if (username != null) json.append("\"username\": \"").append(username).append("\", ");
        if (password != null) json.append("\"password\": \"").append(password).append("\", ");
        if (email != null) json.append("\"email\": \"").append(email).append("\", ");
        if (json.charAt(json.length() - 2) == ',') json.delete(json.length() - 2, json.length());
        json.append("}");
        return json.toString();
    }
}

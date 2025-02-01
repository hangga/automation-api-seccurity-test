package id.web.hangga;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
//import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
//import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
//import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
//import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.hamcrest.Matchers.equalTo;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.matching.MultiValuePattern;

public class ApiSecurityUnitTest {

    private static WireMockServer wireMockServer;

    @BeforeAll
    public static void setup() {
        wireMockServer = new WireMockServer(8080);
        wireMockServer.start();
        configureFor("localhost", 8080);

        // Setup stub for secure endpoint
        stubFor(get(urlEqualTo("/secure-endpoint")).withBasicAuth("username", "password")
            .willReturn(aResponse().withStatus(200)
                .withBody("{\"message\":\"Authenticated successfully\"}")));

        // Setup stub for admin endpoint with valid token
        stubFor(get(urlEqualTo("/admin-endpoint")).withHeader("Authorization", (MultiValuePattern) equalTo("Bearer validAccessToken"))
            .willReturn(aResponse().withStatus(200)
                .withBody("{\"role\":\"admin\"}")));

        // Setup stub for admin endpoint with invalid token
        stubFor(get(urlEqualTo("/admin-endpoint")).withHeader("Authorization", (MultiValuePattern) equalTo("Bearer invalidAccessToken"))
            .willReturn(aResponse().withStatus(403)
                .withBody("{\"error\":\"Forbidden\"}")));

        // Setup stub for invalid credentials
        stubFor(get(urlEqualTo("/secure-endpoint")).withBasicAuth("wrongUsername", "wrongPassword")
            .willReturn(aResponse().withStatus(401)
                .withBody("{\"error\":\"Unauthorized\"}")));
    }

    @AfterAll
    public static void teardown() {
        wireMockServer.stop();
    }
}

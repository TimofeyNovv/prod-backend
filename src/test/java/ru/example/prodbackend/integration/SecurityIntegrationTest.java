package ru.example.prodbackend.integration;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import ru.example.prodbackend.auth.dto.AuthenticationResponse;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

class SecurityIntegrationTest extends AuthIntegrationTestSupport {

    @Test
    void validAccessTokenAuthenticatesUser() throws Exception {
        AuthenticationResponse tokens = registerUser();
        assertAccessTokenWorks(tokens.getAccessToken());
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "empty", "malformed", "expired", "wrong-signature", "refresh", "unknown-user"})
    void protectedEndpointRejectsInvalidAccessToken(String scenario) throws Exception {
        AuthenticationResponse tokens = registerUser();
        String token = switch (scenario) {
            case "missing" -> null;
            case "empty" -> "";
            case "malformed" -> "not-a-jwt";
            case "expired" -> signedAccessToken(EMAIL, Instant.EPOCH);
            case "wrong-signature" -> Jwts.builder()
                    .subject(EMAIL)
                    .expiration(Date.from(Instant.now().plusSeconds(60)))
                    .signWith(Jwts.SIG.HS256.key().build(), Jwts.SIG.HS256)
                    .compact();
            case "refresh" -> tokens.getRefreshToken();
            case "unknown-user" -> signedAccessToken("unknown@example.com", Instant.now().plusSeconds(60));
            default -> throw new IllegalArgumentException("Unknown scenario: " + scenario);
        };

        MockHttpServletRequestBuilder request = get("/api/demo/authping");
        if (token != null) {
            request.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }

        assertErrorResponse(mockMvc.perform(request), 401, "UNAUTHORIZED")
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"));
        assertEquals(1L, refreshTokenRepository.count());
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_URL, AUTHENTICATE_URL})
    void publicAuthEndpointsAcceptExpiredAccessToken(String endpoint) throws Exception {
        registerUser();
        String email = endpoint.equals(REGISTER_URL) ? "new@example.com" : EMAIL;

        AuthenticationResponse tokens = readTokenPair(mockMvc.perform(post(endpoint)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + signedAccessToken(EMAIL, Instant.EPOCH))
                .contentType(MediaType.APPLICATION_JSON)
                .content(jsonMapper.writeValueAsString(Map.of("email", email, "password", PASSWORD)))));

        assertAccessTokenWorks(tokens.getAccessToken());
        assertEquals(2L, refreshTokenRepository.count());
    }
}

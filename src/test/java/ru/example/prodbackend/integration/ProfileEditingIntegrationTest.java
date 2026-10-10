package ru.example.prodbackend.integration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.ResultActions;
import ru.example.prodbackend.auth.dto.AuthenticationRequest;
import ru.example.prodbackend.auth.dto.UpdateProfileResponse;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class ProfileEditingIntegrationTest extends AuthIntegrationTestSupport {
    @Autowired
    private PasswordEncoder passwordEncoder;

    private ResultActions update(String token, String json) throws Exception {
        return mockMvc.perform(patch("/api/auth/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private ResultActions changePassword(String token, String json) throws Exception {
        return mockMvc.perform(post("/api/auth/change-password")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON).content(json));
    }

    @Test
    void partialUpdatesPreserveFieldsAndSessionsAndAllowClearingNames() throws Exception {
        var tokens = registerUser();
        var other = registerUser("other@example.com");
        update(tokens.getAccessToken(), "{\"firstName\":\"Alice\",\"lastName\":\"Smith\"}")
                .andExpect(status().isOk()).andExpect(jsonPath("$.profile.firstName").value("Alice"))
                .andExpect(jsonPath("$.accessToken").isEmpty()).andExpect(jsonPath("$.refreshToken").isEmpty());
        update(tokens.getAccessToken(), "{\"email\":\"user@example.com\",\"firstName\":null,\"lastName\":\"  \"}")
                .andExpect(status().isOk()).andExpect(jsonPath("$.profile.firstName").value("Alice"))
                .andExpect(jsonPath("$.profile.lastName").isEmpty());
        update(tokens.getAccessToken(), "{}").andExpect(status().isOk());
        assertEquals(2, refreshTokenRepository.count());
        assertEquals("Alice", userRepository.findByEmail("other@example.com").orElseThrow().getFirstName());
        mockMvc.perform(get("/api/user/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + tokens.getAccessToken()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.firstName").value("Alice"));
        assertAccessTokenWorks(other.getAccessToken());
    }

    @Test
    void changingEmailReplacesAllOwnSessionsAndReturnsUsableTokens() throws Exception {
        var first = registerUser();
        var second = authenticateUser(EMAIL);
        var other = registerUser("other@example.com");
        String body = update(first.getAccessToken(), "{\"email\":\"new@example.com\"}")
                .andExpect(status().isOk()).andExpect(jsonPath("$.profile.email").value("new@example.com"))
                .andReturn().getResponse().getContentAsString();
        var response = jsonMapper.readValue(body, UpdateProfileResponse.class);
        assertAccessTokenWorks(response.getAccessToken());
        assertRefreshTokenRejected(first.getRefreshToken());
        assertRefreshTokenRejected(second.getRefreshToken());
        readTokenPair(postRefreshToken(REFRESH_URL, response.getRefreshToken()));
        readTokenPair(postRefreshToken(REFRESH_URL, other.getRefreshToken()));
        authenticateUser("new@example.com");
        assertTrue(userRepository.findByEmail(EMAIL).isEmpty());
    }

    @Test
    void duplicateEmailLeavesProfileAndSessionsUnchanged() throws Exception {
        var tokens = registerUser();
        registerUser("other@example.com");
        assertErrorResponse(update(tokens.getAccessToken(), "{\"email\":\"other@example.com\",\"firstName\":\"Alice\"}"),
                409, "USER_ALREADY_EXISTS");
        assertEquals("Alice", userRepository.findByEmail(EMAIL).orElseThrow().getFirstName());
        assertEquals(2, refreshTokenRepository.count());
        readTokenPair(postRefreshToken(REFRESH_URL, tokens.getRefreshToken()));
    }

    @Test
    void passwordChangeHashesPasswordRevokesOwnSessionsAndPreservesAccessTokens() throws Exception {
        var first = registerUser();
        var second = authenticateUser(EMAIL);
        var other = registerUser("other@example.com");
        changePassword(first.getAccessToken(), "{\"currentPassword\":\"P@ssw0rd!\",\"newPassword\":\"NewPassword123\"}")
                .andExpect(status().isNoContent()).andExpect(content().string(""));
        var encoded = userRepository.findByEmail(EMAIL).orElseThrow().getPassword();
        assertNotEquals("NewPassword123", encoded);
        assertTrue(passwordEncoder.matches("NewPassword123", encoded));
        assertErrorResponse(postJson(AUTHENTICATE_URL, new AuthenticationRequest(EMAIL, PASSWORD)), 401, "UNAUTHORIZED");
        readTokenPair(postJson(AUTHENTICATE_URL, new AuthenticationRequest(EMAIL, "NewPassword123")));
        assertRefreshTokenRejected(first.getRefreshToken());
        assertRefreshTokenRejected(second.getRefreshToken());
        assertAccessTokenWorks(first.getAccessToken());
        readTokenPair(postRefreshToken(REFRESH_URL, other.getRefreshToken()));
    }

    @Test
    void wrongCurrentPasswordLeavesCredentialsAndSessionsUnchanged() throws Exception {
        var tokens = registerUser();
        String before = userRepository.findByEmail(EMAIL).orElseThrow().getPassword();
        assertErrorResponse(changePassword(tokens.getAccessToken(), "{\"currentPassword\":\"wrong\",\"newPassword\":\"NewPassword123\"}"),
                401, "UNAUTHORIZED");
        assertEquals(before, userRepository.findByEmail(EMAIL).orElseThrow().getPassword());
        assertEquals(1, refreshTokenRepository.count());
        readTokenPair(postRefreshToken(REFRESH_URL, tokens.getRefreshToken()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{\"currentPassword\":\"P@ssw0rd!\",\"newPassword\":\"short\"}",
            "{\"currentPassword\":\"\",\"newPassword\":\"NewPassword123\"}"})
    void invalidPasswordRequestLeavesDataUnchanged(String json) throws Exception {
        var tokens = registerUser();
        assertErrorResponse(changePassword(tokens.getAccessToken(), json), 422, "VALIDATION_ERROR");
        assertTrue(passwordEncoder.matches(PASSWORD, userRepository.findByEmail(EMAIL).orElseThrow().getPassword()));
        assertEquals(1, refreshTokenRepository.count());
    }

    @Test
    void invalidProfileAndMalformedBodiesUseExistingErrors() throws Exception {
        var tokens = registerUser();
        for (String json : new String[]{"{\"email\":\" \"}", "{\"email\":\"" + "a".repeat(256) + "\"}",
                "{\"firstName\":\"" + "a".repeat(256) + "\"}", "{\"lastName\":\"" + "a".repeat(256) + "\"}"}) {
            assertErrorResponse(update(tokens.getAccessToken(), json), 422, "VALIDATION_ERROR");
        }
        for (String json : new String[]{"", "{"}) {
            assertErrorResponse(update(tokens.getAccessToken(), json), 400, "INVALID_REQUEST_BODY");
            assertErrorResponse(changePassword(tokens.getAccessToken(), json), 400, "INVALID_REQUEST_BODY");
        }
        assertEquals(EMAIL, userRepository.findByEmail(EMAIL).orElseThrow().getEmail());
        assertEquals(1, refreshTokenRepository.count());
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "malformed", "expired", "refresh", "unknown-user"})
    void bothEndpointsRequireValidAccessToken(String scenario) throws Exception {
        var tokens = registerUser();
        String token = switch (scenario) {
            case "missing" -> "";
            case "expired" -> signedAccessToken(EMAIL, java.time.Instant.EPOCH);
            case "refresh" -> tokens.getRefreshToken();
            case "unknown-user" -> signedAccessToken("unknown@example.com", java.time.Instant.now().plusSeconds(60));
            default -> "bad-token";
        };
        assertErrorResponse(update(token, "{}"), 401, "UNAUTHORIZED");
        assertErrorResponse(changePassword(token, "{}"), 401, "UNAUTHORIZED");
        assertEquals(1, refreshTokenRepository.count());
    }
}

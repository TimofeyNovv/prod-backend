package ru.example.prodbackend.auth.service;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.WeakKeyException;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;

import javax.crypto.SecretKey;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtServiceTest {

    private static final SecretKey TEST_KEY = Keys.hmacShaKeyFor(new byte[32]);
    private static final String TEST_SECRET = Encoders.BASE64.encode(TEST_KEY.getEncoded());
    private static final long EXPIRATION_MS = 1_200_000;

    private final JwtService jwtService = new JwtService(TEST_SECRET, EXPIRATION_MS);

    @Test
    void generatedTokenContainsUserRoleAndExpiration() {
        var user = User.withUsername("user@example.com")
                .password("unused")
                .authorities("USER")
                .build();

        var claims = jwtService.extractAllClaims(jwtService.generateToken(user));

        assertEquals("user@example.com", claims.getSubject());
        assertEquals("USER", claims.get("role", String.class));
        assertNotNull(claims.getId());
        assertEquals(EXPIRATION_MS,
                claims.getExpiration().getTime() - claims.getIssuedAt().getTime());
    }

    @Test
    void rejectsExpiredToken() {
        String token = Jwts.builder()
                .subject("user@example.com")
                .expiration(new Date(0))
                .signWith(TEST_KEY, Jwts.SIG.HS256)
                .compact();

        assertThrows(ExpiredJwtException.class, () -> jwtService.extractAllClaims(token));
    }

    @Test
    void rejectsTokenSignedWithAnotherKey() {
        SecretKey otherKey = Jwts.SIG.HS256.key().build();
        String token = Jwts.builder()
                .subject("user@example.com")
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                .signWith(otherKey, Jwts.SIG.HS256)
                .compact();

        assertThrows(SignatureException.class, () -> jwtService.extractAllClaims(token));
    }

    @Test
    void rejectsTokenWithoutSubject() {
        String token = Jwts.builder()
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                .signWith(TEST_KEY, Jwts.SIG.HS256)
                .compact();

        assertThrows(MalformedJwtException.class, () -> jwtService.extractAllClaims(token));
    }

    @Test
    void rejectsTokenWithoutExpiration() {
        String token = Jwts.builder()
                .subject("user@example.com")
                .signWith(TEST_KEY, Jwts.SIG.HS256)
                .compact();

        assertThrows(MalformedJwtException.class, () -> jwtService.extractAllClaims(token));
    }

    @Test
    void rejectsMalformedOrEmptyToken() {
        assertThrows(JwtException.class, () -> jwtService.extractAllClaims("not-a-jwt"));
        assertThrows(IllegalArgumentException.class, () -> jwtService.extractAllClaims(""));
    }

    @Test
    void rejectsNonPositiveExpirationAtConstruction() {
        assertThrows(IllegalArgumentException.class, () -> new JwtService(TEST_SECRET, 0));
        assertThrows(IllegalArgumentException.class, () -> new JwtService(TEST_SECRET, -1));
    }

    @Test
    void rejectsWeakKeyAtConstruction() {
        String weakSecret = Encoders.BASE64.encode(new byte[8]);

        assertThrows(WeakKeyException.class, () -> new JwtService(weakSecret, EXPIRATION_MS));
    }
}

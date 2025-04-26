package com.ambraspace.auth.jwt;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;


// https://www.javainuse.com/webseries/spring-security-jwt/chap7
// https://github.com/jwtk/jjwt
@Service
public class JwtTokenUtil
{

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.token-validity:#{T(java.time.Duration).ofDays(2)}}")
    private Duration tokenValidity;

    private SecretKey secretKey;

    private JwtParser jwtParser;


    @PostConstruct
    public void initializeKeysAndParser()
    {

        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA512");

        jwtParser = Jwts.parser().verifyWith(secretKey).build();

    }


    public String generateToken(String username) {
        return Jwts.builder()
        		.subject(username)
        		.issuedAt(new Date(System.currentTimeMillis()))
        		.expiration(new Date(System.currentTimeMillis() + tokenValidity.toMillis()))
        		.signWith(secretKey)
        		.compact();
    }


    public boolean validateToken(String authToken) {
        try {
            jwtParser.parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            throw new BadCredentialsException("INVALID_CREDENTIALS", ex);
        } catch (ExpiredJwtException ex) {
            throw ex;
        }
    }


    public String getUsernameFromToken(String token) {
        Claims claims = jwtParser.parseSignedClaims(token).getPayload();
        return claims.getSubject();
    }


    public Date getExpiration(String token) {
        Claims claims = jwtParser.parseSignedClaims(token).getPayload();
        return claims.getExpiration();
    }


    public String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }

}

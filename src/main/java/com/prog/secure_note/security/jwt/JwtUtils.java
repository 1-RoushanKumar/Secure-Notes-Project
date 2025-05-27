package com.prog.secure_note.security.jwt;

import com.prog.secure_note.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtUtils {
    // This variable is used to log messages in the class.
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    //This variable is used to read the JWT secret key from the application properties file.
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    //This variable is used to read the JWT expiration time from the application properties file.
    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    // This method extracts the JWT token from the Authorization header of the HTTP request.
    public String getJwtFromHeader(HttpServletRequest request) {
        //getHeader() method is used to retrieve the value of the Authorization header from the HTTP request.
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken); // Log the bearer token
        //it will check if the bearerToken is not null and starts with "Bearer ".
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Remove Bearer prefix
        }
        return null;
    }

    //This will generate a JWT token using the username of the user.
    public String generateTokenFromUsername(UserDetailsImpl userDetails) {
        String username = userDetails.getUsername();
        String roles = userDetails.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .collect(Collectors.joining(","));
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .claim("is2faEnabled", userDetails.is2faEnabled())  //In token, we are adding the is2faEnabled claim.
                .claim("email", userDetails.getEmail()) //In token, we are adding the email claim.So i frontend when we decode it we can fetch email also.
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    //This method is used to extract the username from the JWT token.
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build().parseSignedClaims(token)
                .getPayload().getSubject();
    }

    //    This method is part of a JWT (JSON Web Token) utility class and is typically used when signing or verifying JWTs using an HMAC algorithm like HS256.
    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    //This method is used to validate the JWT token.
    public boolean validateJwtToken(String authToken) {
        try {
            System.out.println("Validate");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}


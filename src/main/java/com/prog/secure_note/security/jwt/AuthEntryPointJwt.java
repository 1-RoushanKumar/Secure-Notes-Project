package com.prog.secure_note.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Custom authentication entry point used to handle unauthorized access attempts.
 * Triggered when an unauthenticated user tries to access a secured HTTP resource.
 */
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    // Logger for logging error messages related to unauthorized access attempts
    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    /**
     * This method is called whenever an unauthenticated user tries to access a protected resource.
     * Instead of redirecting to a login page, this sends a JSON response with HTTP 401 Unauthorized.
     *
     * @param request       HttpServletRequest that resulted in the exception
     * @param response      HttpServletResponse to write the error response
     * @param authException Exception that caused the invocation
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {

        // Log the unauthorized access attempt
        logger.error("Unauthorized error: {}", authException.getMessage());

        // Print exception to the console (can be removed in production)
        System.out.println(authException);

        // Set response content type to application/json
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // Set HTTP status code to 401 Unauthorized
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        // Prepare a JSON body with error details
        final Map<String, Object> body = new HashMap<>();
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED); // 401
        body.put("error", "Unauthorized");                       // Error type
        body.put("message", authException.getMessage());         // Detailed error message
        body.put("path", request.getServletPath());              // Request path where the error occurred

        // Write the JSON response using Jackson's ObjectMapper
        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
    }

}

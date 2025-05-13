package com.prog.secure_note.security.jwt;

import com.prog.secure_note.security.service.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
// This filter is executed once per request to check if the user is authenticated.
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    // This method is called for every request to check if the user is authenticated.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.debug("AuthTokenFilter called for URI: {}", request.getRequestURI());
        try {
            // Extract the JWT token from the request header.
            String jwt = parseJwt(request); //parseJwt() method is defined below.
            // Check if the JWT token is valid.
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                // Get the username from the JWT token.
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                // Load the user details from the database using the username.
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // Create an authentication token using the user details.
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null,
                                userDetails.getAuthorities());
                logger.debug("Roles from JWT: {}", userDetails.getAuthorities());

                // Set the authentication details for the current request.
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set the authentication object in the security context.
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        // Catch any exceptions that occur during the authentication process.
        catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }

        //After the authentication process is complete, the filter chain is continued to process the request.
        filterChain.doFilter(request, response);
    }

    //This method extracts the JWT token from the request header.
    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);//getJwtFromHeader() method is defined in JwtUtils class.
        logger.debug("AuthTokenFilter.java: {}", jwt);
        return jwt;
    }
}


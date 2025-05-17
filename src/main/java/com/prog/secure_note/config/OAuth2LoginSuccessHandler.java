package com.prog.secure_note.config;

import com.prog.secure_note.model.AppRole;
import com.prog.secure_note.model.Role;
import com.prog.secure_note.model.User;
import com.prog.secure_note.repositories.RoleRepository;
import com.prog.secure_note.security.jwt.JwtUtils;
import com.prog.secure_note.security.service.UserDetailsImpl;
import com.prog.secure_note.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
// This is a custom success handler for OAuth2 login.
// It handles the successful authentication of users using OAuth2 providers like GitHub and Google.
public class OAuth2LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Autowired
    private final UserService userService;

    @Autowired
    private final JwtUtils jwtUtils;

    @Autowired
    RoleRepository roleRepository;

    @Value("${frontend.url}")
    private String frontendUrl;

    String username;
    String idAttributeKey;

    // This method is called when the OAuth2 authentication is successful.
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        // Extract OAuth2 authentication token from the authentication object
        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;

        // Check if the login was done via GitHub or Google
        if ("github".equals(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()) || "google".equals(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId())) {
            // Extract user details from the OAuth2 principal
            DefaultOAuth2User principal = (DefaultOAuth2User) authentication.getPrincipal();
            Map<String, Object> attributes = principal.getAttributes();

            // Extract email and name from the attributes
            String email = attributes.getOrDefault("email", "").toString();
            String name = attributes.getOrDefault("name", "").toString();

            // Determine the username and ID attribute key based on the OAuth2 provider
            if ("github".equals(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId())) {
                username = attributes.getOrDefault("login", "").toString(); // GitHub uses "login" as username
                idAttributeKey = "id";
            } else if ("google".equals(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId())) {
                username = email.split("@")[0]; // Derive username from email for Google
                idAttributeKey = "sub";
            } else {
                username = "";
                idAttributeKey = "id";
            }

            System.out.println("HELLO OAUTH: " + email + " : " + name + " : " + username);

            // Check if the user already exists in the database using email
            userService.findByEmail(email)
                    .ifPresentOrElse(user -> {
                        // If user exists, create a new OAuth2User with their authorities and set it in the security context
                        DefaultOAuth2User oauthUser = new DefaultOAuth2User(
                                List.of(new SimpleGrantedAuthority(user.getRole().getRoleName().name())),
                                attributes,
                                idAttributeKey
                        );
                        Authentication securityAuth = new OAuth2AuthenticationToken(
                                oauthUser,
                                List.of(new SimpleGrantedAuthority(user.getRole().getRoleName().name())),
                                oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()
                        );
                        SecurityContextHolder.getContext().setAuthentication(securityAuth);
                    }, () -> {
                        // If user does not exist, register a new user with default ROLE_USER
                        User newUser = new User();
                        Optional<Role> userRole = roleRepository.findByRoleName(AppRole.ROLE_USER);
                        if (userRole.isPresent()) {
                            newUser.setRole(userRole.get());
                        } else {
                            throw new RuntimeException("Default role not found");
                        }

                        newUser.setEmail(email);
                        newUser.setUserName(username);
                        newUser.setSignUpMethod(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId());

                        // Note: password is left null for OAuth2 users
                        userService.registerUser(newUser);

                        // Authenticate the new user
                        DefaultOAuth2User oauthUser = new DefaultOAuth2User(
                                List.of(new SimpleGrantedAuthority(newUser.getRole().getRoleName().name())),
                                attributes,
                                idAttributeKey
                        );
                        Authentication securityAuth = new OAuth2AuthenticationToken(
                                oauthUser,
                                List.of(new SimpleGrantedAuthority(newUser.getRole().getRoleName().name())),
                                oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()
                        );
                        SecurityContextHolder.getContext().setAuthentication(securityAuth);
                    });
        }

        this.setAlwaysUseDefaultTargetUrl(true);

        // FINAL STEP: Create JWT token for the authenticated user
// (Only done once, after authentication has been fully processed)
        DefaultOAuth2User oauth2User = (DefaultOAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = oauth2User.getAttributes();

        String email = (String) attributes.get("email");
        System.out.println("OAuth2LoginSuccessHandler: " + username + " : " + email);

        // Get the authorities from the OAuth2 user and add the user's role
        Set<SimpleGrantedAuthority> authorities = new HashSet<>(oauth2User.getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthority()))
                .collect(Collectors.toList()));
        User user = userService.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));
        authorities.add(new SimpleGrantedAuthority(user.getRole().getRoleName().name()));

// Create UserDetailsImpl (needed for JWT token generation)
        UserDetailsImpl userDetails = new UserDetailsImpl(
                null,
                username,
                email,
                null,
                false,
                authorities
        );

// Generate the JWT token based on authenticated user details
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

// Build frontend redirect URL with token as query param
        String targetUrl = UriComponentsBuilder.fromUriString(frontendUrl + "/oauth2/redirect")
                .queryParam("token", jwtToken)
                .build().toUriString();

// Redirect user to frontend with token
        this.setDefaultTargetUrl(targetUrl);
        super.onAuthenticationSuccess(request, response, authentication);

    }
}

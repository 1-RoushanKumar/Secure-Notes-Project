package com.prog.secure_note.controller;

import com.prog.secure_note.model.AppRole;
import com.prog.secure_note.model.Role;
import com.prog.secure_note.model.User;
import com.prog.secure_note.repositories.RoleRepository;
import com.prog.secure_note.repositories.UserRepository;
import com.prog.secure_note.security.jwt.JwtUtils;
import com.prog.secure_note.security.request.LoginRequest;
import com.prog.secure_note.security.request.SignupRequest;
import com.prog.secure_note.security.response.LoginResponse;
import com.prog.secure_note.security.response.MessageResponse;
import com.prog.secure_note.security.response.UserInfoResponse;
import com.prog.secure_note.security.service.UserDetailsImpl;
import com.prog.secure_note.service.TotpService;
import com.prog.secure_note.service.UserService;
import com.prog.secure_note.utils.AuthUtil;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    UserService userService;

    @Autowired
    AuthUtil authUtil;

    @Autowired
    TotpService totpService;

    @PostMapping("/public/signin")
    //This endpoint is used to authenticate a user and generate a JWT token.
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try {
            // authenticate the user
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        }
        // if authentication fails, return a 401 Unauthorized response
        catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }
        // if authentication is successful, set the authentication in the security context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // get the authenticated user details
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        // generate a JWT token for the authenticated user
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        //here collecting the roles of the authenticated user
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        // Prepare the response body, which include the JWT token, username and roles.
        LoginResponse response = new LoginResponse(userDetails.getUsername(),
                roles, jwtToken,userDetails.getEmail()); //Added email to the response (Optional).

        // Return the response entity with the JWT token included in the response body
        return ResponseEntity.ok(response);
    }

    //This endpoint is used to register a new user.So it is public(accessible to everyone).
    @PostMapping("/public/signup")
    //Taking the SignupRequest object as input, which contains the user's username, email, password and role.
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        // Check if the username and email are already taken
        // If they are, return a 400 Bad Request response with an error message.
        if (userRepository.existsByUserName(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create a new user object and set its properties based on the input from the SignupRequest object.
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                // Set the password using the PasswordEncoder to hash it
                encoder.encode(signUpRequest.getPassword()));

        //strRoles is a Set of strings that represent the roles that the user wants to have.
        Set<String> strRoles = signUpRequest.getRole();
        Role role;

        // Check if the user has specified any roles.
        if (strRoles == null || strRoles.isEmpty()) {
            // If no roles are specified, assign the default role of "user" to the user.
            role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        }
        // If the user has specified roles, check if they are valid.
        else {
            String roleStr = strRoles.iterator().next();
            if (roleStr.equals("admin")) {
                role = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            } else {
                role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            }

            // Set the default properties for the user
            user.setAccountNonLocked(true);
            user.setAccountNonExpired(true);
            user.setCredentialsNonExpired(true);
            user.setEnabled(true);
            user.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
            user.setAccountExpiryDate(LocalDate.now().plusYears(1));
            user.setTwoFactorEnabled(false);
            user.setSignUpMethod("email");
        }
        // Set the role for the user and save the user to the database.
        user.setRole(role);
        userRepository.save(user);

        // Return a 200 OK response with a success message.
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    //This endpoint is used to get the details of the currently authenticated user.
    @GetMapping("/user")
    //AuthenticationPrincipal is used to get the currently authenticated user.
    public ResponseEntity<?> getUserDetails(@AuthenticationPrincipal UserDetails userDetails) {
        // Get the currently authenticated user from the SecurityContext
        User user = userService.findByUsername(userDetails.getUsername());

        // Extract the list of roles (authorities) from the authenticated user's details.
        // Each authority (like "ROLE_USER", "ROLE_ADMIN", etc.) is mapped to its string representation.
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        // Create a UserInfoResponse object to hold the user details
        UserInfoResponse response = new UserInfoResponse(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.isTwoFactorEnabled(),
                roles
        );

        // Return the user details in the response body
        return ResponseEntity.ok().body(response);
    }

    //This endpoint is used to get the username of the currently authenticated user.
    @GetMapping("/username")
    public String currentUserName(@AuthenticationPrincipal UserDetails userDetails) {
        return (userDetails != null) ? userDetails.getUsername() : "";
    }

    //This endpoint is to use the forgot password functionality.
    //Which will create a token and send this to the email.
    @PostMapping("/public/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
        try {
            userService.generatePasswordResetToken(email);
            return ResponseEntity.ok(new MessageResponse(("Password reset email sent successfully")));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Error sending password reset email: " + e.getMessage()));
        }
    }

    @PostMapping("/public/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestParam String newPassword) {
        try {
            userService.resetPassword(token, newPassword);
            return ResponseEntity.ok(new MessageResponse("Password reset successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new MessageResponse(e.getMessage()));
        }
    }

    // Here I added the endpoint for two-factor authentication.
    // This endpoint is used to enable 2FA for the currently authenticated user.
    // 2FA Authentication

    // This endpoint is used to enable 2FA for the currently authenticated user.
    @PostMapping("/enable-2fa")
    public ResponseEntity<String> enable2FA() {
        //First, fetching the userId of an authenticated user.
        Long userId = authUtil.loggedInUserId();
        //Getting the secret from the userService.
        GoogleAuthenticatorKey secret = userService.generate2FASecret(userId);
        // Then, we are generating the QR code URL using the secret and the username.
        String qrCodeUrl = totpService.getQrCodeUrl(secret,
                userService.getUserById(userId).getUserName());
        return ResponseEntity.ok(qrCodeUrl);
    }

    // This endpoint is used to disable 2FA for the currently authenticated user.
    @PostMapping("/disable-2fa")
    public ResponseEntity<String> disable2FA() {
        Long userId = authUtil.loggedInUserId();
        //Simple in a database where we added the field isTwoFactorEnabled just set it to false.
        userService.disable2FA(userId);
        return ResponseEntity.ok("2FA disabled");
    }


    // This endpoint is used to verify the 2FA code entered by the user.
    @PostMapping("/verify-2fa")
    public ResponseEntity<String> verify2FA(@RequestParam int code) {
        // First, fetching the userId of an authenticated user.
        Long userId = authUtil.loggedInUserId();
        // Then, we are validating the 2FA code entered by the user.
        boolean isValid = userService.validate2FACode(userId, code);
        if (isValid) {
            userService.enable2FA(userId);
            return ResponseEntity.ok("2FA Verified");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid 2FA Code");
        }
    }


    // This endpoint is used to get the 2FA status of the currently authenticated user.
    @GetMapping("/user/2fa-status")
    public ResponseEntity<?> get2FAStatus() {
        User user = authUtil.loggedInUser();
        if (user != null) {
            //We may be wondering why we are using Map.of() here.
            //This is a convenient way to create an immutable map with a single entry.
            return ResponseEntity.ok().body(Map.of("is2faEnabled", user.isTwoFactorEnabled()));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }
    }


    // This endpoint is used to verify the 2FA code entered by the user during login.
    @PostMapping("/public/verify-2fa-login")
    public ResponseEntity<String> verify2FALogin(@RequestParam int code,
                                                 @RequestParam String jwtToken) {
        String username = jwtUtils.getUserNameFromJwtToken(jwtToken);
        User user = userService.findByUsername(username);
        boolean isValid = userService.validate2FACode(user.getUserId(), code);
        if (isValid) {
            return ResponseEntity.ok("2FA Verified");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid 2FA Code");
        }
    }
}
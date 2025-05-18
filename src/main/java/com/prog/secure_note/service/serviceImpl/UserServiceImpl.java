package com.prog.secure_note.service.serviceImpl;

import com.prog.secure_note.model.*;
import com.prog.secure_note.repositories.PasswordResetTokenRepository;
import com.prog.secure_note.repositories.RoleRepository;
import com.prog.secure_note.repositories.UserRepository;
import com.prog.secure_note.service.TotpService;
import com.prog.secure_note.service.UserService;
import com.prog.secure_note.utils.EmailService;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Value("${frontend.url}")
    private String frontendUrl;

    @Autowired
    EmailService emailService;

    @Autowired
    TotpService totpService;

    @Override
    public void updateUserRole(Long userId, String roleName) {
        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        AppRole appRole = AppRole.valueOf(roleName);
        Role role = roleRepository.findByRoleName(appRole)
                .orElseThrow(() -> new RuntimeException("Role not found"));
        user.setRole(role);
        userRepository.save(user);
    }


    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }


    @Override
    public UserDTO getUserById(Long id) {
        User user = userRepository.findById(id).orElseThrow();
        return convertToDto(user);
    }

    private UserDTO convertToDto(User user) {
        return new UserDTO(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.getTwoFactorSecret(),
                user.isTwoFactorEnabled(),
                user.getSignUpMethod(),
                user.getRole(),
                user.getCreatedDate(),
                user.getUpdatedDate()
        );
    }

    @Override
    public User findByUsername(String username) {
        Optional<User> user = userRepository.findByUserName(username);
        return user.orElseThrow(() -> new RuntimeException("User not found with username: " + username));
    }

    @Override
    public void updateAccountLockStatus(Long userId, boolean lock) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setAccountNonLocked(!lock);
        userRepository.save(user);
    }

    @Override
    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }

    @Override
    public void updateAccountExpiryStatus(Long userId, boolean expire) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setAccountNonExpired(!expire);
        userRepository.save(user);
    }

    @Override
    public void updateAccountEnabledStatus(Long userId, boolean enabled) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setEnabled(enabled);
        userRepository.save(user);
    }

    @Override
    public void updateCredentialsExpiryStatus(Long userId, boolean expire) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setCredentialsNonExpired(!expire);
        userRepository.save(user);
    }

    @Override
    public void updatePassword(Long userId, String password) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            user.setPassword(passwordEncoder.encode(password));
            userRepository.save(user);
        } catch (Exception e) {
            throw new RuntimeException("Failed to update password");
        }
    }

    // This method generates a password reset token for the user with the given email address.
    @Override
    public void generatePasswordResetToken(String email) {
        //First we fetching the user associated with this email address
        User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));

        //Here we are generating a unique token for the password reset
        String token = UUID.randomUUID().toString();
        //We are setting the expiry date for the token to 24 hours from now
        Instant expiryDate = Instant.now().plus(24, ChronoUnit.HOURS);
        //We are creating a new PasswordResetToken object and saving it to the database
        PasswordResetToken resetToken = new PasswordResetToken(token, expiryDate, user);
        passwordResetTokenRepository.save(resetToken);

        //We are creating a reset URL that the user can use to reset their password
        String resetUrl = frontendUrl + "/reset-password?token=" + token;

        //Send email to the user with the reset URL
        emailService.sendPasswordResetEmail(user.getEmail(), resetUrl);
    }

    // This method resets the user's password using the provided token and new password.
    // And also validates the token to ensure it is not expired or already used.
    @Override
    public void resetPassword(String token, String newPassword) {
        // Fetching the password reset token from the database using the provided token
        PasswordResetToken resetToken = passwordResetTokenRepository
                .findByToken(token).orElseThrow(() -> new RuntimeException("Invalid password reset token"));

        // Check if the token has already been used or expired
        if (resetToken.isUsed()) {
            throw new RuntimeException("Password reset token has already been used");
        }

        if (resetToken.getExpiryDate().isBefore(Instant.now())) {
            throw new RuntimeException("Password reset token has expired");
        }

        // If the token is valid, we fetch the user associated with the token
        // And reset the user's password and save this new password to database.
        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Mark the token as used to prevent it from being used again
        resetToken.setUsed(true);
        passwordResetTokenRepository.save(resetToken);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    //This will registerUser of the OAuth2 user.
    @Override
    public User registerUser(User user) {
        System.out.println("Password: " + user.getPassword());
        //See password will be null if the user is registered using OAuth2
        // So we need to check if the password is null or not
        if (user.getPassword() != null) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        return userRepository.save(user);
    }

    //This method will generate a 2FA secret and store it in a database.
    @Override
    public GoogleAuthenticatorKey generate2FASecret(Long userId) {
        //First finding the user by id.
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        //Generating the secret key using the totpService.
        GoogleAuthenticatorKey key = totpService.generateSecret();
        //Setting the secret key to the user.
        user.setTwoFactorSecret(key.getKey());
        //Save this secret in a database.
        userRepository.save(user);
        return key;
    }

    //Here we're validating the 2FA code.
    @Override
    public boolean validate2FACode(Long userId, int code) {
        //First fetched the user by id.
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        //Then we're getting the secret key from the user.And then using verifyCode method of totpService to verify the code.
        return totpService.verifyCode(user.getTwoFactorSecret(), code);
    }

    //This method will enable the 2FA for the user.
    @Override
    public void enable2FA(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
    }

    //This method will disable the 2FA for the user.
    @Override
    public void disable2FA(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setTwoFactorEnabled(false);
        userRepository.save(user);
    }


}


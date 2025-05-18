package com.prog.secure_note.service.serviceImpl;

import com.prog.secure_note.service.TotpService;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.springframework.stereotype.Service;

// This class is responsible for generating and verifying TOTP (Time-based One-Time Password) codes.
@Service
public class TotpServiceImpl implements TotpService {

    // This class uses the Google Authenticator library to generate and verify TOTP codes.(TOTP means Time-based One-Time Password)
    private final GoogleAuthenticator gAuth;

    // Constructor injection is used to inject the GoogleAuthenticator instance.
    public TotpServiceImpl(GoogleAuthenticator gAuth) {
        this.gAuth = gAuth;
    }

    // Default constructor for creating a new instance of GoogleAuthenticator.
    public TotpServiceImpl() {
        this.gAuth = new GoogleAuthenticator();
    }

    // This method generates a new secret key for TOTP authentication.
    @Override
    public GoogleAuthenticatorKey generateSecret() {
        return gAuth.createCredentials();
    }

    // This method generates a QR code URL for the TOTP secret key, which can be scanned by the Google Authenticator app.
    @Override
    public String getQrCodeUrl(GoogleAuthenticatorKey secret, String username) {
        //It's taking the username and secret key as parameters and generates a QR code URL.
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL("Secure Notes Application", username, secret);
    }

    // This method will verify the secret key and the provided TOTP code.
    // It checks if the code is valid for the given secret key.
    @Override
    public boolean verifyCode(String secret, int code) {
        return gAuth.authorize(secret, code);
    }
}

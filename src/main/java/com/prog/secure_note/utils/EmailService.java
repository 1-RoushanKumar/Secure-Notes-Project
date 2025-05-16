package com.prog.secure_note.utils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    // This method sends a simple email to the user with a password reset link
    public void sendPasswordResetEmail(String to, String resetUrl) {

        // Create a simple email message
//        SimpleMailMessage message = new SimpleMailMessage();
//        message.setTo(to);
//        message.setSubject("Password Reset Request");
//        message.setText("To reset your password, click on the link below:\n" + resetUrl);
//        mailSender.send(message);

        // Created a good-looking email message
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);
            helper.setTo(to);
            helper.setSubject("🔐 Password Reset Request");

            String htmlContent = "<div style=\"font-family:Arial,sans-serif; font-size:14px; color:#333;\">" +
                    "<h2>Password Reset Request</h2>" +
                    "<p>We received a request to reset your password. Click the button below to reset it:</p>" +
                    "<a href=\"" + resetUrl + "\" " +
                    "style=\"display:inline-block;padding:10px 20px;margin:10px 0;background-color:#007bff;color:#fff;text-decoration:none;border-radius:5px;\">" +
                    "Reset Password</a>" +
                    "<p>If you didn’t request this, you can safely ignore this email.</p>" +
                    "<br><p>— SecureNote Team</p>" +
                    "</div>";

            helper.setText(htmlContent, true); // true indicates HTML content

            mailSender.send(mimeMessage);
        } catch (MessagingException e) {
            e.printStackTrace(); // You might want to log this or rethrow in a real application
        }
    }
}

//Both messages will work just for some design i added the second one.

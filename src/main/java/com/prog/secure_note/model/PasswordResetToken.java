package com.prog.secure_note.model;

import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

@Entity
@Data
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;

    //Instant is a Java class that represents a specific moment in time, with nanosecond precision.
    //This gives very accurate time representation, which is useful for tokens that need to expire.
    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private boolean used;

    // The @ManyToOne annotation is used to define a many-to-one relationship between PasswordResetToken and User.
    // We need this because each password reset token is associated with a single user.
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    public PasswordResetToken(String token, Instant expiryDate, User user) {
        this.token = token;
        this.expiryDate = expiryDate;
        this.user = user;
    }

    public PasswordResetToken() {

    }
}

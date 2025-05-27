package com.prog.secure_note.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ContactMessage {
//Contact Message entity to store messages with user details and status in database.

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String email;

    @Column(columnDefinition = "TEXT")
    private String message;

    private String timestamp;

    @Enumerated(EnumType.STRING)  // Store enum as string in DB
    private MessageStatus status = MessageStatus.PENDING;  // Use enum with default value
}

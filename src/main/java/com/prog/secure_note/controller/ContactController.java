package com.prog.secure_note.controller;

import com.prog.secure_note.model.ContactMessage;
import com.prog.secure_note.service.ContactMessageService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/contact")
@CrossOrigin(origins = "http://localhost:3000")
public class ContactController {

    //ContactMessageController, which is used to add messages to the database.
    private final ContactMessageService contactMessageService;

    public ContactController(ContactMessageService contactMessageService) {
        this.contactMessageService = contactMessageService;
    }

    //Saving the messages to the databas.
    @PostMapping
    public ContactMessage saveMessage(@RequestBody ContactMessage message) {
        return contactMessageService.saveMessage(message);
    }

    //Here i fetching all the messages from the database for a specific user by his email
    @GetMapping("/my-messages")
    public ResponseEntity<List<ContactMessage>> getMessagesByEmail(@RequestParam String email) {
        List<ContactMessage> messages = contactMessageService.getMessagesByEmail(email);
        return ResponseEntity.ok(messages);
    }
}


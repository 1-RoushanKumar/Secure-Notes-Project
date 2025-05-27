package com.prog.secure_note.service;

import com.prog.secure_note.model.ContactMessage;

import java.util.List;

public interface ContactMessageService {
    List<ContactMessage> getAllMessages();

    ContactMessage saveMessage(ContactMessage contactMessage);

    void deleteMessages(Long id);

    void deleteAllMessages();

    ContactMessage updateStatus(Long id, String status);

    List<ContactMessage> getMessagesByEmail(String email);
}

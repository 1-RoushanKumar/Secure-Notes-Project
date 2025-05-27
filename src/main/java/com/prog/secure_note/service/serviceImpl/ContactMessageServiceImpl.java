package com.prog.secure_note.service.serviceImpl;

import com.prog.secure_note.model.ContactMessage;
import com.prog.secure_note.model.MessageStatus;
import com.prog.secure_note.repositories.ContactMessageRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

//Contact Message Service Implementation which provides methods to handle contact messages.
@Service
public class ContactMessageServiceImpl implements com.prog.secure_note.service.ContactMessageService {
    private final ContactMessageRepository contactMessageRepository;

    public ContactMessageServiceImpl(ContactMessageRepository contactMessageRepository) {
        this.contactMessageRepository = contactMessageRepository;
    }

    @Override
    public List<ContactMessage> getAllMessages() {
        return contactMessageRepository.findAll();
    }

    @Override
    public ContactMessage saveMessage(ContactMessage contactMessage) {
        contactMessage.setTimestamp(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        return contactMessageRepository.save(contactMessage);
    }

    @Override
    public void deleteMessages(Long id) {
        contactMessageRepository.deleteById(id);
    }

    @Override
    public void deleteAllMessages() {
        contactMessageRepository.deleteAll();
    }

    @Override
    public ContactMessage updateStatus(Long id, String status) {
        ContactMessage message = contactMessageRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Message not found"));

        // Convert string to enum safely (case-insensitive)
        try {
            MessageStatus newStatus = MessageStatus.valueOf(status.toUpperCase());
            message.setStatus(newStatus);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid status value: " + status +
                    ". Allowed values are: PENDING, IN_PROGRESS, RESOLVED.");
        }

        return contactMessageRepository.save(message);
    }

    @Override
    public List<ContactMessage> getMessagesByEmail(String email) {
        return contactMessageRepository.findByEmail(email);
    }
}


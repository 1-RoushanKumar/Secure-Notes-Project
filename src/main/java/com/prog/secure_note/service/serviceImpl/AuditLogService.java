package com.prog.secure_note.service.serviceImpl;

import com.prog.secure_note.model.AuditLog;
import com.prog.secure_note.model.Note;
import com.prog.secure_note.repositories.AuditLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AuditLogService implements com.prog.secure_note.service.AuditLogService {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Override
    public void logNoteCreation(String username, Note note) {
        AuditLog log = new AuditLog();
        log.setAction("Note Created");
        log.setUsername(username);
        log.setNoteId(note.getId());
        log.setNoteContent(note.getContent());
        log.setTimestamp(LocalDateTime.now());

        auditLogRepository.save(log);
    }

    @Override
    public void logNoteUpdate(String username, Note note) {
        AuditLog log = new AuditLog();
        log.setAction("Note Updated");
        log.setUsername(username);
        log.setNoteId(note.getId());
        log.setNoteContent(note.getContent());
        log.setTimestamp(LocalDateTime.now());

        auditLogRepository.save(log);
    }

    @Override
    public void logNoteDeletion(String username, Long noteId) {
        AuditLog log = new AuditLog();
        log.setAction("Note Deleted");
        log.setUsername(username);
        log.setNoteId(noteId);
        log.setTimestamp(LocalDateTime.now());

        auditLogRepository.save(log);
    }

    //This method will return all the audit logs
    @Override
    public List<AuditLog> getAllAuditLogs() {
        return auditLogRepository.findAll();
    }

    //This method will return all the audit logs for a specific note
    @Override
    public List<AuditLog> getAuditLogForNoteid(Long id) {
        //This id is the note id. Not audit log id.So we cannot simply do auditLogRepository.findById(id);
        //We need to find the audit logs for a specific note id.For this we need to create a method in AuditLogRepository
        return auditLogRepository.findByNoteId(id);
    }
}

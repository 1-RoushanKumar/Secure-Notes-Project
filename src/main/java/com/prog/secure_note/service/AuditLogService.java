package com.prog.secure_note.service;

import com.prog.secure_note.model.AuditLog;
import com.prog.secure_note.model.Note;

import java.util.List;

public interface AuditLogService {
    void logNoteCreation(String username, Note note);

    void logNoteUpdate(String username, Note note);

    void logNoteDeletion(String username, Long noteId);

    List<AuditLog> getAllAuditLogs();

    List<AuditLog> getAuditLogForNoteid(Long id);
}

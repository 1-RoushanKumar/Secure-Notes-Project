package com.prog.secure_note.repositories;

import com.prog.secure_note.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog,Long> {
    List<AuditLog> findByNoteId(Long noteId);
}


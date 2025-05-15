package com.prog.secure_note.controller;

import com.prog.secure_note.model.AuditLog;
import com.prog.secure_note.service.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/audit")
public class AuditController {

    @Autowired
    AuditLogService auditLogService;

    @GetMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')") //for only admin users.
    //It will give all the audit logs.
    public List<AuditLog> getAuditLog(){
        return auditLogService.getAllAuditLogs();
    }

    @GetMapping("/note/{id}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    //It will give all the audit logs for a specific note.
    public List<AuditLog> getNoteAuditLog(@PathVariable Long id){
        return auditLogService.getAuditLogForNoteid(id);
    }
}

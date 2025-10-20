package com.secure.notes.services.impl;

import com.secure.notes.models.AuditLog;
import com.secure.notes.models.Note;
import com.secure.notes.repositories.AuditLogRepository;
import com.secure.notes.services.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AuditLogServiceImpl implements AuditLogService {
    @Autowired
    private AuditLogRepository auditLogRepository;

    @Override
    public void logNoteCreation(String username, Note note) {
        AuditLog auditLog = AuditLog
                .builder()
                .action("CREATE")
                .username(username)
                .noteId(note.getId())
                .noteContent(note.getContent())
                .timestamp(LocalDateTime.now())
                .build();

        auditLogRepository.save(auditLog);
    }

    @Override
    public void logNoteUpdate(String username, Note note) {
        AuditLog auditLog = AuditLog
                .builder()
                .action("UPDATE")
                .username(username)
                .noteId(note.getId())
                .noteContent(note.getContent())
                .timestamp(LocalDateTime.now())
                .build();

        auditLogRepository.save(auditLog);
    }

    @Override
    public void logNoteDeletion(String username, Long noteId) {
        AuditLog auditLog = AuditLog
                .builder()
                .action("DELETE")
                .username(username)
                .noteId(noteId)
                .timestamp(LocalDateTime.now())
                .build();

        auditLogRepository.save(auditLog);
    }

    @Override
    public List<AuditLog> getAllAuditLogs() {
        return auditLogRepository.findAll();
    }

    @Override
    public List<AuditLog> getAuditLogsByNoteId(Long noteId) {
        return auditLogRepository.findByNoteId(noteId);
    }
}

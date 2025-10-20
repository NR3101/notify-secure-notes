package com.secure.notes.services.impl;

import com.secure.notes.exceptions.ResourceNotFoundException;
import com.secure.notes.exceptions.UnauthorizedException;
import com.secure.notes.models.Note;
import com.secure.notes.repositories.NoteRepository;
import com.secure.notes.services.AuditLogService;
import com.secure.notes.services.NoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class NoteServiceImpl implements NoteService {
    @Autowired
    private NoteRepository noteRepository;

    @Autowired
    private AuditLogService auditLogService;

    @Override
    public Note createNoteForUser(String username, String content) {
        Note note = Note.builder()
                .ownerUsername(username)
                .content(content)
                .build();
        Note savedNote = noteRepository.save(note);
        auditLogService.logNoteCreation(username, savedNote);
        return savedNote;
    }

    @Override
    public Note updateNoteForUser(Long noteId, String username, String content) {
        Note note = noteRepository.findById(noteId)
                .orElseThrow(() -> new ResourceNotFoundException("Note not found with id: " + noteId));
        if (!note.getOwnerUsername().equals(username)) {
            throw new UnauthorizedException("You are not authorized to update this note");
        }

        note.setContent(content);
        auditLogService.logNoteUpdate(username, note);
        return noteRepository.save(note);
    }

    @Override
    public void deleteNoteForUser(Long noteId, String username) {
        Note note = noteRepository.findById(noteId)
                .orElseThrow(() -> new ResourceNotFoundException("Note not found with id: " + noteId));
        if (!note.getOwnerUsername().equals(username)) {
            throw new UnauthorizedException("You are not authorized to delete this note");
        }

        auditLogService.logNoteDeletion(username, noteId);
        noteRepository.delete(note);
    }

    @Override
    public List<Note> getNotesForUser(String username) {
        return noteRepository.findByOwnerUsername(username);
    }
}

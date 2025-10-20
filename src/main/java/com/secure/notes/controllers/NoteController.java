package com.secure.notes.controllers;

import com.secure.notes.dtos.NoteRequest;
import com.secure.notes.models.Note;
import com.secure.notes.services.NoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/notes")
public class NoteController {
    @Autowired
    private NoteService noteService;

    @PostMapping
    public Note createNote(@RequestBody NoteRequest request,
                           @AuthenticationPrincipal UserDetails userDetails) {
        System.out.println("User Details: " + userDetails);
        return noteService.createNoteForUser(userDetails.getUsername(), request.getContent());
    }

    @GetMapping
    public List<Note> getUserNotes(@AuthenticationPrincipal UserDetails userDetails) {
        return noteService.getNotesForUser(userDetails.getUsername());
    }

    @PutMapping("/{noteId}")
    public Note updateNote(@PathVariable Long noteId,
                                                  @RequestBody NoteRequest request,
                                                  @AuthenticationPrincipal UserDetails userDetails) {
        return noteService.updateNoteForUser(noteId, userDetails.getUsername(), request.getContent());
    }

    @DeleteMapping("/{noteId}")
    public void deleteNote(@PathVariable Long noteId,
                           @AuthenticationPrincipal UserDetails userDetails) {
        noteService.deleteNoteForUser(noteId, userDetails.getUsername());
    }
}

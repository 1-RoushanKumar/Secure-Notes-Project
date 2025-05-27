package com.prog.secure_note.controller;

import com.prog.secure_note.model.ContactMessage;
import com.prog.secure_note.model.Role;
import com.prog.secure_note.model.User;
import com.prog.secure_note.model.UserDTO;
import com.prog.secure_note.repositories.RoleRepository;
import com.prog.secure_note.service.ContactMessageService;
import com.prog.secure_note.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
//@PreAuthorize("hasRole('ROLE_ADMIN')") //added class level @PreAuthorize annotation.
public class AdminController {

    @Autowired
    UserService userService;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    private ContactMessageService contactMessageService;

    //    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/getusers")
    public ResponseEntity<List<User>> getAllUsers() {
        return new ResponseEntity<>(userService.getAllUsers(), HttpStatus.OK);
    }

    //    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PutMapping("/update-role")
    public ResponseEntity<String> updateUserRole(@RequestParam Long userId,
                                                 @RequestParam String roleName) {
        userService.updateUserRole(userId, roleName);
        return ResponseEntity.ok("User role updated");
    }

    //    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/user/{id}")
    public ResponseEntity<UserDTO> getUser(@PathVariable Long id) {
        return new ResponseEntity<>(userService.getUserById(id), HttpStatus.OK);
    }

    @PutMapping("/update-lock-status")
    public ResponseEntity<String> updateAccountLockStatus(@RequestParam Long userId, @RequestParam boolean lock) {
        userService.updateAccountLockStatus(userId, lock);
        return ResponseEntity.ok("Account lock status updated");
    }

    @GetMapping("/roles")
    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }

    @PutMapping("/update-expiry-status")
    public ResponseEntity<String> updateAccountExpiryStatus(@RequestParam Long userId, @RequestParam boolean expire) {
        userService.updateAccountExpiryStatus(userId, expire);
        return ResponseEntity.ok("Account expiry status updated");
    }

    @PutMapping("/update-enabled-status")
    public ResponseEntity<String> updateAccountEnabledStatus(@RequestParam Long userId, @RequestParam boolean enabled) {
        userService.updateAccountEnabledStatus(userId, enabled);
        return ResponseEntity.ok("Account enabled status updated");
    }

    @PutMapping("/update-credentials-expiry-status")
    public ResponseEntity<String> updateCredentialsExpiryStatus(@RequestParam Long userId, @RequestParam boolean expire) {
        userService.updateCredentialsExpiryStatus(userId, expire);
        return ResponseEntity.ok("Credentials expiry status updated");
    }

    @PutMapping("/update-password")
    public ResponseEntity<String> updatePassword(@RequestParam Long userId, @RequestParam String password) {
        try {
            userService.updatePassword(userId, password);
            return ResponseEntity.ok("Password updated");
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    //Here i added the contact message service to handle contact messages i added it in admin so only admin can access it.
    //Here it will fetch all the messages from the database.
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/contact-messages")
    public ResponseEntity<List<ContactMessage>> getAllContactMessages() {
        List<ContactMessage> messages = contactMessageService.getAllMessages();
        return new ResponseEntity<>(messages, HttpStatus.OK);
    }

    //Here it will use to delete the message by id.
    @PreAuthorize("hasRole('ROLE_ADMIN')") // Only admin users can access this endpoint
    @DeleteMapping("/message/{id}")
    public void deleteMessage(@PathVariable Long id) {
        contactMessageService.deleteMessages(id);
    }

    //Here it will use to delete all the messages.
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @DeleteMapping("/message/delete-all")
    public void deleteAllMessages() {
        contactMessageService.deleteAllMessages();
    }

    //Here it will change the status of the message.
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PutMapping("/message/{id}/status")
    public ResponseEntity<ContactMessage> updateMessageStatus(
            @PathVariable Long id,
            @RequestParam String status) {
        ContactMessage updatedMessage = contactMessageService.updateStatus(id, status);
        return ResponseEntity.ok(updatedMessage);
    }


}


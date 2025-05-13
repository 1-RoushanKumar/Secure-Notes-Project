package com.prog.secure_note.service;

import com.prog.secure_note.model.User;
import com.prog.secure_note.model.UserDTO;

import java.util.List;

public interface UserService {
    void updateUserRole(Long userId, String roleName);

    List<User> getAllUsers();

    UserDTO getUserById(Long id);

    User findByUsername(String username);
}

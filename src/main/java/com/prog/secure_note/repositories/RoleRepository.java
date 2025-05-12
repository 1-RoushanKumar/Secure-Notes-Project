package com.prog.secure_note.repositories;

import com.prog.secure_note.model.AppRole;
import com.prog.secure_note.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(AppRole appRole);

}
package com.prog.secure_note.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.HashSet;
import java.util.Set;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Data
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_id")
    private Integer roleId;

    //@Enumerated is used to specify that a persistent property or field should be persisted as an enumerated type.
    //here EnumType.STRING is used to specify that the enum should be persisted as a string in the database.(EnumType can be STRING or ORDINAL, by default it is ORDINAL so we need to specify it explicitly to use STRING).
    @ToString.Exclude
    @Enumerated(EnumType.STRING)
    @Column(length = 20, name = "role_name")
    private AppRole roleName;

    //Making one to many relationship between Role and User.
    @OneToMany(mappedBy = "role", fetch = FetchType.LAZY, cascade = {CascadeType.MERGE})
    @JsonBackReference
    @ToString.Exclude
    private Set<User> users = new HashSet<>(); // Set<User> is used to avoid duplicate users in the role.

    public Role(AppRole roleName) {
        this.roleName = roleName;
    }
}


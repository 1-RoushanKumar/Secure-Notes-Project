package com.prog.secure_note.security.response;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
public class LoginResponse {
    private String jwtToken;

    private String username;
    private List<String> roles;
    private String email;

    public LoginResponse(String username, List<String> roles, String jwtToken , String email) {
        this.username = username;
        this.roles = roles;
        this.jwtToken = jwtToken;
        this.email = email;
    }

}



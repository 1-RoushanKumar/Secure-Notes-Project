package com.prog.secure_note.Controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @GetMapping("/hello")
    public String hello() {
        return "Hello, World!";
    }

    @GetMapping("/contact")
    public String contact() {
        return "Contact Me!!";
    }

    @GetMapping("/about")
    public String about() {
        return "About Me!!";
    }
}

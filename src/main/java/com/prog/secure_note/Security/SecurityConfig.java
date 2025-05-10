package com.prog.secure_note.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    //copied from the SpringBootWebSecurityConfiguration.java class.
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) ->
                requests
                        .requestMatchers("/contact", "/about").permitAll()
                        .anyRequest().authenticated()); // it says that all requests that are hitting the server need to be authenticated.
//        http.formLogin(withDefaults()); // this is the default login form provided by Spring Security.
        http.httpBasic(withDefaults()); // this is the default basic authentication provided by Spring Security.
        return http.build();
    }
}

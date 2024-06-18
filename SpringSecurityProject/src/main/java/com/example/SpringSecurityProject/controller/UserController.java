package com.example.SpringSecurityProject.controller;

import com.example.SpringSecurityProject.domain.AuthenticationRequest;
import com.example.SpringSecurityProject.domain.AuthenticationResponse;
import com.example.SpringSecurityProject.service.MyUserDetailsService;
import com.example.SpringSecurityProject.util.JwtUtil;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final MyUserDetailsService userDetailsService;

    @Autowired
    public UserController(AuthenticationManager authenticationManager, JwtUtil jwtUtil, MyUserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/login")
    public AuthenticationResponse  createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        // Authenticate the user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        // Load user details
        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        // Generate JWT token
        final String jwt = jwtUtil.generateToken(userDetails.getUsername());
        System.out.println("Generated JWT Token: " + jwt);
        return new AuthenticationResponse(jwt);
    }

    @GetMapping("/secure")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String secureEndpoint() {
        return "This is a secure endpoint!";
    }
}

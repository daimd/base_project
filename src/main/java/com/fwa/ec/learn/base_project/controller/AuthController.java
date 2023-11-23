package com.fwa.ec.learn.base_project.controller;

import com.fwa.ec.learn.base_project.service.GenerateTokenService;
import com.fwa.ec.learn.base_project.utils.LoginRequest;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import org.springframework.web.bind.annotation.*;


//@CrossOrigin(origins = {"http://localhost:5173"})
@RestController
@RequiredArgsConstructor
public class AuthController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);
    private final GenerateTokenService generateTokenService;
    private final AuthenticationManager authenticationManager;

    @PostMapping
    @RequestMapping(value = "/token")
    public ResponseEntity<String> getToken(@RequestBody LoginRequest loginRequest) throws Exception {
        Authentication authenticationRequest =
                new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password());
        Authentication authenticationResponse =
                this.authenticationManager.authenticate(authenticationRequest);

        String token = generateTokenService.generateToken(authenticationResponse);
        LOG.info("Token granted: {}", token);
        return new ResponseEntity<>(token, HttpStatus.OK);
    }
}

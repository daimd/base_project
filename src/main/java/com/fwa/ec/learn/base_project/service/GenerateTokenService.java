package com.fwa.ec.learn.base_project.service;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Service
public class GenerateTokenService {

    private final JwtEncoder jwtEncoder;

    public GenerateTokenService(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;

    }

    public String generateToken(Authentication authentication){
        Instant instant = Instant.now();// we will record the creation to coz the token to expire in 8 hours
        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
        JwtClaimsSet jwtClaimsSet= JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(instant)
                .expiresAt(instant.plus(2, ChronoUnit.MINUTES))
                .subject(authentication.getName())
                .claim("scope",scope)
                .build();

        return this.jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
    }

}

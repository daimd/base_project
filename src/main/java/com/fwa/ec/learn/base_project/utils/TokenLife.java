package com.fwa.ec.learn.base_project.utils;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@ConfigurationProperties(prefix = "token")
public record TokenLife(Instant createdOn) {
    @Override
    public Instant createdOn() {
        return createdOn.plus(2, ChronoUnit.MINUTES);
    }
}

package com.fwa.ec.learn.base_project.utils;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties(prefix = "rsa")
public record RsaKeyProperties(RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey) {
}


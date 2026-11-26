package com.securebank;

import com.securebank.security.JwtKeys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SecureBankApplication {

    private static final Logger log = LoggerFactory.getLogger(SecureBankApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(SecureBankApplication.class, args);

        // LAB 8 (A04 — Cryptographic Failures): FIXED. The signing secret
        // used to be written to the log at startup, so anyone with log access
        // — or a screenshot of a CI console — could mint an admin token. The
        // secret now comes from the environment, and only its presence is
        // reported, never its value.
        JwtKeys.logSecretAtStartup(log);
    }
}

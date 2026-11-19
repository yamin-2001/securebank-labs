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

        // LAB 8 (A04 — Cryptographic Failures): the signing secret is
        // written to the log at startup. Anyone with log access — or a
        // screenshot of a CI console — can mint an admin token.
        JwtKeys.logSecretAtStartup(log);
    }
}

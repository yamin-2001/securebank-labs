package com.securebank.security;

import com.securebank.core.LabToggles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the lab-specific security components.
 *
 * <p>These live in their own configuration class rather than in
 * {@link SecurityConfig} because {@link SecurityConfig} injects
 * {@link LabAuthFilter} into its constructor — declaring the filter as a bean
 * in the same class would be a circular reference.
 */
@Configuration
public class LabSecurityBeans {

    @Bean
    public LabJwtService labJwtService(LabToggles labs) {
        return new LabJwtService(labs);
    }

    @Bean
    public LabAuthFilter labAuthFilter(LabJwtService jwt) {
        return new LabAuthFilter(jwt);
    }
}

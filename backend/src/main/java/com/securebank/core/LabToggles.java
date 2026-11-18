package com.securebank.core;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Runtime access to the per-lab toggles.
 *
 * <p>Used by every lab service to select the vulnerable branch. The toggle
 * arms the lab; the fix lives in the same method as the vulnerable branch.
 *
 * <p><strong>THE RULE:</strong> {@code lab.<slug>=true} ARMS a lab. It is
 * <em>not</em> the fix. Fixing a lab means editing the vulnerable code at the
 * location the lab's panel names — the toggle stays {@code true}. This is
 * what lets the verification harness assert on behaviour rather than on
 * configuration: the same exploit succeeds before the fix and fails after it,
 * with no flag change in between.
 *
 * <p>Toggles are read from the {@link Environment} rather than bound through
 * {@code @ConfigurationProperties}, because relaxed binding into a
 * {@code Map<String, Boolean>} field does not pick up flat {@code lab.*} keys
 * the way a plain property lookup does. Reading them explicitly keeps the
 * mechanism obvious and stable.
 */
@Component
public class LabToggles {

    private static final String PREFIX = "lab.";

    private final Environment env;
    private final Map<String, Boolean> cache = new LinkedHashMap<>();

    public LabToggles(Environment env) {
        this.env = env;
    }

    /** @return true if the named lab is armed (e.g. {@code isEnabled("idor")}). */
    public boolean isEnabled(String labId) {
        return Boolean.parseBoolean(env.getProperty(PREFIX + labId, "false"));
    }

    /** All lab ids that are currently armed. */
    public Map<String, Boolean> armedLabs() {
        return cache;
    }
}

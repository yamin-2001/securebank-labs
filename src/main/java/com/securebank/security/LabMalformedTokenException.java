package com.securebank.security;

/**
 * Thrown by the hand-rolled JWT parser when a token is structurally broken
 * (not base64url, not two parts, and so on).
 *
 * <p>This exception type exists to keep <strong>Lab 21</strong> and
 * <strong>Lab 25</strong> independent:
 *
 * <ul>
 *   <li>Lab 21's exploit is an <em>unsecured</em> token ({@code alg:none}).
 *       The fixed parser (jjwt) rejects it with a {@code JwtException}.</li>
 *   <li>Lab 25's exploit is a <em>malformed</em> token. The fail-open branch
 *       catches only this exception type.</li>
 * </ul>
 *
 * <p>Because the two catch different exception types, fixing Lab 21 (switch
 * to jjwt) does not silently also fix Lab 25, and fixing Lab 25 (fail closed)
 * does not silently also fix Lab 21.
 */
public class LabMalformedTokenException extends RuntimeException {

    public LabMalformedTokenException(String message) {
        super(message);
    }

    public LabMalformedTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}

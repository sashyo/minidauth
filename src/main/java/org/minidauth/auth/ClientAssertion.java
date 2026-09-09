package org.minidauth.auth;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Deque;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedDeque;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Proof that a caller holds a private key, without ever sending it.
 *
 * <p>A shared secret has to exist at both ends, so a copy of this service's configuration is a copy
 * of every caller's credential. That sits badly in a project whose claim is that reading the host
 * hands you nothing. Here the caller signs a short-lived assertion and this service keeps only a
 * public key, so the operators file is no longer worth stealing and a leak at either end is worth
 * nothing on its own.
 *
 * <p>The shape is a JWT, because every language can already produce one, with Ed25519 to match the
 * signatures the rest of this project deals in. Three things are checked beyond the signature: that
 * it was meant for this service, that it is fresh, and that it has not been seen before. The last is
 * what stops an assertion observed in transit being replayed by whoever saw it.
 */
public final class ClientAssertion {

    /** How far from now an assertion may claim to have been issued. */
    static final long MAX_AGE_SECONDS = 300;

    /** Clock skew allowed in the caller's favour. */
    static final long SKEW_SECONDS = 60;

    /** Enough jtis to cover the freshness window comfortably. */
    private static final int REPLAY_MEMORY = 8192;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /* Seen jtis, in arrival order so the oldest can be dropped.
     *
     * Bounded rather than time-swept: an assertion older than the freshness window is refused before
     * this is consulted, so forgetting the oldest can never let a still-valid one through. */
    private final Set<String> seen = new HashSet<>();
    private final Deque<String> order = new ConcurrentLinkedDeque<>();

    private final String audience;

    public ClientAssertion(String audience) {
        this.audience = audience;
    }

    /** Why an assertion was refused. Never says which part of a signature failed. */
    public static final class Invalid extends RuntimeException {
        public Invalid(String message) { super(message); }
    }

    /**
     * Check an assertion and return the name it claims to be.
     *
     * <p>The caller looks that name up and verifies the signature against the key it finds, so an
     * unknown name and a bad signature are the same answer here: refused.
     */
    public String verify(String compact, java.util.function.Function<String, String> publicKeyFor) {
        String[] parts = compact.split("\\.");
        if (parts.length != 3) {
            throw new Invalid("An assertion is three dot separated parts");
        }

        Map<String, Object> claims;
        try {
            claims = MAPPER.readValue(Base64.getUrlDecoder().decode(parts[1]), Map.class);
        } catch (Exception e) {
            throw new Invalid("The assertion's claims could not be read");
        }

        String issuer = str(claims, "iss");
        if (issuer == null) throw new Invalid("The assertion names no issuer");

        if (!audience.equals(str(claims, "aud"))) {
            // Without this an assertion made for another service would be accepted here.
            throw new Invalid("The assertion was not meant for this service");
        }

        long now = Instant.now().getEpochSecond();
        Long issuedAt = num(claims, "iat");
        Long expiry = num(claims, "exp");
        if (issuedAt == null || expiry == null) throw new Invalid("The assertion has no lifetime");
        if (issuedAt > now + SKEW_SECONDS) throw new Invalid("The assertion is issued in the future");
        if (expiry < now - SKEW_SECONDS) throw new Invalid("The assertion has expired");
        if (expiry - issuedAt > MAX_AGE_SECONDS) {
            throw new Invalid("The assertion is valid for longer than " + MAX_AGE_SECONDS + "s");
        }

        String jti = str(claims, "jti");
        if (jti == null || jti.isBlank()) throw new Invalid("The assertion has no jti");

        String encodedKey = publicKeyFor.apply(issuer);
        if (encodedKey == null) throw new Invalid("Unknown client");

        byte[] signed = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        if (!signatureVerifies(encodedKey, signed, Base64.getUrlDecoder().decode(parts[2]))) {
            throw new Invalid("The assertion's signature did not verify");
        }

        // Last, so a replay cannot be recorded by anything that failed earlier.
        remember(jti);
        return issuer;
    }

    private synchronized void remember(String jti) {
        if (!seen.add(jti)) throw new Invalid("This assertion has already been used");
        order.addLast(jti);
        while (order.size() > REPLAY_MEMORY) {
            seen.remove(order.pollFirst());
        }
    }

    private static boolean signatureVerifies(String encodedKey, byte[] signed, byte[] signature) {
        try {
            PublicKey key = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(encodedKey)));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(signed);
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    private static String str(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v == null ? null : String.valueOf(v);
    }

    private static Long num(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v instanceof Number n ? n.longValue() : null;
    }
}

package org.minidauth.tide;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

/**
 * An enclave approval token.
 *
 * <p>A doken is a JWT the ORK cohort issues under the threshold VVK. It names the Tide identity that
 * approved ({@code vuid}), what it is good for ({@code aud}) and when it stops being good
 * ({@code exp}).
 *
 * <p><b>Why this class verifies rather than just parses.</b> The approval has to be credited to the
 * identity inside the doken, not to whoever made the HTTP call. TideCloak's own IGA surface credits
 * the caller, so proxying approvals through a service account records every human's approval under
 * that one account and the quorum silently collapses. Reading {@code vuid} out of an unverified
 * token would be no better than trusting the caller, so the signature is checked against the VVK
 * public key before the vuid is believed.
 */
public final class Doken {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public final String vuid;
    public final String audience;
    public final long expiresAt;
    public final JsonNode payload;
    private final String raw;

    private Doken(String vuid, String audience, long expiresAt, JsonNode payload, String raw) {
        this.vuid = vuid;
        this.audience = audience;
        this.expiresAt = expiresAt;
        this.payload = payload;
        this.raw = raw;
    }

    public String raw() { return raw; }

    public boolean hasExpired() {
        return expiresAt > 0 && expiresAt < Instant.now().getEpochSecond();
    }

    /**
     * Parse and verify a doken against the VVK.
     *
     * @param token      the compact JWT the enclave returned
     * @param gVVKHex    the VVK public point, hex, the {@code clientId} the wallet finalize produced
     * @throws IllegalArgumentException if the token is malformed or its signature does not verify
     */
    public static Doken verify(String token, String gVVKHex) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("No doken supplied");
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("A doken must be a compact JWT with three segments, got " + parts.length);
        }

        byte[] signed = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8);
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);

        if (!ed25519Verify(publicKeyFromHex(gVVKHex), signed, signature)) {
            throw new IllegalArgumentException(
                    "Doken signature does not verify against this vendor's VVK. It was issued for a "
                            + "different vendor, or it has been tampered with.");
        }

        JsonNode payload;
        try {
            payload = MAPPER.readTree(Base64.getUrlDecoder().decode(parts[1]));
        } catch (Exception e) {
            throw new IllegalArgumentException("Doken payload is not JSON", e);
        }

        JsonNode vuidNode = payload.get("vuid");
        if (vuidNode == null || !vuidNode.isTextual()) {
            throw new IllegalArgumentException("Doken carries no vuid, so it names no approver");
        }

        return new Doken(
                vuidNode.asText(),
                payload.hasNonNull("aud") ? payload.get("aud").asText() : null,
                payload.hasNonNull("exp") ? payload.get("exp").asLong() : 0L,
                payload,
                token);
    }

    /**
     * Rebuild an Ed25519 public key from a 32-byte compressed point.
     *
     * <p>The wire form is little-endian with the x-coordinate's sign in the top bit of the last
     * byte, which is the inverse of what {@link EdECPoint} wants.
     */
    static PublicKey publicKeyFromHex(String hex) {
        if (hex == null || hex.isBlank()) {
            throw new IllegalStateException("No VVK public key available to verify against");
        }
        byte[] point = HexFormat.of().parseHex(hex.trim());
        if (point.length != 32) {
            throw new IllegalStateException("A VVK public point must be 32 bytes, got " + point.length);
        }
        byte[] le = point.clone();
        boolean xOdd = (le[31] & 0x80) != 0;
        le[31] &= 0x7F;

        // reverse to big-endian for BigInteger
        byte[] be = new byte[32];
        for (int i = 0; i < 32; i++) be[i] = le[31 - i];

        try {
            EdECPoint p = new EdECPoint(xOdd, new BigInteger(1, be));
            return KeyFactory.getInstance("Ed25519")
                    .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, p));
        } catch (Exception e) {
            throw new IllegalStateException("Could not rebuild the VVK public key from " + hex, e);
        }
    }

    static boolean ed25519Verify(PublicKey key, byte[] message, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }
}

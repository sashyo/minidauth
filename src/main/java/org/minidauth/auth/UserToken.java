package org.minidauth.auth;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.minidauth.config.Config;

/**
 * Verifies an end user's token and returns the user id it carries.
 *
 * <p>The tideless voucher and sign paths trust the calling application to name the user, because the
 * application did the login. That is fine until the application is exactly what you no longer want to
 * trust to name users. This closes that: the user presents a token their IAM signed, this service
 * verifies it here, and the user id comes from a verified claim rather than a field the caller filled
 * in. The ORKs are untouched, they still honour whatever voucher this service issues.
 *
 * <p>HS256, because that is what the apps in front of this already mint. The identity is only as
 * strong as the secret shared with the issuing IAM; roles are still the quorum-approved grant read
 * live, never a claim in this token.
 */
public final class UserToken {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Clock skew allowed in the user's favour. */
    private static final long SKEW_SECONDS = 60;

    private final byte[] secret;       // HS256 (fallback), or null when using a public key
    private final PublicKey publicKey; // Ed25519 (preferred), or null when using a secret
    private final String issuer;   // required iss, or null
    private final String audience; // required aud, or null
    private final String uidClaim;

    public UserToken(Config.UserTokenConfig cfg) {
        if (cfg.publicKey != null && !cfg.publicKey.isBlank()) {
            this.secret = null;
            try {
                this.publicKey = KeyFactory.getInstance("Ed25519")
                        .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(cfg.publicKey.trim())));
            } catch (Exception e) {
                throw new IllegalStateException("MC_USER_TOKEN_PUBLIC_KEY is not a valid Ed25519 SPKI key", e);
            }
        } else {
            this.publicKey = null;
            this.secret = cfg.secret.getBytes(StandardCharsets.UTF_8);
        }
        this.issuer = cfg.issuer;
        this.audience = cfg.audience;
        this.uidClaim = cfg.uidClaim;
    }

    /** Why a token was refused. Never says which part failed. */
    public static final class Invalid extends RuntimeException {
        public Invalid(String message) { super(message); }
    }

    /** Check the token and return the user id it claims, or throw {@link Invalid}. */
    public Verified verify(String compact) {
        String[] parts = compact == null ? new String[0] : compact.split("\\.");
        if (parts.length != 3) throw new Invalid("A user token is three dot separated parts");

        Map<String, Object> header;
        Map<String, Object> claims;
        try {
            header = MAPPER.readValue(Base64.getUrlDecoder().decode(parts[0]), Map.class);
            claims = MAPPER.readValue(Base64.getUrlDecoder().decode(parts[1]), Map.class);
        } catch (Exception e) {
            throw new Invalid("The user token could not be read");
        }

        String alg = str(header, "alg");
        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        byte[] got;
        try {
            got = Base64.getUrlDecoder().decode(parts[2]);
        } catch (Exception e) {
            throw new Invalid("The user token signature could not be read");
        }
        if (publicKey != null) {
            if (!"EdDSA".equals(alg)) throw new Invalid("Unexpected token algorithm");
            if (!ed25519Verifies(signingInput, got)) throw new Invalid("The user token signature did not verify");
        } else {
            if (!"HS256".equals(alg)) throw new Invalid("Unexpected token algorithm");
            if (!MessageDigest.isEqual(hmac(signingInput), got)) throw new Invalid("The user token signature did not verify");
        }

        long now = Instant.now().getEpochSecond();
        Long exp = num(claims, "exp");
        Long nbf = num(claims, "nbf");
        if (exp != null && now > exp + SKEW_SECONDS) throw new Invalid("The user token has expired");
        if (nbf != null && now < nbf - SKEW_SECONDS) throw new Invalid("The user token is not yet valid");
        if (issuer != null && !issuer.equals(str(claims, "iss"))) throw new Invalid("The user token issuer is not trusted");
        if (audience != null && !audienceMatches(claims)) throw new Invalid("The user token was not meant for this service");

        String uid = str(claims, uidClaim);
        if (uid == null || uid.isBlank()) throw new Invalid("The user token names no user (" + uidClaim + ")");
        return new Verified(uid, str(claims, "cnf"));
    }

    /** A verified user token: the user id, and the session key it is bound to (cnf), if any. */
    public record Verified(String uid, String cnf) {}

    private boolean audienceMatches(Map<String, Object> claims) {
        Object aud = claims.get("aud");
        if (aud instanceof String s) return audience.equals(s);
        if (aud instanceof List<?> list) return list.stream().map(String::valueOf).anyMatch(audience::equals);
        return false;
    }

    private boolean ed25519Verifies(byte[] signed, byte[] signature) {
        try {
            Signature v = Signature.getInstance("Ed25519");
            v.initVerify(publicKey);
            v.update(signed);
            return v.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    private byte[] hmac(byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new Invalid("The user token signature could not be checked");
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

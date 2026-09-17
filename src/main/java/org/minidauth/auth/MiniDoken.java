package org.minidauth.auth;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Something like a doken, minted and verified by this service instead of the ORK cohort.
 *
 * <p>A real doken is minted by the cohort after an enclave sign-in, carries cohort-attested roles,
 * and is bound to a session key so a copy lifted from anywhere is useless. We cannot mint one without
 * changing the ORKs. But the cohort never checks user identity on a tideless voucher anyway, it
 * honours whatever voucher this service issues, so the identity boundary is already here. This gives
 * a token with the doken's two operational properties this service can provide on its own:
 *
 * <ul>
 *   <li><b>Session binding.</b> The token carries the public half of a key the client generated
 *       ({@code cnf}). Every use must be accompanied by a fresh signature from the private half
 *       (proof of possession), so a stolen token without that key is inert. This is the DPoP idea.</li>
 *   <li><b>Short life, live roles.</b> The token only names the user; roles are still read live from
 *       the quorum-approved grant at every voucher, so a revocation takes effect at once and the
 *       token never carries an authority of its own.</li>
 * </ul>
 *
 * <p>What it is not: cohort-attested. The verification root is this service, not the distributed
 * network, which is the price of touching nothing but this service. It is signed with a secret minted
 * at boot and never leaves this process, so the token is only ever verified by its issuer.
 */
public final class MiniDoken {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder UB64URL = Base64.getUrlDecoder();

    /** Clock skew allowed on a proof of possession. */
    private static final long POP_SKEW_SECONDS = 60;

    private final byte[] secret; // minted at boot, never leaves this process
    private final long ttlSeconds;
    private final Clock clock;

    // Proofs seen, keyed by nonce -> the time after which it may be forgotten. Eviction is by TIME,
    // not count: a nonce is remembered for the whole freshness window, so a captured proof cannot be
    // replayed by flooding the cache to push it out (a count-bounded cache could be).
    private final Map<String, Long> seenUntil = new HashMap<>();

    public MiniDoken(long ttlSeconds) {
        this(ttlSeconds, Clock.systemUTC());
    }

    MiniDoken(long ttlSeconds, Clock clock) {
        this.ttlSeconds = ttlSeconds;
        this.clock = clock;
        byte[] s = new byte[32];
        new SecureRandom().nextBytes(s);
        this.secret = s;
    }

    public static final class Invalid extends RuntimeException {
        public Invalid(String message) { super(message); }
    }

    /** What a verified mini-doken carries. {@code sid} is the app session it was minted for, so the app
     *  can revoke every doken of a session at logout; null on a doken minted without one. */
    public record Parsed(String uid, String sessionKeyB64, String role, String sid) {}

    /** Mint a token binding {@code uid} to the client's Ed25519 session public key (SPKI, base64) and
     *  to a single {@code role} scope, set by the minting app. The role is then not something the
     *  caller can change at voucher time: a doken scoped to one role cannot request another. {@code sid}
     *  carries the app session so the app can revoke it at logout; pass null to mint without one. */
    public String mint(String uid, String sessionKeyB64, String role, String sid) {
        long now = clock.instant().getEpochSecond();
        String header = B64URL.encodeToString("{\"alg\":\"HS256\",\"typ\":\"mdk\"}".getBytes(StandardCharsets.US_ASCII));
        Map<String, Object> claimMap = new HashMap<>(Map.of(
                "sub", uid, "cnf", sessionKeyB64, "role", role == null ? "" : role, "iat", now, "exp", now + ttlSeconds));
        if (sid != null && !sid.isBlank()) claimMap.put("sid", sid);
        String claims;
        try {
            claims = B64URL.encodeToString(MAPPER.writeValueAsBytes(claimMap));
        } catch (Exception e) {
            throw new Invalid("The user doken could not be minted");
        }
        String sig = B64URL.encodeToString(hmac((header + "." + claims).getBytes(StandardCharsets.US_ASCII)));
        return header + "." + claims + "." + sig;
    }

    /** Verify the token's own signature and lifetime; return the uid and the bound session key. */
    public Parsed verify(String compact) {
        String[] parts = compact == null ? new String[0] : compact.split("\\.");
        if (parts.length != 3) throw new Invalid("A user doken is three dot separated parts");

        byte[] expected = hmac((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        byte[] got;
        try {
            got = UB64URL.decode(parts[2]);
        } catch (Exception e) {
            throw new Invalid("The user doken signature could not be read");
        }
        if (!MessageDigest.isEqual(expected, got)) throw new Invalid("The user doken did not verify");

        Map<String, Object> claims;
        try {
            claims = MAPPER.readValue(UB64URL.decode(parts[1]), Map.class);
        } catch (Exception e) {
            throw new Invalid("The user doken claims could not be read");
        }
        Long exp = num(claims, "exp");
        if (exp == null || clock.instant().getEpochSecond() >= exp) throw new Invalid("The user doken has expired");
        String uid = str(claims, "sub");
        String cnf = str(claims, "cnf");
        if (uid == null || uid.isBlank() || cnf == null || cnf.isBlank()) throw new Invalid("The user doken is incomplete");
        return new Parsed(uid, cnf, str(claims, "role"), str(claims, "sid"));
    }

    /**
     * Verify a proof of possession: an Ed25519 signature by the bound session key over
     * {@code sub.timestamp.nonce.sha256(boundRequest)}, fresh and not replayed. Binding the request
     * hash is what stops a captured proof being redirected: a proof made for one decryption cannot
     * authorize a different one, because this service recomputes the hash from the request it actually
     * received. The nonce lets many legitimate reads in the same second each carry a distinct proof
     * and, once remembered, stops any proof being reused; the timestamp bounds the window. A stolen
     * doken without the session key cannot produce any of this.
     */
    public void verifyProofOfPossession(Parsed dk, String timestamp, String nonce, String boundRequest, String popSigB64) {
        if (timestamp == null || nonce == null || nonce.isBlank() || popSigB64 == null) {
            throw new Invalid("A proof of possession is required");
        }
        long ts;
        try {
            ts = Long.parseLong(timestamp.trim());
        } catch (Exception e) {
            throw new Invalid("The proof of possession timestamp is malformed");
        }
        long now = clock.instant().getEpochSecond();
        if (ts < now - POP_SKEW_SECONDS || ts > now + POP_SKEW_SECONDS) {
            throw new Invalid("The proof of possession is stale");
        }
        String requestHash = sha256Hex(boundRequest == null ? "" : boundRequest);
        byte[] signed = (dk.uid() + "." + ts + "." + nonce + "." + requestHash).getBytes(StandardCharsets.US_ASCII);
        if (!ed25519Verifies(dk.sessionKeyB64(), signed, popSigB64)) {
            throw new Invalid("The proof of possession did not verify");
        }
        remember(nonce, ts); // last, so a failure above cannot record a replay slot
    }

    private static String sha256Hex(String s) {
        try {
            byte[] d = java.security.MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte x : d) sb.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
            return sb.toString();
        } catch (Exception e) {
            throw new Invalid("hash failure");
        }
    }

    private synchronized void remember(String nonce, long timestamp) {
        long now = clock.instant().getEpochSecond();
        seenUntil.entrySet().removeIf(e -> e.getValue() <= now); // forget only nonces past the window
        // Future-dated proofs remain fresh longer than one skew window after receipt. Keep their
        // nonce through the last accepted second of the proof's own timestamp window.
        if (seenUntil.putIfAbsent(nonce, timestamp + POP_SKEW_SECONDS + 1) != null) {
            throw new Invalid("This proof of possession has already been used");
        }
    }

    private static boolean ed25519Verifies(String spkiB64, byte[] signed, String sigB64) {
        try {
            PublicKey key = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(spkiB64)));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(signed);
            return verifier.verify(Base64.getUrlDecoder().decode(sigB64));
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
            throw new Invalid("The user doken signature could not be computed");
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

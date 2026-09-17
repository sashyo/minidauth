package org.minidauth.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

class MiniDokenTest {
    private final MutableClock clock = new MutableClock();
    private final MiniDoken verifier = new MiniDoken(120, clock);
    private final KeyPair key = keyPair();

    @Test
    void acceptsTheBoundKeyAndRejectsImmediateReplay() throws Exception {
        var token = verifier.verify(token());
        String timestamp = Long.toString(clock.instant().getEpochSecond());
        String proof = proof(timestamp, "once", "request");
        verifier.verifyProofOfPossession(token, timestamp, "once", "request", proof);
        assertThrows(MiniDoken.Invalid.class, () ->
                verifier.verifyProofOfPossession(token, timestamp, "once", "request", proof));
    }

    @Test
    void retainsFutureDatedProofUntilItsEntireFreshnessWindowCloses() throws Exception {
        var token = verifier.verify(token());
        String timestamp = Long.toString(clock.instant().getEpochSecond() + 55);
        String proof = proof(timestamp, "future", "request");
        verifier.verifyProofOfPossession(token, timestamp, "future", "request", proof);
        clock.advance(66);
        assertThrows(MiniDoken.Invalid.class, () ->
                verifier.verifyProofOfPossession(token, timestamp, "future", "request", proof));
        clock.advance(49);
        assertThrows(MiniDoken.Invalid.class, () ->
                verifier.verifyProofOfPossession(token, timestamp, "future", "request", proof));
    }

    @Test
    void rejectsTimestampOverflow() throws Exception {
        var token = verifier.verify(token());
        String timestamp = Long.toString(clock.instant().getEpochSecond() - Long.MIN_VALUE);
        String proof = proof(timestamp, "overflow", "request");
        assertThrows(MiniDoken.Invalid.class, () ->
                verifier.verifyProofOfPossession(token, timestamp, "overflow", "request", proof));
    }

    @Test
    void rejectsChangedRequestWithoutConsumingTheOriginalProof() throws Exception {
        var token = verifier.verify(token());
        String timestamp = Long.toString(clock.instant().getEpochSecond());
        String proof = proof(timestamp, "bound", "original");
        assertThrows(MiniDoken.Invalid.class, () ->
                verifier.verifyProofOfPossession(token, timestamp, "bound", "changed", proof));
        verifier.verifyProofOfPossession(token, timestamp, "bound", "original", proof);
    }

    @Test
    void tokenExpiresAtItsExpiryTime() {
        String token = token();
        assertEquals("reader", verifier.verify(token).uid());
        clock.advance(120);
        assertThrows(MiniDoken.Invalid.class, () -> verifier.verify(token));
    }

    private String token() {
        return verifier.mint("reader", Base64.getEncoder().encodeToString(key.getPublic().getEncoded()), "crm-reader", null);
    }

    private String proof(String timestamp, String nonce, String request) throws Exception {
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(request.getBytes(StandardCharsets.UTF_8)));
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key.getPrivate());
        signer.update(("reader." + timestamp + "." + nonce + "." + hash).getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
    }

    private static KeyPair keyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static final class MutableClock extends Clock {
        private Instant now = Instant.ofEpochSecond(1_800_000_000);
        void advance(long seconds) { now = now.plusSeconds(seconds); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}

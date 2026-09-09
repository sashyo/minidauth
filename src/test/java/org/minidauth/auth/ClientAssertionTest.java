package org.minidauth.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import org.junit.jupiter.api.Test;

class ClientAssertionTest {

    private static final String AUDIENCE = "http://localhost:8081";

    private final KeyPair app = keyPair();
    private final KeyPair other = keyPair();
    private final String appKey = publicKeyOf(app);

    private ClientAssertion verifier() {
        return new ClientAssertion(AUDIENCE);
    }

    private String keyFor(String name) {
        return "app".equals(name) ? appKey : null;
    }

    @Test
    void acceptsAnAssertionSignedByTheRegisteredKey() {
        assertEquals("app", verifier().verify(assertion(app, claims("app", AUDIENCE, 60)), this::keyFor));
    }

    @Test
    void refusesTheSameAssertionTwice() {
        ClientAssertion verifier = verifier();
        String once = assertion(app, claims("app", AUDIENCE, 60));
        verifier.verify(once, this::keyFor);
        // Whoever observes an assertion in transit must not be able to use it.
        assertThrows(ClientAssertion.Invalid.class, () -> verifier.verify(once, this::keyFor));
    }

    @Test
    void refusesAnAssertionMeantForSomewhereElse() {
        assertThrows(ClientAssertion.Invalid.class, () ->
                verifier().verify(assertion(app, claims("app", "https://elsewhere.example", 60)), this::keyFor));
    }

    @Test
    void refusesAnExpiredAssertion() {
        long past = Instant.now().getEpochSecond() - 600;
        String json = "{\"iss\":\"app\",\"aud\":\"" + AUDIENCE + "\",\"iat\":" + past
                + ",\"exp\":" + (past + 60) + ",\"jti\":\"" + UUID.randomUUID() + "\"}";
        assertThrows(ClientAssertion.Invalid.class, () ->
                verifier().verify(assertion(app, json), this::keyFor));
    }

    @Test
    void refusesAnAssertionThatWouldLiveTooLong() {
        assertThrows(ClientAssertion.Invalid.class, () ->
                verifier().verify(assertion(app, claims("app", AUDIENCE, 86400)), this::keyFor));
    }

    @Test
    void refusesAKeyItDoesNotKnow() {
        assertThrows(ClientAssertion.Invalid.class, () ->
                verifier().verify(assertion(app, claims("nobody", AUDIENCE, 60)), this::keyFor));
    }

    /** The point of the whole mechanism: claiming a name is not holding its key. */
    @Test
    void refusesSomebodyElsesSignatureUnderTheAppsName() {
        assertThrows(ClientAssertion.Invalid.class, () ->
                verifier().verify(assertion(other, claims("app", AUDIENCE, 60)), this::keyFor));
    }

    @Test
    void refusesAMalformedAssertion() {
        assertThrows(ClientAssertion.Invalid.class, () -> verifier().verify("not.an.assertion", this::keyFor));
        assertThrows(ClientAssertion.Invalid.class, () -> verifier().verify("two.parts", this::keyFor));
    }

    // ------------------------------------------------------------------ helpers

    private static String claims(String issuer, String audience, long lifetime) {
        long now = Instant.now().getEpochSecond();
        return "{\"iss\":\"" + issuer + "\",\"aud\":\"" + audience + "\",\"iat\":" + now
                + ",\"exp\":" + (now + lifetime) + ",\"jti\":\"" + UUID.randomUUID() + "\"}";
    }

    private static String assertion(KeyPair signer, String claimsJson) {
        String header = b64("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}");
        String payload = b64(claimsJson);
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(signer.getPrivate());
            s.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
            return header + "." + payload + "."
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(s.sign());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static KeyPair keyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String publicKeyOf(KeyPair pair) {
        return Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
    }
}

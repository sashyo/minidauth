package org.minidauth.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.minidauth.config.Config;

class UserTokenTest {
    private final KeyPair key = keyPair();
    private final UserToken verifier = new UserToken(new Config.UserTokenConfig(null,
            Base64.getEncoder().encodeToString(key.getPublic().getEncoded()), null, null, "sub"));

    @Test
    void acceptsAValidSignedBoundToken() throws Exception {
        var claims = Map.of("sub", "reader", "cnf", "session", "exp", Instant.now().getEpochSecond() + 30);
        var verified = verifier.verify(sign(new ObjectMapper().writeValueAsString(claims)));
        assertEquals("reader", verified.uid());
        assertEquals("session", verified.cnf());
    }

    @Test
    void requiresExpiry() throws Exception {
        String token = sign("{\"sub\":\"reader\",\"cnf\":\"session\"}");
        assertThrows(UserToken.Invalid.class, () -> verifier.verify(token));
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "\"expired\"", "true", "{}", "1800000000.5", "18446744075509551616"})
    void rejectsNonIntegerExpiry(String expiry) throws Exception {
        String token = sign("{\"sub\":\"reader\",\"cnf\":\"session\",\"exp\":" + expiry + "}");
        assertThrows(UserToken.Invalid.class, () -> verifier.verify(token));
    }

    @Test
    void rejectsMalformedNotBefore() throws Exception {
        String token = sign("{\"sub\":\"reader\",\"nbf\":\"tomorrow\",\"exp\":"
                + (Instant.now().getEpochSecond() + 30) + "}");
        assertThrows(UserToken.Invalid.class, () -> verifier.verify(token));
    }

    @Test
    void rejectsExpiredAndNotYetValidTokens() throws Exception {
        long now = Instant.now().getEpochSecond();
        String expired = sign("{\"sub\":\"reader\",\"exp\":" + (now - 120) + "}");
        String future = sign("{\"sub\":\"reader\",\"exp\":" + (now + 600) + ",\"nbf\":" + (now + 300) + "}");
        assertThrows(UserToken.Invalid.class, () -> verifier.verify(expired));
        assertThrows(UserToken.Invalid.class, () -> verifier.verify(future));
    }

    @Test
    void refusesModifiedClaims() throws Exception {
        String token = sign("{\"sub\":\"reader\",\"exp\":" + (Instant.now().getEpochSecond() + 30) + "}");
        String[] parts = token.split("\\.");
        String forged = parts[0] + "." + encode("{\"sub\":\"other\",\"exp\":1900000000}") + "." + parts[2];
        assertThrows(UserToken.Invalid.class, () -> verifier.verify(forged));
    }

    private String sign(String claims) throws Exception {
        String input = encode("{\"alg\":\"EdDSA\"}") + "." + encode(claims);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key.getPrivate());
        signer.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static KeyPair keyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}

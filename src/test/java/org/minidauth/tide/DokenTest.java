package org.minidauth.tide;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.EdECPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The doken is what makes an approval attributable to a person rather than to whoever holds the
 * service token, so its verification is load bearing. These round-trip a real Ed25519 key through
 * the same wire encoding the VVK public point uses.
 */
class DokenTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private record Vendor(KeyPair keys, String gVVKHex) {}

    /** A stand-in for the cohort's VVK. */
    private static Vendor vendor() throws Exception {
        KeyPair kp = DokenTestKeys.generate();
        return new Vendor(kp, DokenTestKeys.encodePoint(kp.getPublic()));
    }

    private static String jwt(KeyPair keys, Map<String, Object> claims) throws Exception {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String header = b64.encodeToString(MAPPER.writeValueAsBytes(Map.of("alg", "EdDSA", "typ", "JWT")));
        String payload = b64.encodeToString(MAPPER.writeValueAsBytes(claims));
        String signingInput = header + "." + payload;

        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(keys.getPrivate());
        signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
        return signingInput + "." + b64.encodeToString(signer.sign());
    }

    private static Map<String, Object> claims(String vuid, long exp) {
        return Map.of("vuid", vuid, "aud", "minified-tidecloak", "exp", exp);
    }

    @Test
    void aValidDokenYieldsItsVuid() throws Exception {
        Vendor v = vendor();
        long exp = Instant.now().getEpochSecond() + 300;
        Doken d = Doken.verify(jwt(v.keys(), claims("vuid-alice", exp)), v.gVVKHex());

        assertEquals("vuid-alice", d.vuid);
        assertEquals("minified-tidecloak", d.audience);
        assertEquals(exp, d.expiresAt);
        assertFalse(d.hasExpired());
    }

    @Test
    void aDokenFromAnotherVendorIsRejected() throws Exception {
        Vendor ours = vendor();
        Vendor theirs = vendor();
        String foreign = jwt(theirs.keys(), claims("vuid-mallory", Instant.now().getEpochSecond() + 300));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Doken.verify(foreign, ours.gVVKHex()));
        assertTrue(e.getMessage().contains("does not verify"));
    }

    /**
     * The attack this exists to stop: swap the vuid for someone else's and the signature no longer
     * covers the payload.
     */
    @Test
    void aTamperedVuidIsRejected() throws Exception {
        Vendor v = vendor();
        String token = jwt(v.keys(), claims("vuid-alice", Instant.now().getEpochSecond() + 300));
        String[] parts = token.split("\\.");
        String forgedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MAPPER.writeValueAsBytes(claims("vuid-bob", Instant.now().getEpochSecond() + 300)));
        String forged = parts[0] + "." + forgedPayload + "." + parts[2];

        assertThrows(IllegalArgumentException.class, () -> Doken.verify(forged, v.gVVKHex()));
    }

    @Test
    void anExpiredDokenVerifiesButReportsItselfExpired() throws Exception {
        Vendor v = vendor();
        Doken d = Doken.verify(jwt(v.keys(), claims("vuid-alice", 1_000L)), v.gVVKHex());
        assertTrue(d.hasExpired(), "an old approval must not be replayable");
    }

    @Test
    void aDokenWithNoVuidNamesNoApproverAndIsRejected() throws Exception {
        Vendor v = vendor();
        String token = jwt(v.keys(), Map.of("aud", "minified-tidecloak",
                "exp", Instant.now().getEpochSecond() + 300));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Doken.verify(token, v.gVVKHex()))
                .getMessage().contains("no vuid"));
    }

    @Test
    void malformedInputIsRejectedRatherThanParsedLoosely() throws Exception {
        Vendor v = vendor();
        assertThrows(IllegalArgumentException.class, () -> Doken.verify(null, v.gVVKHex()));
        assertThrows(IllegalArgumentException.class, () -> Doken.verify("", v.gVVKHex()));
        assertThrows(IllegalArgumentException.class, () -> Doken.verify("not.a.jwt.at.all", v.gVVKHex()));
        assertThrows(IllegalArgumentException.class, () -> Doken.verify("onlyonepart", v.gVVKHex()));
    }

    @Test
    void theVvkPointRoundTripsThroughTheWireEncoding() throws Exception {
        for (int i = 0; i < 20; i++) { // exercise both parities of the sign bit
            Vendor v = vendor();
            assertEquals(v.keys().getPublic(), Doken.publicKeyFromHex(v.gVVKHex()));
        }
    }

    @Test
    void anUnusableVvkIsRefusedClearly() {
        assertThrows(IllegalStateException.class, () -> Doken.publicKeyFromHex(null));
        assertThrows(IllegalStateException.class, () -> Doken.publicKeyFromHex("aabb"));
    }
}

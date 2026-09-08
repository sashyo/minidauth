package org.minidauth.auth;

import org.junit.jupiter.api.Test;
import org.minidauth.tide.DokenBuilder;
import org.minidauth.tide.DokenTestKeys;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * These tests are the door to governance. Everything a compromised application might try, a doken
 * it forged, one it copied from another vendor, an expired one, one naming a role that was revoked
 * an hour ago, has to fail here, because past here it can grant itself the role that reads data.
 */
class DokenOperatorsTest {

    private static final String VVK_ID = "vvk-under-test";

    private final KeyPair cohort;
    private final String vvkPublic;

    DokenOperatorsTest() throws Exception {
        cohort = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        vvkPublic = DokenTestKeys.encodePoint(cohort.getPublic());
    }

    /** Sign a doken the way the cohort would. */
    private String mint(String vuid, List<String> roles, long expiresAt, String audience) throws Exception {
        return mint(vuid, roles, expiresAt, audience, cohort);
    }

    private String mint(String vuid, List<String> roles, long expiresAt, String audience, KeyPair signer)
            throws Exception {
        DokenBuilder b = new DokenBuilder()
                .userKey("USERKEY")
                .vuid(vuid)
                .expiresAt(expiresAt)
                .audience(audience)
                .realmRoles(roles);

        Signature s = Signature.getInstance("Ed25519");
        s.initSign(signer.getPrivate());
        s.update(b.dataToSign().getBytes(StandardCharsets.UTF_8));
        return b.build(Base64.getEncoder().encodeToString(s.sign()));
    }

    private static long soon() {
        return Instant.now().getEpochSecond() + 3600;
    }

    /** An authenticator whose grant record says exactly {@code granted} for every vuid. */
    private DokenOperators withGrants(Set<String> granted) {
        return new DokenOperators(() -> vvkPublic, () -> VVK_ID, vuid -> granted);
    }

    // ------------------------------------------------------------------ the happy paths

    @Test
    void aGovernanceAdminGetsBothCapabilities() throws Exception {
        Optional<Operator> op = withGrants(Set.of(DokenOperators.ROLE_ADMIN))
                .authenticate(mint("vuid-1", List.of(DokenOperators.ROLE_ADMIN), soon(), VVK_ID));

        assertTrue(op.isPresent());
        assertEquals("vuid-1", op.get().name(), "the vuid is what an approval is attributed to");
        assertTrue(op.get().has(Role.VRK_ADMIN));
        assertTrue(op.get().has(Role.APPROVER), "an admin is also an approver");
    }

    @Test
    void anApproverGetsOnlyApproval() throws Exception {
        Optional<Operator> op = withGrants(Set.of(DokenOperators.ROLE_APPROVER))
                .authenticate(mint("vuid-2", List.of(DokenOperators.ROLE_APPROVER), soon(), VVK_ID));

        assertTrue(op.isPresent());
        assertTrue(op.get().has(Role.APPROVER));
        assertFalse(op.get().has(Role.VRK_ADMIN), "approving must not imply key control");
    }

    // ------------------------------------------------------------------ the refusals

    /** The whole point: a token this vendor key did not sign is not an operator. */
    @Test
    void aDokenSignedByAnotherKeyIsRefused() throws Exception {
        KeyPair impostor = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String forged = mint("vuid-1", List.of(DokenOperators.ROLE_ADMIN), soon(), VVK_ID, impostor);

        assertTrue(withGrants(Set.of(DokenOperators.ROLE_ADMIN)).authenticate(forged).isEmpty());
    }

    /** A valid doken minted for a different vendor must not carry over to this one. */
    @Test
    void aDokenForAnotherAudienceIsRefused() throws Exception {
        String other = mint("vuid-1", List.of(DokenOperators.ROLE_ADMIN), soon(), "some-other-vvk");
        assertTrue(withGrants(Set.of(DokenOperators.ROLE_ADMIN)).authenticate(other).isEmpty());
    }

    @Test
    void anExpiredDokenIsRefused() throws Exception {
        String stale = mint("vuid-1", List.of(DokenOperators.ROLE_ADMIN),
                Instant.now().getEpochSecond() - 1, VVK_ID);
        assertTrue(withGrants(Set.of(DokenOperators.ROLE_ADMIN)).authenticate(stale).isEmpty());
    }

    /**
     * The reason the live record is consulted at all. The doken still says admin and still verifies;
     * the grant behind it is gone, so it stops working now rather than when it expires.
     */
    @Test
    void aRevokedRoleStopsWorkingBeforeTheDokenExpires() throws Exception {
        String token = mint("vuid-1", List.of(DokenOperators.ROLE_ADMIN), soon(), VVK_ID);

        assertTrue(withGrants(Set.of(DokenOperators.ROLE_ADMIN)).authenticate(token).isPresent(),
                "sanity: it works while the grant stands");
        assertTrue(withGrants(Set.of()).authenticate(token).isEmpty(),
                "and stops the moment the grant is revoked");
    }

    /**
     * The inverse: a grant made after sign-in does not apply until the operator signs in again.
     * That direction is the safe one, so it is pinned deliberately rather than left to chance.
     */
    @Test
    void aGrantMadeAfterSignInDoesNotApplyToAnOldDoken() throws Exception {
        String token = mint("vuid-1", List.of(DokenOperators.ROLE_APPROVER), soon(), VVK_ID);

        Optional<Operator> op = withGrants(
                Set.of(DokenOperators.ROLE_APPROVER, DokenOperators.ROLE_ADMIN))
                .authenticate(token);

        assertTrue(op.isPresent());
        assertFalse(op.get().has(Role.VRK_ADMIN),
                "the cohort never attested admin in this token, so the local record must not add it");
    }

    @Test
    void aDokenWithNoGovernanceRoleIsNotAnOperator() throws Exception {
        String token = mint("vuid-1", List.of("vault-reader"), soon(), VVK_ID);
        assertTrue(withGrants(Set.of("vault-reader")).authenticate(token).isEmpty(),
                "reading vault data is not permission to govern");
    }

    @Test
    void aDokenWithNoRolesAtAllIsRefused() throws Exception {
        String token = mint("vuid-1", List.of(), soon(), VVK_ID);
        assertTrue(withGrants(Set.of()).authenticate(token).isEmpty());
    }

    @Test
    void garbageIsRefusedRatherThanThrowing() {
        DokenOperators auth = withGrants(Set.of(DokenOperators.ROLE_ADMIN));
        assertTrue(auth.authenticate(null).isEmpty());
        assertTrue(auth.authenticate("   ").isEmpty());
        assertTrue(auth.authenticate("not.a.token").isEmpty());
        assertTrue(auth.authenticate("a.b.c").isEmpty());
    }

    /** Before a vendor key exists nothing can have been signed by it. */
    @Test
    void nothingAuthenticatesBeforeThereIsAVendorKey() throws Exception {
        String token = mint("vuid-1", List.of(DokenOperators.ROLE_ADMIN), soon(), VVK_ID);
        DokenOperators noKey = new DokenOperators(() -> null, () -> VVK_ID,
                vuid -> Set.of(DokenOperators.ROLE_ADMIN));
        assertTrue(noKey.authenticate(token).isEmpty());
    }

    // ------------------------------------------------------------------ the mapping itself

    @Test
    void theRoleMappingIsCaseInsensitiveAndIgnoresUnknownRoles() {
        assertEquals(Set.of(Role.VRK_ADMIN, Role.APPROVER),
                DokenOperators.toServiceRoles(List.of("GOVERNANCE-ADMIN")));
        assertEquals(Set.of(), DokenOperators.toServiceRoles(List.of("editor", "administrator")),
                "a WordPress or Keycloak role name must not become governance here");
        assertEquals(Set.of(), DokenOperators.toServiceRoles(null));
    }
}

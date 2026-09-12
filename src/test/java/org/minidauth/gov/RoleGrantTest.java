package org.minidauth.gov;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.minidauth.auth.Operator;
import org.minidauth.auth.Operators;
import org.minidauth.auth.Role;
import org.minidauth.config.Config;
import org.minidauth.store.VendorKeyStore;
import org.minidauth.vrk.VrkLifecycle;

import java.nio.file.Path;
import java.util.EnumSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Role grants decide who can decrypt, so the rule that matters is that nothing reaches
 * {@link GovernanceService#rolesFor} except through a committed quorum.
 */
class RoleGrantTest {

    private static final Set<Role> ALL = EnumSet.allOf(Role.class);
    private static final String VUID = "vuid-alice";
    private static final String ROLE = "tide-vault-reader";

    @TempDir Path dir;

    private GovernanceStore store;
    private GovernanceService gov;
    private Operator alice;
    private Operator bob;
    private Operator carol;

    @BeforeEach
    void setUp() {
        store = new GovernanceStore( dir.resolve( "gov.json" ) );
        VendorKeyStore keys = new VendorKeyStore( dir.resolve( "vk.json" ), 3, 5 );
        gov = new GovernanceService( store, Operators.load( null, null, null ),
                new VrkLifecycle( keys, Config.fromEnv() ), 2, false,
                (vuid, roles) -> {
                    // Stands in for the cohort. Real signing needs a vendor key and a live network;
                    // what these tests exercise is the governance rules around the grant.
                    java.util.List<org.minidauth.gov.RoleGrant.SignedUnit> out = new java.util.ArrayList<>();
                    for (String r : roles) {
                        out.add(new org.minidauth.gov.RoleGrant.SignedUnit("unit:" + r, "sig:" + r));
                    }
                    out.add(new org.minidauth.gov.RoleGrant.SignedUnit("unit:map:" + vuid, "sig:map"));
                    return out;
                } );
        alice = new Operator( "alice", ALL );
        bob   = new Operator( "bob", ALL );
        carol = new Operator( "carol", ALL );
    }

    /** File, approve to quorum, commit. */
    private ChangeRequest grant( String vuid, String role, boolean revoke ) {
        ChangeRequest cr = gov.fileRoleChange( alice, vuid, role, revoke );
        gov.authorize( bob, cr.id );
        gov.authorize( carol, cr.id );
        return gov.commit( bob, cr.id );
    }

    @Test
    void aRoleIsHeldOnlyAfterTheQuorumCommits() {
        ChangeRequest cr = gov.fileRoleChange( alice, VUID, ROLE, false );
        assertTrue( gov.rolesFor( VUID ).isEmpty(), "filing alone must grant nothing" );

        gov.authorize( bob, cr.id );
        assertTrue( gov.rolesFor( VUID ).isEmpty(), "one approval is not the quorum" );

        gov.authorize( carol, cr.id );
        assertTrue( gov.rolesFor( VUID ).isEmpty(),
                "reaching the quorum must still not apply it, commit is a separate act" );

        gov.commit( bob, cr.id );
        assertEquals( Set.of( ROLE ), gov.rolesFor( VUID ) );
    }

    @Test
    void aSingleOperatorCannotGrantThemselvesARole() {
        ChangeRequest cr = gov.fileRoleChange( alice, VUID, ROLE, false );
        // The filer cannot supply an approval, so one person can never reach quorum alone.
        assertEquals( 409, assertThrows( GovernanceException.class,
                () -> gov.authorize( alice, cr.id ) ).status );
        assertEquals( 412, assertThrows( GovernanceException.class,
                () -> gov.commit( bob, cr.id ) ).status );
        assertTrue( gov.rolesFor( VUID ).isEmpty() );
    }

    @Test
    void revokingRemovesTheRole() {
        grant( VUID, ROLE, false );
        assertEquals( Set.of( ROLE ), gov.rolesFor( VUID ) );

        grant( VUID, ROLE, true );
        assertTrue( gov.rolesFor( VUID ).isEmpty(), "a revoked role must not survive" );
    }

    @Test
    void grantingARoleTwiceIsRefusedAtFiling() {
        grant( VUID, ROLE, false );
        assertEquals( 409, assertThrows( GovernanceException.class,
                () -> gov.fileRoleChange( alice, VUID, ROLE, false ) ).status );
    }

    @Test
    void revokingARoleNobodyHoldsIsRefusedAtFiling() {
        assertEquals( 409, assertThrows( GovernanceException.class,
                () -> gov.fileRoleChange( alice, VUID, ROLE, true ) ).status );
    }

    /**
     * Two revocations can both reach quorum before either commits. The second must not silently
     * succeed, or an audit trail would show two removals of one role.
     */
    @Test
    void aSecondCommitOfTheSameRevocationIsRefused() {
        grant( VUID, ROLE, false );

        ChangeRequest a = gov.fileRoleChange( alice, VUID, ROLE, true );
        ChangeRequest b = gov.fileRoleChange( alice, VUID, ROLE, true );
        for ( ChangeRequest cr : new ChangeRequest[] { a, b } ) {
            gov.authorize( bob, cr.id );
            gov.authorize( carol, cr.id );
        }

        gov.commit( bob, a.id );
        assertTrue( gov.rolesFor( VUID ).isEmpty() );

        GovernanceException e = assertThrows( GovernanceException.class, () -> gov.commit( bob, b.id ) );
        assertEquals( 409, e.status, "a stale change request is a conflict, not a server failure" );
        assertTrue( e.getMessage().contains( "no longer holds" ) );
    }

    /**
     * The mirror case: two grants of the same role both reaching quorum must not double-apply.
     */
    @Test
    void aSecondCommitOfTheSameGrantIsRefused() {
        ChangeRequest a = gov.fileRoleChange( alice, VUID, ROLE, false );
        // filed before the first commits, so the filing-time check cannot catch it
        ChangeRequest b = gov.fileRoleChange( alice, VUID, "other-role", false );
        b.payload.put( "role", ROLE ); // force the collision the filing check would have blocked
        for ( ChangeRequest cr : new ChangeRequest[] { a, b } ) {
            gov.authorize( bob, cr.id );
            gov.authorize( carol, cr.id );
        }

        gov.commit( bob, a.id );
        assertEquals( Set.of( ROLE ), gov.rolesFor( VUID ) );

        assertTrue( assertThrows( GovernanceException.class, () -> gov.commit( bob, b.id ) )
                .getMessage().contains( "already holds" ) );
        assertEquals( Set.of( ROLE ), gov.rolesFor( VUID ), "the role set must not have doubled" );
    }

    @Test
    void rolesAreHeldPerIdentity() {
        grant( "vuid-alice", ROLE, false );
        assertEquals( Set.of( ROLE ), gov.rolesFor( "vuid-alice" ) );
        assertTrue( gov.rolesFor( "vuid-bob" ).isEmpty(), "a grant must not leak to another identity" );
    }

    @Test
    void anIdentityCanHoldSeveralRoles() {
        grant( VUID, "tide-vault-reader", false );
        grant( VUID, "tide-vault-admin", false );
        assertEquals( Set.of( "tide-vault-reader", "tide-vault-admin" ), gov.rolesFor( VUID ) );

        grant( VUID, "tide-vault-reader", true );
        assertEquals( Set.of( "tide-vault-admin" ), gov.rolesFor( VUID ),
                "revoking one role must leave the others alone" );
    }

    @Test
    void theGrantRecordsWhichChangeRequestAuthorisedIt() {
        ChangeRequest committed = grant( VUID, ROLE, false );
        RoleGrant record = store.grant( VUID );
        assertEquals( committed.id, record.changeRequestId );
        assertNotNull( record.updatedAt );
        assertEquals( 2, committed.authorizers.size(), "the approvers are on the audit record" );
    }

    @Test
    void grantsSurviveAReload() {
        grant( VUID, ROLE, false );
        GovernanceStore reloaded = new GovernanceStore( dir.resolve( "gov.json" ) );
        assertEquals( Set.of( ROLE ), reloaded.grant( VUID ).roles );
    }

    @Test
    void anIdentityWithNoGrantHasNoRolesRatherThanAnError() {
        assertTrue( gov.rolesFor( "never-seen" ).isEmpty() );
        assertTrue( store.grant( "never-seen" ).roles.isEmpty() );
    }

    @Test
    void filingRequiresAVuidAndARole() {
        assertEquals( 400, assertThrows( GovernanceException.class,
                () -> gov.fileRoleChange( alice, "", ROLE, false ) ).status );
        assertEquals( 400, assertThrows( GovernanceException.class,
                () -> gov.fileRoleChange( alice, VUID, "  ", false ) ).status );
    }
    /**
     * The point of signing at commit time: the stored units are what a doken is built from, so a
     * grant recorded without them could not be proved to the network even if this file said so.
     */
    @Test
    void aCommittedGrantCarriesTheAttestedUnitsThatProveIt() {
        grant( "vuid-alice", "vault-reader", false );

        var stored = gov.signedRoleUnitsFor( "vuid-alice" );
        assertFalse( stored.isEmpty(), "a granted role must leave attested units behind" );
        assertTrue( stored.stream().anyMatch( u -> u[ 0 ].contains( "vault-reader" ) ),
                "the role's own unit must be among them" );
        assertTrue( stored.stream().anyMatch( u -> u[ 0 ].contains( "map:vuid-alice" ) ),
                "and the mapping that ties them to this identity" );
    }

    /**
     * Revoking the last role takes the attested units with it.
     *
     * The units only ever live here, so deleting the record is what makes the revocation real: there
     * is nothing left to replay, and a doken minted afterwards carries no role at all.
     */
    @Test
    void revokingRemovesTheUnitsThatVouchedForTheRole() {
        grant( "vuid-alice", "vault-reader", false );
        var before = gov.signedRoleUnitsFor( "vuid-alice" );
        assertTrue( before.stream().anyMatch( u -> u[ 0 ].contains( "vault-reader" ) ) );

        grant( "vuid-alice", "vault-reader", true );

        var after = gov.signedRoleUnitsFor( "vuid-alice" );
        assertTrue( after.isEmpty(),
                "nothing may remain that could be replayed to claim the revoked role" );
    }

    // ---- tideless subjects: application users with no Tide identity ----

    private ChangeRequest grantTideless( String subject, String role, boolean revoke ) {
        ChangeRequest cr = gov.fileRoleChange( alice, subject, role, revoke, true );
        gov.authorize( bob, cr.id );
        gov.authorize( carol, cr.id );
        return gov.commit( bob, cr.id );
    }

    @Test
    void aTidelessRoleStillNeedsTheQuorum() {
        ChangeRequest cr = gov.fileRoleChange( alice, "user_clerk_1", "vault-reader", false, true );
        assertTrue( gov.rolesFor( "user_clerk_1" ).isEmpty(), "filing alone must grant nothing" );
        gov.authorize( bob, cr.id );
        assertTrue( gov.rolesFor( "user_clerk_1" ).isEmpty(), "below threshold grants nothing" );
        gov.authorize( carol, cr.id );
        gov.commit( bob, cr.id );
        assertTrue( gov.rolesFor( "user_clerk_1" ).contains( "vault-reader" ) );
    }

    @Test
    void aTidelessGrantAttestsNothing() {
        grantTideless( "user_clerk_1", "vault-reader", false );
        assertTrue( gov.signedRoleUnitsFor( "user_clerk_1" ).isEmpty(),
                "a tideless subject has no identity to attest, so no units may exist to replay into a doken" );
        assertTrue( store.grant( "user_clerk_1" ).tideless );
    }

    @Test
    void theFilerStillCannotApproveATidelessGrant() {
        ChangeRequest cr = gov.fileRoleChange( alice, "user_clerk_1", "vault-reader", false, true );
        assertThrows( GovernanceException.class, () -> gov.authorize( alice, cr.id ),
                "four-eyes holds for tideless grants too" );
    }

    @Test
    void aSubjectCannotBeBothTideAndTideless() {
        grant( "user_clerk_1", "vault-reader", false );
        assertThrows( GovernanceException.class,
                () -> gov.fileRoleChange( alice, "user_clerk_1", "vault-writer", false, true ),
                "a subject enforced one way must not also be enforced the other" );
    }
}

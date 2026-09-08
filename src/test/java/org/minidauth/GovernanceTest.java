package org.minidauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.minidauth.auth.Operator;
import org.minidauth.auth.Operators;
import org.minidauth.auth.Role;
import org.minidauth.config.Config;
import org.minidauth.gov.ChangeRequest;
import org.minidauth.gov.GovernanceException;
import org.minidauth.gov.GovernanceService;
import org.minidauth.gov.GovernanceStore;
import org.minidauth.gov.Status;
import org.minidauth.store.VendorKeyStore;
import org.minidauth.vrk.VrkLifecycle;

import java.nio.file.Path;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class GovernanceTest {

    private static final Set<Role> ALL = EnumSet.allOf(Role.class);

    @TempDir Path dir;

    private GovernanceStore store;
    private GovernanceService gov;
    private Operator alice;
    private Operator bob;
    private Operator carol;

    @BeforeEach
    void setUp() {
        store = new GovernanceStore(dir.resolve("gov.json"));
        Operators operators = Operators.load(null, null, null);
        VendorKeyStore keyStore = new VendorKeyStore(dir.resolve("vendor-key.json"), 3, 5);
        VrkLifecycle vrk = new VrkLifecycle(keyStore, Config.fromEnv());
        // Fixed threshold of 2 keeps the tests about the rules, not the dynamic floor.
        gov = new GovernanceService(store, operators, vrk, 2, false,
                (vuid, roles) -> {
                    java.util.List<org.minidauth.gov.RoleGrant.SignedUnit> out = new java.util.ArrayList<>();
                    for (String r : roles) {
                        out.add(new org.minidauth.gov.RoleGrant.SignedUnit("unit:" + r, "sig:" + r));
                    }
                    out.add(new org.minidauth.gov.RoleGrant.SignedUnit("unit:map:" + vuid, "sig:map"));
                    return out;
                });

        alice = new Operator("alice", ALL);
        bob = new Operator("bob", ALL);
        carol = new Operator("carol", ALL);
    }

    private ChangeRequest fileContract(Operator by, String source) {
        return gov.fileContractRegistration(by, "test-contract", source, "forseti");
    }

    @Test
    void contractIdIsUppercaseSha512OfTheExactSource() {
        String id = GovernanceService.contractId("contract Foo {}");
        assertEquals(128, id.length());
        assertTrue(id.matches("^[0-9A-F]{128}$"), "must be uppercase hex: " + id);
        // Any edit at all is a different contract.
        assertNotEquals(id, GovernanceService.contractId("contract Foo {} // comment"));
    }

    @Test
    void filingDoesNotCountAsAnApproval() {
        ChangeRequest cr = fileContract(alice, "contract A {}");
        assertEquals(Status.PENDING, cr.status);
        assertEquals(0, cr.authorizationCount, "the filer must not be auto-credited with a vote");
        assertFalse(cr.readyToCommit);
    }

    @Test
    void filerCannotAuthorizeTheirOwnRequest() {
        ChangeRequest cr = fileContract(alice, "contract A {}");
        GovernanceException e = assertThrows(GovernanceException.class, () -> gov.authorize(alice, cr.id));
        assertEquals(409, e.status);
        assertTrue(e.getMessage().contains("Four-eyes"));
    }

    @Test
    void sameApproverCannotVoteTwice() {
        ChangeRequest cr = fileContract(alice, "contract A {}");
        gov.authorize(bob, cr.id);
        GovernanceException e = assertThrows(GovernanceException.class, () -> gov.authorize(bob, cr.id));
        assertEquals(409, e.status);
        assertEquals(1, store.changeRequest(cr.id).orElseThrow().authorizationCount);
    }

    @Test
    void authorizingToThresholdDoesNotCommit() {
        ChangeRequest cr = fileContract(alice, "contract A {}");
        gov.authorize(bob, cr.id);
        ChangeRequest atQuorum = gov.authorize(carol, cr.id);

        assertEquals(2, atQuorum.authorizationCount);
        assertTrue(atQuorum.readyToCommit, "should be ready...");
        assertEquals(Status.PENDING, atQuorum.status, "...but authorize must never commit");
        assertTrue(store.contracts().isEmpty(), "nothing may be applied before an explicit commit");
    }

    @Test
    void commitUnderThresholdIsRefused() {
        ChangeRequest cr = fileContract(alice, "contract A {}");
        gov.authorize(bob, cr.id);
        GovernanceException e = assertThrows(GovernanceException.class, () -> gov.commit(bob, cr.id));
        assertEquals(412, e.status);
        assertTrue(e.getMessage().contains("1 of 2"));
    }

    @Test
    void commitAtThresholdAppliesTheContract() {
        String source = "contract A {}";
        ChangeRequest cr = fileContract(alice, source);
        gov.authorize(bob, cr.id);
        gov.authorize(carol, cr.id);
        ChangeRequest committed = gov.commit(bob, cr.id);

        assertEquals(Status.APPROVED, committed.status);
        assertEquals(GovernanceService.contractId(source), committed.resultId);
        assertEquals(1, store.contracts().size());
        assertEquals(source, store.contract(committed.resultId).orElseThrow().source);
    }

    @Test
    void aDeniedRequestCannotBeAuthorizedOrCommitted() {
        ChangeRequest cr = fileContract(alice, "contract A {}");
        gov.deny(bob, cr.id);
        assertEquals(409, assertThrows(GovernanceException.class, () -> gov.authorize(carol, cr.id)).status);
        assertEquals(409, assertThrows(GovernanceException.class, () -> gov.commit(carol, cr.id)).status);
    }

    @Test
    void anEmptyRosterStillClampsTheThresholdToOne() {
        GovernanceService dynamic = govOver(Operators.load(null, null, null));
        // The floor is max(1, floor(0.7 x approvers)); it never reaches 0, so the gate cannot be
        // disabled by declaring no approvers.
        assertEquals(1, dynamic.currentThreshold());
    }

    @Test
    void theThresholdFollowsTheConfiguredApproverCount() throws Exception {
        assertEquals(7, govOver(roster(10)).currentThreshold(), "floor(0.7 x 10)");
        assertEquals(2, govOver(roster(3)).currentThreshold(), "floor(0.7 x 3)");
    }

    @Test
    void thresholdIsSnapshottedAtFilingSoARosterChangeCannotLowerTheBar() throws Exception {
        GovernanceService small = govOver(roster(3));
        ChangeRequest cr = small.fileContractRegistration(alice, "c", "contract A {}", "forseti");
        assertEquals(2, cr.threshold);

        // A redeploy with a bigger roster raises the bar for NEW requests only; this one keeps its.
        assertEquals(7, govOver(roster(10)).currentThreshold());
        assertEquals(2, cr.threshold);
    }

    /** A roster file with {@code n} approvers, the way a deployment would declare one. */
    private Operators roster(int n) throws Exception {
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < n; i++) {
            if (i > 0) json.append(',');
            json.append("{\"name\":\"approver-").append(i)
                .append("\",\"token\":\"tok-").append(i)
                .append("\",\"roles\":[\"approver\"]}");
        }
        java.nio.file.Path f = dir.resolve("operators-" + n + ".json");
        java.nio.file.Files.writeString(f, json.append(']').toString());
        return Operators.load(f, null, null);
    }

    private GovernanceService govOver(Operators operators) {
        VendorKeyStore keyStore = new VendorKeyStore(
                dir.resolve("vk-" + System.nanoTime() + ".json"), 3, 5);
        return new GovernanceService(new GovernanceStore(dir.resolve("gov-" + System.nanoTime() + ".json")),
                operators, new VrkLifecycle(keyStore, Config.fromEnv()), null, false,
                (vuid, roles) -> {
                    java.util.List<org.minidauth.gov.RoleGrant.SignedUnit> out = new java.util.ArrayList<>();
                    for (String r : roles) {
                        out.add(new org.minidauth.gov.RoleGrant.SignedUnit("unit:" + r, "sig:" + r));
                    }
                    out.add(new org.minidauth.gov.RoleGrant.SignedUnit("unit:map:" + vuid, "sig:map"));
                    return out;
                });
    }

    @Test
    void aPolicyWithALowercaseContractIdIsRefusedAtFiling() {
        String lower = GovernanceService.contractId("contract A {}").toLowerCase();
        Map<String, Object> spec = policySpec(lower);
        GovernanceException e = assertThrows(GovernanceException.class,
                () -> gov.filePolicyDeployment(alice, spec));
        assertEquals(400, e.status);
        assertTrue(e.getMessage().contains("UPPERCASE"));
    }

    @Test
    void aWellFormedPolicySpecFiles() {
        ChangeRequest cr = gov.filePolicyDeployment(alice, policySpec(GovernanceService.contractId("contract A {}")));
        assertEquals(Status.PENDING, cr.status);
        assertEquals(0, cr.authorizationCount);
    }

    @Test
    void aPolicyParameterOfAnUnsupportedTypeIsRefusedAtFilingNotAtCommit() {
        Map<String, Object> spec = policySpec(GovernanceService.contractId("contract A {}"));
        @SuppressWarnings("unchecked")
        Map<String, Object> params = (Map<String, Object>) spec.get("params");
        params.put("ratio", 0.7d); // PolicyParameters has no wire type for a double
        GovernanceException e = assertThrows(GovernanceException.class,
                () -> gov.filePolicyDeployment(alice, spec));
        assertEquals(400, e.status);
        assertTrue(e.getMessage().contains("ratio"));
    }

    @Test
    void anAlreadyExpiredPolicyIsRefused() {
        Map<String, Object> spec = policySpec(GovernanceService.contractId("contract A {}"));
        spec.put("expiry", 1_000L);
        GovernanceException e = assertThrows(GovernanceException.class,
                () -> gov.filePolicyDeployment(alice, spec));
        assertEquals(400, e.status);
    }

    @Test
    void registeringTheSameContractSourceTwiceIsRefused() {
        String source = "contract A {}";
        ChangeRequest cr = fileContract(alice, source);
        gov.authorize(bob, cr.id);
        gov.authorize(carol, cr.id);
        gov.commit(bob, cr.id);

        assertEquals(409, assertThrows(GovernanceException.class, () -> fileContract(alice, source)).status);
    }

    private static Map<String, Object> policySpec(String contractId) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("threshold", 2);
        params.put("role", "governance-admin");
        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("name", "admin-threshold");
        spec.put("contractId", contractId);
        spec.put("modelIds", List.of("any"));
        spec.put("keyId", "11111111-2222-3333-4444-555555555555");
        spec.put("params", params);
        return spec;
    }
}

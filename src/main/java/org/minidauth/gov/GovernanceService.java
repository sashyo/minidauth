package org.minidauth.gov;

import org.midgard.models.Policy.ApprovalType;
import org.midgard.models.Policy.ExecutionType;
import org.midgard.models.Policy.Policy;
import org.midgard.models.Policy.PolicyParameters;
import org.midgard.Serialization.Tools;
import org.midgard.models.RequestExtensions.PolicySignRequest;
import org.midgard.models.SignatureResponse;
import org.minidauth.Log;
import org.minidauth.auth.Operator;
import org.minidauth.auth.Operators;
import org.minidauth.auth.Role;
import org.minidauth.tide.Doken;
import org.minidauth.vrk.VrkLifecycle;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Files, approves and commits governed changes to contracts and policies.
 *
 * <h3>The three verbs are distinct, and deliberately so</h3>
 * <ul>
 *   <li><b>file</b> creates a PENDING change request. It does <b>not</b> auto-approve the filer.</li>
 *   <li><b>authorize</b> records one approval and <b>never</b> commits, even at quorum.</li>
 *   <li><b>commit</b> applies the change, and refuses (412) below threshold.</li>
 * </ul>
 *
 * <p>A filer who is also credited with an approval holds two of the votes the quorum exists to
 * split, so filing here does not vote and the filer cannot authorize their own request.
 */
public final class GovernanceService {
    private static final Log log = Log.of(GovernanceService.class);

    /** The ORKs compare contract ids as a case-sensitive string, and theirs are uppercase. */
    /**
     * A compiled Forseti contract, addressed by the SHA-512 of its source. The ORKs compare it
     * case-sensitively, so lowercase is rejected rather than folded.
     */
    private static final Pattern CONTRACT_ID = Pattern.compile("^[0-9A-F]{128}$");

    /**
     * A contract built into the ORK, addressed as {@code Name:Version}, for example
     * {@code GenericRealmAccessThresholdRole:1}, the threshold-of-role contract an admin policy
     * normally uses. These have no source to hash because the vendor never supplies one.
     */
    private static final Pattern BUILTIN_CONTRACT_ID = Pattern.compile("^[A-Za-z][A-Za-z0-9]*:[0-9]+$");

    /** Policy signs need ORK round-trip headroom; the PolicySignRequest default of 30s is tight. */
    private static final int POLICY_SIGN_EXPIRY_SECONDS = 180;

    private static final String VRK_AUTH_FLOW = "VRK:1";

    /**
     * The authorization flow every policy after the first one uses.
     *
     * <p>The VRK's authorizer pack signs exactly one {@code Policy:1} and is then revoked by the
     * ORK, deliberately, to force the newly signed policy to govern from then on. So the first
     * policy on a key must be an admin policy, one whose {@code modelIds} include {@code Policy:1}
     * or the {@code any} wildcard, and every later policy is authorized by that one instead.
     */
    private static final String POLICY_AUTH_FLOW = "Policy:1";

    /** The wildcard an admin policy uses to authorize any model. */
    private static final String ANY_MODEL = "any";

    /** The model that signs attestation units, which every token depends on. */
    private static final String UNIT_MODEL = "AttestationUnit:1";

    /**
     * How long a carrier awaiting admin approvals stays valid.
     *
     * <p>Far longer than a direct sign, because a quorum assembles at human speed: the carrier is
     * built, persisted, and only signed once enough admins have approved it, which may be hours.
     * The short window that suits an immediate sign expires the carrier before anyone can approve.
     */
    private static final long APPROVAL_CARRIER_EXPIRY_SECONDS = 7L * 24 * 60 * 60;

    /** The class the ORK instantiates from an uploaded contract source. */
    private static final String DEFAULT_ENTRY_TYPE = "Contract";

    /** The 32-byte public point inside a TideMemory authorizer pack. */
    private static final Pattern PACK_POINT = Pattern.compile("23000000200000([0-9A-Fa-f]{64})");

    private final GovernanceStore store;
    private final Operators operators;
    private final VrkLifecycle vrk;
    private final Integer thresholdOverride;
    /** When true, a bearer token alone cannot approve, the enclave lane is the only lane. */
    private final boolean requireTideApproval;

    /**
     * Turns a role set into cohort-signed attestation units.
     *
     * <p>Injectable so the governance rules can be tested without an ORK network. It is not a way to
     * opt out: production wires the real one, and a commit whose units cannot be signed is refused,
     * so there is no path that records a grant this service could not prove.
     */
    @FunctionalInterface
    public interface RoleAttestor {
        java.util.List<RoleGrant.SignedUnit> attest(String vuid, java.util.Collection<String> roles)
                throws Exception;
    }

    private final RoleAttestor roleAttestor;

    public GovernanceService(GovernanceStore store, Operators operators, VrkLifecycle vrk,
                             Integer thresholdOverride, boolean requireTideApproval) {
        this(store, operators, vrk, thresholdOverride, requireTideApproval, null);
    }

    public GovernanceService(GovernanceStore store, Operators operators, VrkLifecycle vrk,
                             Integer thresholdOverride, boolean requireTideApproval,
                             RoleAttestor roleAttestor) {
        this.store = store;
        this.operators = operators;
        this.vrk = vrk;
        this.thresholdOverride = thresholdOverride;
        this.requireTideApproval = requireTideApproval;
        this.roleAttestor = roleAttestor == null ? this::signRoleUnits : roleAttestor;
    }

    public boolean requiresTideApproval() {
        return requireTideApproval;
    }

    /**
     * How many approvals a new request needs.
     *
     * <p>The dynamic floor mirrors TideCloak's MultiAdmin rule: {@code max(1, floor(0.7 × approvers))}.
     * Clamped at 1, the gate cannot be disabled by emptying the approver roster.
     */
    public int currentThreshold() {
        if (thresholdOverride != null) return Math.max(1, thresholdOverride);
        return Math.max(1, (int) Math.floor(0.7 * operators.approverCount()));
    }

    // ==================================================================== file

    public synchronized ChangeRequest fileContractRegistration(Operator by, String name, String source,
                                                               String type) {
        by.require(Role.APPROVER);
        if (name == null || name.isBlank()) throw GovernanceException.badRequest("name is required");
        if (source == null || source.isBlank()) throw GovernanceException.badRequest("source is required");
        String contractType = (type == null || type.isBlank()) ? "forseti" : type.trim();
        if (!"forseti".equals(contractType)) {
            throw GovernanceException.badRequest("Unsupported contract type '" + contractType + "'; only 'forseti' exists");
        }

        String contractId = contractId(source);
        if (store.contract(contractId).isPresent()) {
            throw GovernanceException.conflict("That exact contract source is already registered as " + contractId);
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("name", name);
        payload.put("type", contractType);
        payload.put("source", source);
        payload.put("contractId", contractId);

        return file(by, Kind.DEPLOY_CONTRACT, payload);
    }

    /**
     * @param spec the policy: {@code contractId}, {@code modelIds}, {@code keyId}, {@code approvalType},
     *             {@code executionType}, {@code params}, optional {@code expiry}, optional
     *             {@code uploadContract} (ship the contract source alongside the sign).
     */
    public synchronized ChangeRequest filePolicyDeployment(Operator by, Map<String, Object> spec) {
        by.require(Role.APPROVER);
        // Validate now, at filing, so a request cannot collect approvals and only then turn out to
        // be unbuildable.
        buildPolicy(spec);
        return file(by, Kind.DEPLOY_POLICY, new LinkedHashMap<>(spec));
    }

    /**
     * File a role grant or revocation.
     *
     * <p>Nothing changes until this commits. That is the point: a role is what lets a doken decrypt,
     * so putting the grant behind the same quorum as a policy deployment means no single operator,
     * and no compromise of the application that files it, can hand out decryption rights.
     *
     * @param vuid   the Tide identity, as proven by an enclave sign-in
     * @param role   realm role name, e.g. {@code tide-vault-reader}
     * @param revoke true to take the role away instead of granting it
     */
    public synchronized ChangeRequest fileRoleChange(Operator by, String vuid, String role, boolean revoke) {
        by.require(Role.APPROVER);
        if (vuid == null || vuid.isBlank()) throw GovernanceException.badRequest("vuid is required");
        if (role == null || role.isBlank()) throw GovernanceException.badRequest("role is required");

        String cleanRole = role.trim();
        boolean held = store.grant(vuid.trim()).roles.contains(cleanRole);
        if (revoke && !held) {
            throw GovernanceException.conflict(vuid + " does not hold " + cleanRole);
        }
        if (!revoke && held) {
            throw GovernanceException.conflict(vuid + " already holds " + cleanRole);
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("vuid", vuid.trim());
        payload.put("role", cleanRole);
        return file(by, revoke ? Kind.REVOKE_ROLE : Kind.GRANT_ROLE, payload);
    }

    private ChangeRequest file(Operator by, Kind kind, Map<String, Object> payload) {
        ChangeRequest cr = new ChangeRequest();
        cr.id = UUID.randomUUID().toString();
        cr.kind = kind;
        cr.status = Status.PENDING;
        cr.requestedBy = by.name();
        cr.requestedBySubject = by.name();
        cr.createdAt = Instant.now().toString();
        cr.payload = payload;
        // Snapshot the threshold, so adding approvers after filing cannot lower the bar this
        // request already has to clear.
        cr.threshold = currentThreshold();
        cr.recount();
        store.putChangeRequest(cr);
        store.persist();
        log.info("Filed %s change request %s by %s (threshold %d)", kind, cr.id, by.name(), cr.threshold);
        return cr;
    }

    // =============================================================== authorize

    /**
     * Record one approval on the operator-token lane. Never commits, even once the threshold is met.
     *
     * <p>This lane trusts a bearer token, so it is refused entirely when the deployment requires
     * enclave-backed approvals, see {@link #approveWithEnclave}.
     */
    public synchronized ChangeRequest authorize(Operator by, String id) {
        by.require(Role.APPROVER);
        ChangeRequest cr = require(id);
        if (requireTideApproval) {
            throw GovernanceException.conflict(
                    "This deployment requires enclave-backed approval. Use POST /iga/change-requests/"
                            + id + "/approve with a doken; a bearer token alone cannot approve.");
        }
        return record(cr, ChangeRequest.Authorization.byOperator(by.name(), Instant.now().toString()));
    }

    /**
     * Record one approval proven by a Tide enclave doken.
     *
     * <p>The approval is credited to the <b>vuid inside the doken</b>, never to the caller. That
     * distinction is the whole point: TideCloak's own IGA surface credits whoever authenticated the
     * HTTP request, so routing approvals through one app-server identity records every human's
     * approval under that identity and the quorum quietly collapses to one. Here, the same service
     * token can carry approvals from many people and they still count separately, because the
     * signature, not the transport, says who approved.
     */
    public synchronized ChangeRequest approveWithEnclave(Operator by, String id, String dokenToken) {
        by.require(Role.APPROVER);
        ChangeRequest cr = require(id);

        String gVVK = vrk.store().get(org.minidauth.store.VendorKeyStore.VVK_PUBLIC);
        if (gVVK == null) {
            throw GovernanceException.conflict("No VVK available; the vendor key has not been finalized");
        }

        Doken doken;
        try {
            doken = Doken.verify(dokenToken, gVVK);
        } catch (IllegalArgumentException e) {
            throw GovernanceException.forbidden("Doken rejected: " + e.getMessage());
        }
        if (doken.hasExpired()) {
            throw GovernanceException.forbidden("This doken expired at " + java.time.Instant.ofEpochSecond(doken.expiresAt)
                    + "; approve again from the enclave");
        }

        return record(cr, ChangeRequest.Authorization.byEnclave(doken.vuid, by.name(), Instant.now().toString()));
    }

    /** The rules every approval goes through, whichever lane produced it. */
    private ChangeRequest record(ChangeRequest cr, ChangeRequest.Authorization auth) {
        if (cr.status != Status.PENDING) {
            throw GovernanceException.conflict("Change request " + cr.id + " is " + cr.status + ", not PENDING");
        }
        if (auth.subject.equalsIgnoreCase(cr.requestedBySubject)) {
            throw GovernanceException.conflict(
                    "Four-eyes: " + auth.subject + " filed this change request and cannot also authorize it");
        }
        if (cr.hasAuthorized(auth.subject)) {
            throw GovernanceException.conflict(auth.subject + " has already authorized " + cr.id);
        }

        cr.authorizers.add(auth);
        cr.recount();
        store.putChangeRequest(cr);
        store.persist();
        log.info("Approved %s by %s via %s (%d/%d)", cr.id, auth.subject, auth.method,
                cr.authorizationCount, cr.threshold);
        return cr;
    }

    public synchronized ChangeRequest deny(Operator by, String id) {
        by.require(Role.APPROVER);
        ChangeRequest cr = require(id);
        if (cr.status != Status.PENDING) {
            throw GovernanceException.conflict("Change request " + id + " is " + cr.status + ", not PENDING");
        }
        cr.status = Status.DENIED;
        cr.resolvedBy = by.name();
        cr.resolvedAt = Instant.now().toString();
        cr.recount();
        store.putChangeRequest(cr);
        store.persist();
        log.info("Denied %s by %s", id, by.name());
        return cr;
    }

    // ================================================================== commit

    /** Apply the change. Refuses below threshold; the approvals must already be in. */
    public synchronized ChangeRequest commit(Operator by, String id) {
        by.require(Role.APPROVER);
        ChangeRequest cr = require(id);

        if (cr.status != Status.PENDING) {
            throw GovernanceException.conflict("Change request " + id + " is " + cr.status + ", not PENDING");
        }
        if (cr.authorizationCount < cr.threshold) {
            throw GovernanceException.preconditionFailed("Change request " + id + " has "
                    + cr.authorizationCount + " of " + cr.threshold + " required approvals");
        }

        try {
            String resultId = switch (cr.kind) {
                case DEPLOY_CONTRACT -> commitContract(cr);
                case DEPLOY_POLICY -> commitPolicy(cr);
                case GRANT_ROLE -> commitRoleChange(cr, false);
                case REVOKE_ROLE -> commitRoleChange(cr, true);
            };
            cr.status = Status.APPROVED;
            cr.resultId = resultId;
            cr.resolvedBy = by.name();
            cr.resolvedAt = Instant.now().toString();
            cr.lastError = null;
            cr.recount();
            store.putChangeRequest(cr);
            store.persist();
            log.info("Committed %s -> %s", id, resultId);
            return cr;
        } catch (GovernanceException e) {
            throw e;
        } catch (Exception e) {
            // Leave the request PENDING with its approvals intact, so a transient ORK failure
            // costs a retry rather than a whole new approval round.
            cr.lastError = e.getMessage();
            store.putChangeRequest(cr);
            store.persist();
            log.error(e, "Commit of %s failed", id);
            throw new GovernanceException(502, "Commit failed: " + e.getMessage());
        }
    }

    private String commitContract(ChangeRequest cr) {
        String source = (String) cr.payload.get("source");
        String contractId = contractId(source);

        // Recompute rather than trust the stored id: the source is what the ORKs hash.
        if (!contractId.equals(cr.payload.get("contractId"))) {
            throw GovernanceException.conflict("Contract source no longer hashes to the id filed with this request");
        }

        Contract c = new Contract();
        c.contractId = contractId;
        c.name = (String) cr.payload.get("name");
        c.type = (String) cr.payload.getOrDefault("type", "forseti");
        c.source = source;
        c.registeredBy = cr.requestedBy;
        c.registeredAt = Instant.now().toString();
        c.changeRequestId = cr.id;
        store.putContract(c);
        return contractId;
    }

    /**
     * Apply an approved role change.
     *
     * <p>Re-checks the current state rather than trusting what was true at filing: two requests for
     * the same role can both reach quorum, and the second must not silently double-apply or
     * resurrect a role the first one removed.
     */
    /**
     * The policy that may sign role-conferring units, if one is deployed.
     *
     * <p>Recognised by needing approvals. Two policies can cover {@code AttestationUnit:1} at once
     * and that is the point: the IMPLICIT one signs the units every sign-in needs and refuses the
     * two that confer a role, this one signs only those two and only with approvals. Neither can do
     * the other's job, so which one a request names is not a choice this service can abuse.
     */
    public synchronized java.util.Optional<DeployedPolicy> rolePolicy() {
        return store.policies().stream()
                .filter(p -> p.modelIds != null && p.modelIds.contains(UNIT_MODEL))
                .filter(p -> "EXPLICIT".equals(p.approvalType))
                .findFirst();
    }

    /** A deployed policy that can authorise attestation unit signing. */
    public synchronized java.util.Optional<DeployedPolicy> unitPolicy() {
        return store.policies().stream()
                .filter(p -> p.modelIds != null
                        && (p.modelIds.contains(UNIT_MODEL) || p.modelIds.contains(ANY_MODEL)))
                // Never the role policy: it demands approvals, and these units are signed on every
                // sign-in, so naming it here would mean no token could be minted without a quorum.
                .filter(p -> !"EXPLICIT".equals(p.approvalType))
                .findFirst();
    }

    /**
     * Ask the cohort to sign attestation units.
     *
     * <p>Two routes, and which one is available decides whether this key still works. The VRK's
     * authorizer pack can sign these, but the network revokes that pack the moment it signs a
     * policy, and every token needs attestation units. So once any policy is deployed, this has to
     * go through a policy instead, and {@code AttestationUnit:1} accepts the Policy flow precisely
     * so that it can.
     *
     * <p>The policy route is also the better one. The pack allows any unit at all; a policy runs the
     * contract's data validation first, so it can refuse to sign units it does not recognise, which
     * is how signing a role grant can be made to need approval while signing the config units a
     * token needs does not.
     */
    public synchronized String[] signAttestationUnits(byte[][] units) throws Exception {
        org.midgard.models.RequestExtensions.AttestationUnitSignRequest req;

        java.util.Optional<DeployedPolicy> policy = unitPolicy();
        if (policy.isPresent()) {
            req = new org.midgard.models.RequestExtensions.AttestationUnitSignRequest(POLICY_AUTH_FLOW);
            req.SetUnits(units);
            req.SetPolicy(Base64.getDecoder().decode(policy.get().policyBytes));
        } else {
            // Bootstrap only, and only until the first policy is deployed.
            req = new org.midgard.models.RequestExtensions.AttestationUnitSignRequest(VRK_AUTH_FLOW);
            req.SetUnits(units);
            vrk.authorizeRequestWithFirstAdmin(req);
        }

        var settings = vrk.store().midgardSettings();
        settings.TraceParent = org.minidauth.vrk.Trace.current();
        SignatureResponse response = org.midgard.Midgard.SignModel(settings, req);

        if (response.Signatures == null || response.Signatures.length < units.length) {
            throw new IllegalStateException("The Tide network returned "
                    + (response.Signatures == null ? 0 : response.Signatures.length)
                    + " signatures for " + units.length + " attestation units");
        }
        return response.Signatures;
    }

    /**
     * Sign the attestation units that make a role grant real.
     *
     * <p>Done when the change commits, not when a token is minted, and that timing is the point. A
     * unit rebuilt from local state at mint time would verify perfectly no matter who edited that
     * state; a unit signed once by the cohort and replayed cannot be forged by whoever later owns
     * the disk. It moves this file from being the authority to being a cache of what was agreed.
     */
    /**
     * The stored, cohort-signed role units for an identity, as [unit, signature] base64 pairs.
     */
    public synchronized java.util.List<String[]> signedRoleUnitsFor(String vuid) {
        RoleGrant grant = store.grant(vuid);
        java.util.List<String[]> out = new java.util.ArrayList<>();
        if (grant.signedUnits != null) {
            for (RoleGrant.SignedUnit u : grant.signedUnits) {
                out.add(new String[]{u.unit, u.signature});
            }
        }
        return out;
    }

    private java.util.List<RoleGrant.SignedUnit> signRoleUnits(String vuid, java.util.Collection<String> roles)
            throws Exception {
        String vvkId = vrk.store().get(org.minidauth.store.VendorKeyStore.VENDOR_ID);
        if (vvkId == null) {
            throw new IllegalStateException("No vendor key, so a grant cannot be attested");
        }

        java.util.List<byte[]> units = new java.util.ArrayList<>();
        java.util.List<String> roleIds = new java.util.ArrayList<>();
        for (String role : roles) {
            units.add(org.minidauth.tide.AttestationUnits.roleDefinition(role, role, false, vvkId));
            roleIds.add(role);
        }
        // The mapping unit is what ties the roles to this identity. On a full revocation the store
        // drops the record entirely, so these units go with it and there is nothing left to replay.
        units.add(org.minidauth.tide.AttestationUnits.userRoleMappingSet(vuid, roleIds));

        byte[][] array = units.toArray(new byte[0][]);

        String[] signatures = signAttestationUnits(array);

        java.util.List<RoleGrant.SignedUnit> out = new java.util.ArrayList<>();
        for (int i = 0; i < array.length; i++) {
            out.add(new RoleGrant.SignedUnit(
                    Base64.getEncoder().encodeToString(array[i]), signatures[i]));
        }
        return out;
    }

    /** The role set a change request would leave the identity holding. */
    private java.util.List<String> resultingRoles(ChangeRequest cr, boolean revoke) {
        String vuid = (String) cr.payload.get("vuid");
        String role = (String) cr.payload.get("role");
        java.util.LinkedHashSet<String> roles = new java.util.LinkedHashSet<>(store.grant(vuid).roles);
        if (revoke) roles.remove(role); else roles.add(role);
        return new java.util.ArrayList<>(roles);
    }

    /** The attestation units that make a role set real for an identity. */
    private java.util.List<byte[]> roleUnitsFor(String vuid, java.util.Collection<String> roles) {
        String vvkId = vrk.store().get(org.minidauth.store.VendorKeyStore.VENDOR_ID);
        if (vvkId == null) {
            throw new IllegalStateException("No vendor key, so a grant cannot be attested");
        }
        java.util.List<byte[]> units = new java.util.ArrayList<>();
        java.util.List<String> roleIds = new java.util.ArrayList<>();
        for (String role : roles) {
            units.add(org.minidauth.tide.AttestationUnits.roleDefinition(role, role, false, vvkId));
            roleIds.add(role);
        }
        units.add(org.minidauth.tide.AttestationUnits.userRoleMappingSet(vuid, roleIds));
        return units;
    }

    /**
     * Build the carrier a quorum of administrators approves to grant a role.
     *
     * <p>The same two phase shape as a policy deployment, for the same reason: this service holds
     * the vendor key, so if it could sign these alone it could grant itself anything. The units are
     * stamped with the VRK so the enclave will accept the blob, then each administrator's enclave
     * appends their own doken, and the accumulated result is what the cohort finally signs.
     */
    private String buildRoleUnitCarrier(ChangeRequest cr, boolean revoke, DeployedPolicy authorizer)
            throws Exception {
        String vuid = (String) cr.payload.get("vuid");
        java.util.List<byte[]> units = roleUnitsFor(vuid, resultingRoles(cr, revoke));

        var req = new org.midgard.models.RequestExtensions.AttestationUnitSignRequest(POLICY_AUTH_FLOW);
        req.SetUnits(units.toArray(new byte[0][]));
        req.SetPolicy(Base64.getDecoder().decode(authorizer.policyBytes));
        req.SetCustomExpiry((System.currentTimeMillis() / 1000) + APPROVAL_CARRIER_EXPIRY_SECONDS);

        // Materialise the draft before stamping it: the stamp signs a hash of the draft, and
        // encoding before it exists leaves the approvers signing nothing.
        req.GetDraft();
        vrk.initializeRequestWithVrk(req);

        cr.carrierUnits = new java.util.ArrayList<>();
        for (byte[] unit : units) {
            cr.carrierUnits.add(Base64.getEncoder().encodeToString(unit));
        }
        return Base64.getEncoder().encodeToString(req.Encode());
    }

    /**
     * Sign role units under the policy that requires administrator approvals.
     *
     * <p>The first commit attempt only builds the carrier and stops. Refusing to sign until the
     * threshold is met is the whole mechanism.
     */
    private java.util.List<RoleGrant.SignedUnit> attestViaAdminQuorum(ChangeRequest cr,
                                                                     DeployedPolicy authorizer)
            throws Exception {
        if (cr.approvalCarrier == null || cr.approvalCarrier.isBlank()) {
            throw GovernanceException.conflict(
                    "This role change must be approved by " + requiredApprovals(authorizer)
                    + " Tide administrator(s) before it can be committed. Approve it in the "
                    + "governance console, then commit again.");
        }
        int required = requiredApprovals(authorizer);
        if (cr.carrierApprovals < required) {
            throw GovernanceException.conflict("Waiting on Tide administrator approvals: "
                    + cr.carrierApprovals + " of " + required + " collected.");
        }
        if (cr.carrierUnits == null || cr.carrierUnits.isEmpty()) {
            throw new IllegalStateException("The approved carrier has no units recorded against it");
        }

        // Submitted exactly as the approvers left it: its bytes are what their dokens signed over.
        var req = org.midgard.models.ModelRequest.FromBytes(
                Base64.getDecoder().decode(cr.approvalCarrier));
        var settings = vrk.store().midgardSettings();
        settings.TraceParent = org.minidauth.vrk.Trace.current();
        SignatureResponse resp = org.midgard.Midgard.SignModel(settings, req);

        if (resp.Signatures == null || resp.Signatures.length < cr.carrierUnits.size()) {
            throw new IllegalStateException("The Tide network returned "
                    + (resp.Signatures == null ? 0 : resp.Signatures.length)
                    + " signatures for " + cr.carrierUnits.size() + " attestation units");
        }

        java.util.List<RoleGrant.SignedUnit> out = new java.util.ArrayList<>();
        for (int i = 0; i < cr.carrierUnits.size(); i++) {
            out.add(new RoleGrant.SignedUnit(cr.carrierUnits.get(i), resp.Signatures[i]));
        }
        return out;
    }

    private String commitRoleChange(ChangeRequest cr, boolean revoke) {
        String vuid = (String) cr.payload.get("vuid");
        String role = (String) cr.payload.get("role");

        RoleGrant grant = store.grant(vuid);
        boolean held = grant.roles.contains(role);
        if (revoke && !held) {
            throw GovernanceException.conflict(vuid + " no longer holds " + role
                    + "; another change request already removed it");
        }
        if (!revoke && held) {
            throw GovernanceException.conflict(vuid + " already holds " + role
                    + "; another change request already granted it");
        }

        /* Work out the new role set without touching the stored one.
         *
         * The store hands back the live grant, so mutating it here and attesting afterwards would
         * leave the role in memory when the cohort refuses, and any later write would persist a
         * grant that nothing has attested. The record must only move once the signatures exist. */
        java.util.LinkedHashSet<String> target = new java.util.LinkedHashSet<>(grant.roles);
        if (revoke) {
            target.remove(role);
        } else {
            target.add(role);
        }

        // Attest the new role set before recording it. If the cohort will not sign, the change does
        // not happen: a grant this service could write but not prove would be exactly the kind of
        // locally-asserted authority the design exists to remove.
        java.util.Optional<DeployedPolicy> approvals = rolePolicy();
        java.util.List<RoleGrant.SignedUnit> signed;
        try {
            signed = approvals.isPresent()
                    ? attestViaAdminQuorum(cr, approvals.get())
                    : roleAttestor.attest(vuid, target);
        } catch (GovernanceException e) {
            throw e;
        } catch (Exception e) {
            throw new GovernanceException(502,
                    "The Tide network would not attest this role change, so it was not applied: "
                            + e.getMessage());
        }

        grant.roles.clear();
        grant.roles.addAll(target);
        grant.signedUnits = signed;

        grant.changeRequestId = cr.id;
        grant.updatedAt = Instant.now().toString();
        store.putGrant(grant);

        log.info("%s %s %s %s", revoke ? "Revoked" : "Granted", role, revoke ? "from" : "to", vuid);
        return vuid;
    }

    /** The roles a Tide identity holds. This is what a doken's realm_access is built from. */
    public synchronized java.util.Set<String> rolesFor(String vuid) {
        return new java.util.LinkedHashSet<>(store.grant(vuid).roles);
    }

    public synchronized List<RoleGrant> allGrants() {
        return store.grants();
    }

    /**
     * The real ceremony: build the policy, wrap it in a {@code Policy:1} sign request authorized by
     * the firstAdmin pack, have the cohort sign it, and attach that signature to the policy so the
     * stored bytes are the shippable artifact.
     */
    /**
     * The carrier an admin's enclave is asked to approve.
     *
     * <p>Built on first request rather than at filing, because building it costs an ORK round trip
     * and most filed changes are never opened for approval.
     */
    public synchronized String carrierFor(String changeRequestId) throws Exception {
        ChangeRequest cr = require(changeRequestId);
        boolean roleChange = cr.kind == Kind.GRANT_ROLE || cr.kind == Kind.REVOKE_ROLE;
        if (cr.kind != Kind.DEPLOY_POLICY && !roleChange) {
            throw GovernanceException.badRequest(
                    "Only a policy deployment or a role change is approved this way");
        }

        if (cr.approvalCarrier == null || cr.approvalCarrier.isBlank()) {
            if (roleChange) {
                DeployedPolicy authorizer = rolePolicy().orElseThrow(() ->
                        GovernanceException.conflict("No policy requiring approvals is deployed for "
                                + "role changes, so there is nothing to approve against"));
                cr.approvalCarrier = buildRoleUnitCarrier(cr, cr.kind == Kind.REVOKE_ROLE, authorizer);
            } else {
                DeployedPolicy authorizer = adminPolicy().orElseThrow(() ->
                        GovernanceException.conflict(
                                "No admin policy is deployed, so there is nothing to approve against"));
                cr.approvalCarrier = buildApprovalCarrier(buildPolicy(cr.payload), cr.payload, authorizer);
            }
            cr.carrierApprovals = 0;
            store.putChangeRequest(cr);
            store.persist();
        }
        return cr.approvalCarrier;
    }

    /**
     * Take back a carrier an enclave has added a doken to.
     *
     * <p>The only thing verified here is that the <b>draft is unchanged</b>. An approval adds a
     * doken to the request's authorizer section and must leave everything else alone, so a carrier
     * whose draft differs is not this change any more, it is a different policy wearing this
     * change request's id, which is exactly how an approval collected for one thing would be
     * redirected onto another.
     *
     * <p>The approval <em>count</em> is deliberately not treated as security. The ORK counts the
     * dokens itself and refuses a sign below the policy's threshold, so this number only decides
     * when it is worth attempting the sign; a caller that inflates it gets a refusal from the
     * cohort rather than an unapproved policy.
     */
    public synchronized ChangeRequest acceptCarrier(String changeRequestId, String carrierBase64)
            throws Exception {
        ChangeRequest cr = require(changeRequestId);
        if (cr.approvalCarrier == null || cr.approvalCarrier.isBlank()) {
            throw GovernanceException.conflict("No approval was started for this change request");
        }
        if (carrierBase64 == null || carrierBase64.isBlank()) {
            throw GovernanceException.badRequest("An approved request is required");
        }

        byte[] before;
        byte[] after;
        try {
            before = org.midgard.models.ModelRequest
                    .FromBytes(Base64.getDecoder().decode(cr.approvalCarrier)).GetDraft();
            after = org.midgard.models.ModelRequest
                    .FromBytes(Base64.getDecoder().decode(carrierBase64)).GetDraft();
        } catch (Exception e) {
            throw GovernanceException.badRequest("That is not a readable approval request: " + e.getMessage());
        }

        if (!java.util.Arrays.equals(before, after)) {
            throw GovernanceException.badRequest(
                    "The approved request describes a different change than the one it was issued for");
        }

        cr.approvalCarrier = carrierBase64;
        cr.carrierApprovals++;
        store.putChangeRequest(cr);
        log.info("Collected approval %d for %s", cr.carrierApprovals, cr.id);
        return cr;
    }

    /** The only model an openly served policy may authorize. */
    public static final String ENCRYPT_MODEL = "PolicyEnabledEncryption:1";
    public static final String DECRYPT_MODEL = "PolicyEnabledDecryption:1";

    /**
     * A deployed policy that is safe to hand to anyone.
     *
     * <p>Safe means one thing only: its models are exactly the encryption model, nothing else. A
     * policy is a credential, and the reason this one can be published is that the ORK refuses to
     * let it authorize any request other than the models it names. Widen that list and the same
     * bytes become a key to something else, so the check is exact rather than "contains".
     */
    /** The deployed decryption policy, if one is deployed. */
    public synchronized java.util.Optional<DeployedPolicy> publicDecryptPolicy() {
        return store.policies().stream()
                .filter(p -> p.modelIds != null
                        && p.modelIds.size() == 1
                        && DECRYPT_MODEL.equals(p.modelIds.get(0)))
                .findFirst();
    }

    public synchronized java.util.Optional<DeployedPolicy> publicEncryptPolicy() {
        return store.policies().stream()
                .filter(p -> p.modelIds != null
                        && p.modelIds.size() == 1
                        && ENCRYPT_MODEL.equals(p.modelIds.get(0)))
                .findFirst();
    }

    /**
     * The admin policy that authorizes deploying other policies, if one is deployed.
     *
     * <p>Recognised by what it can authorize rather than by its name: a policy earns this role by
     * carrying {@code Policy:1} or the {@code any} wildcard in its models, which is exactly the
     * property the ORK checks. Naming it "admin" would let a policy called admin that cannot
     * actually authorize a sign look like the answer, and the failure would surface much later.
     */
    public synchronized java.util.Optional<DeployedPolicy> adminPolicy() {
        return store.policies().stream()
                .filter(p -> p.modelIds != null
                        && (p.modelIds.contains(ANY_MODEL) || p.modelIds.contains(POLICY_AUTH_FLOW)))
                .findFirst();
    }

    /**
     * Build the carrier a quorum of admins approve to deploy a policy.
     *
     * <p>This is phase one of two. The vendor cannot authorize this sign itself, the VRK's one
     * {@code Policy:1} was spent on the admin policy and revoked, so instead it builds a request
     * naming the admin policy as its authorizer, stamps a creation authorization on it with the
     * VRK, and hands the result out as an opaque blob. Each admin's enclave then appends their own
     * doken to that blob, and the accumulated result is what the ORKs finally sign.
     *
     * <p>The creation authorization is what makes the blob approvable at all: without it the
     * enclave finds an empty signature where it expects the vendor's, and refuses. It has to be
     * applied <em>after</em> the draft is materialised, because it signs a hash of that draft. That
     * is why {@code GetDraft()} is called and its return value is
     * discarded but whose side effect is the entire point.
     *
     * <p>Note that this creation authorization uses the <b>main</b> gVRK pack, not the firstAdmin
     * one: it is really a {@code TideRequestInitialization:1} request underneath, and only the main
     * pack lists that model.
     *
     * @return Base64 of the carrier, to be persisted and handed to approvers
     */
    private String buildApprovalCarrier(Policy policy, Map<String, Object> spec,
                                        DeployedPolicy authorizer) throws Exception {
        PolicySignRequest req = new PolicySignRequest(policy.ToBytes(), POLICY_AUTH_FLOW);

        if (Boolean.TRUE.equals(spec.get("uploadContract"))) {
            String contractIdRef = (String) spec.get("contractId");
            Contract c = store.contract(contractIdRef).orElseThrow(() ->
                    GovernanceException.badRequest("uploadContract was requested but contract "
                            + contractIdRef + " is not registered"));
            String entryType = str(spec, "entryType");
            req.AddContractToUpload(PolicySignRequest.ContractType.forseti,
                    contractUploadPayload(c.source, entryType == null ? DEFAULT_ENTRY_TYPE : entryType));
        }

        req.SetCustomExpiry((System.currentTimeMillis() / 1000) + APPROVAL_CARRIER_EXPIRY_SECONDS);

        // The authorizing policy travels with the request; the ORK reads it to decide who may
        // approve and whether an executor is needed.
        req.SetPolicy(Base64.getDecoder().decode(authorizer.policyBytes));

        // Materialise the draft. PolicySignRequest folds its payload in lazily, and encoding before
        // that leaves an empty draft, the approvers would then be signing nothing.
        req.GetDraft();

        vrk.initializeRequestWithVrk(req);

        return Base64.getEncoder().encodeToString(req.Encode());
    }

    /**
     * Deploy a policy under the admin policy, which needs a quorum of admin dokens.
     *
     * <p>Two phases, and the first commit attempt only completes the first of them. The vendor
     * builds a carrier and stops; admins approve it through their enclaves; a later commit finds
     * enough approvals and submits it. Refusing to sign until the threshold is met is the whole
     * mechanism, the vendor holds the VRK, and if it could deploy a policy alone it could deploy
     * one that grants itself the ability to read everything.
     *
     * @return the id of the deployed policy
     * @throws GovernanceException.Conflict while approvals are still outstanding
     */
    /**
     * Deploy a policy under an authorizer that asks nobody.
     *
     * <p>This is the bootstrap policy's route, and it exists because the bootstrap has to be
     * IMPLICIT. Attestation units are signed under the same policy on every sign-in, and a policy
     * that demanded approvals for those would mean no token could ever be minted, including the
     * admin tokens whose approvals it was waiting for.
     *
     * <p>The cost is real and worth stating: while this is the authorizer, deploying a policy needs
     * only the vendor key. The bootstrap contract narrows what that is worth by refusing to sign
     * the units that confer a role, so the way out of it is to deploy an EXPLICIT policy and let
     * the quorum route above take over.
     */
    private String commitPolicyUnderImplicitAuthorizer(ChangeRequest cr, Policy policy,
                                                       Map<String, Object> spec,
                                                       DeployedPolicy authorizer) throws Exception {
        PolicySignRequest req = new PolicySignRequest(policy.ToBytes(), POLICY_AUTH_FLOW);

        if (Boolean.TRUE.equals(spec.get("uploadContract"))) {
            String contractIdRef = (String) spec.get("contractId");
            Contract c = store.contract(contractIdRef).orElseThrow(() ->
                    GovernanceException.badRequest("uploadContract was requested but contract "
                            + contractIdRef + " is not registered"));
            String entryType = str(spec, "entryType");
            req.AddContractToUpload(PolicySignRequest.ContractType.forseti,
                    contractUploadPayload(c.source, entryType == null ? DEFAULT_ENTRY_TYPE : entryType));
        }

        req.SetCustomExpiry((System.currentTimeMillis() / 1000) + POLICY_SIGN_EXPIRY_SECONDS);
        req.SetPolicy(Base64.getDecoder().decode(authorizer.policyBytes));

        var settings = vrk.store().midgardSettings();
        settings.TraceParent = org.minidauth.vrk.Trace.current();
        SignatureResponse resp = org.midgard.Midgard.SignModel(settings, req);
        if (resp.Signatures == null || resp.Signatures.length == 0 || resp.Signatures[0] == null) {
            throw new IllegalStateException("Tide network returned no signature for the policy sign");
        }
        return storeSignedPolicy(cr, policy, spec, resp.Signatures[0]);
    }

    private String commitPolicyViaAdminQuorum(ChangeRequest cr, Policy policy,
                                              Map<String, Object> spec,
                                              DeployedPolicy authorizer) throws Exception {
        if (cr.approvalCarrier == null || cr.approvalCarrier.isBlank()) {
            cr.approvalCarrier = buildApprovalCarrier(policy, spec, authorizer);
            cr.carrierApprovals = 0;
            store.putChangeRequest(cr);
            throw GovernanceException.conflict(
                    "This policy must be approved by " + requiredApprovals(authorizer) + " Tide "
                    + "administrator(s) before it can be deployed. The approval request is ready; "
                    + "approve it in the governance console, then commit again.");
        }

        int required = requiredApprovals(authorizer);
        if (cr.carrierApprovals < required) {
            throw GovernanceException.conflict(
                    "Waiting on Tide administrator approvals: " + cr.carrierApprovals + " of "
                    + required + " collected.");
        }

        // The accumulated carrier is submitted exactly as the approvers left it. Its bytes are what
        // their dokens signed over, so re-encoding it here, even to something equivalent, would
        // invalidate every approval it carries.
        org.midgard.models.ModelRequest req = org.midgard.models.ModelRequest.FromBytes(Base64.getDecoder().decode(cr.approvalCarrier));

        var settings = vrk.store().midgardSettings();
        settings.TraceParent = org.minidauth.vrk.Trace.current();
        SignatureResponse resp = org.midgard.Midgard.SignModel(settings, req);
        if (resp.Signatures == null || resp.Signatures.length == 0 || resp.Signatures[0] == null) {
            throw new IllegalStateException("Tide network returned no signature for the policy sign");
        }

        return storeSignedPolicy(cr, policy, spec, resp.Signatures[0]);
    }

    /** How many admin dokens the authorizing policy demands. */
    private static int requiredApprovals(DeployedPolicy authorizer) {
        Object threshold = authorizer.params == null ? null : authorizer.params.get("threshold");
        if (threshold instanceof Number n) {
            return Math.max(1, n.intValue());
        }
        return 1;
    }

    /**
     * Refuse the first policy until somebody holds {@code governance-admin}.
     *
     * <p>Signing it spends the VRK's authorizer pack, and the pack is the only thing that can
     * attest a role while no policy exists. Deploying first therefore leaves a key on which no role
     * can ever be granted: the pack is gone, and any policy careful enough to be worth deploying
     * refuses to sign the units that confer one. There is no way back from it, which is why this
     * refuses rather than warns.
     */
    private void requireAnAdminExistsBeforeSpendingThePack() {
        boolean anyAdmin = store.grants().stream()
                .anyMatch(g -> g.roles != null && g.roles.contains(org.minidauth.auth.DokenOperators.ROLE_ADMIN));
        if (!anyAdmin) {
            throw GovernanceException.conflict(
                    "Grant " + org.minidauth.auth.DokenOperators.ROLE_ADMIN + " to at least one Tide "
                    + "identity before deploying the first policy. Signing it revokes the authorizer "
                    + "pack, which is the only thing that can attest a role until a policy exists, so "
                    + "deploying first leaves a key on which no role can ever be granted.");
        }
    }

    private String commitPolicy(ChangeRequest cr) throws Exception {
        Map<String, Object> spec = cr.payload;
        Policy policy = buildPolicy(spec);

        // Which route this takes is not a preference. The VRK's authorizer pack signs one Policy:1
        // and is revoked by the ORK on success, so the direct route below works exactly once per
        // vendor key, and only while no admin policy exists yet. Once one does, every further
        // policy has to be approved by a quorum of admins through it.
        java.util.Optional<DeployedPolicy> authorizer = adminPolicy();
        if (authorizer.isPresent()) {
            // Which of the two policy routes applies is decided by the authorizer, not by this
            // service. An IMPLICIT policy is one the ORKs never ask approvers about, so building a
            // carrier and waiting for dokens against one would wait forever.
            if ("IMPLICIT".equals(authorizer.get().approvalType)) {
                return commitPolicyUnderImplicitAuthorizer(cr, policy, spec, authorizer.get());
            }
            return commitPolicyViaAdminQuorum(cr, policy, spec, authorizer.get());
        }

        requireFirstAdminPackMatchesActiveVrk();
        requireAnAdminExistsBeforeSpendingThePack();

        PolicySignRequest req = new PolicySignRequest(policy.ToBytes(), VRK_AUTH_FLOW);

        // Ship the contract source with the sign, when asked. Must happen before the request is
        // authorized: the contract goes into Draft, and Draft is what GetDataToAuthorize hashes.
        if (Boolean.TRUE.equals(spec.get("uploadContract"))) {
            String contractIdRef = (String) spec.get("contractId");
            Contract c = store.contract(contractIdRef).orElseThrow(() ->
                    GovernanceException.badRequest("uploadContract was requested but contract "
                            + contractIdRef + " is not registered"));
            String entryType = str(spec, "entryType");
            req.AddContractToUpload(PolicySignRequest.ContractType.forseti,
                    contractUploadPayload(c.source, entryType == null ? DEFAULT_ENTRY_TYPE : entryType));
        }

        // Override the expiry BEFORE the request is authorized, for the same reason.
        req.SetCustomExpiry((System.currentTimeMillis() / 1000) + POLICY_SIGN_EXPIRY_SECONDS);

        // A Policy:1 sign is authorized by the firstAdmin authorizer pack, not the main gVRK pack.
        vrk.authorizeRequestWithFirstAdmin(req);

        var settings = vrk.store().midgardSettings();
        settings.TraceParent = org.minidauth.vrk.Trace.current();
        SignatureResponse resp = org.midgard.Midgard.SignModel(settings, req);
        if (resp.Signatures == null || resp.Signatures.length == 0 || resp.Signatures[0] == null) {
            throw new IllegalStateException("Tide network returned no signature for the policy sign");
        }
        return storeSignedPolicy(cr, policy, spec, resp.Signatures[0]);
    }

    /**
     * Attach the cohort's signature and record the finished policy.
     *
     * <p>Shared by both deployment routes, so the stored artifact is identical whether the sign was
     * authorized by the VRK or by an admin quorum. The signature is attached before the id is
     * computed because the id is a hash of the policy's bytes, and an unsigned policy hashes to
     * something the ORKs will never recognise.
     */
    private String storeSignedPolicy(ChangeRequest cr, Policy policy, Map<String, Object> spec,
                                     String vvkSig) {
        policy.AddSignature(Base64.getDecoder().decode(vvkSig));

        DeployedPolicy dp = new DeployedPolicy();
        dp.policyId = HexFormat.of().formatHex(policy.GetId()).toUpperCase(Locale.ROOT);
        dp.name = (String) spec.get("name");
        dp.contractId = policy.getContractId();
        dp.modelIds = List.of(policy.getModelIds());
        dp.keyId = policy.getKeyId();
        dp.approvalType = policy.getApprovalType().name();
        dp.executionType = policy.getExecutionType().name();
        dp.params = new LinkedHashMap<>(policy.getParams());
        dp.expiry = policy.getExpiry();
        dp.signature = vvkSig;
        dp.policyBytes = Base64.getEncoder().encodeToString(policy.ToBytes());
        dp.deployedBy = cr.requestedBy;
        dp.deployedAt = Instant.now().toString();
        dp.changeRequestId = cr.id;
        store.putPolicy(dp);
        return dp.policyId;
    }

    /**
     * Build the payload {@code PolicySignRequest.AddContractToUpload} expects.
     *
     * <p>The ORK unwraps this twice. {@code CompilableContractTransport} reads the envelope as
     * {@code [0]=type, [1]=payload}; then {@code ForsetiContract(data, compiled)} reads
     * <b>{@code data[1]}</b> as the inner block and takes {@code inner[0]} as the source and
     * {@code inner[1]} as the entry type. So the payload handed to {@code AddContractToUpload}
     * must itself be {@code [_, [source, entryType]]}, passing the raw source bytes makes the
     * ORK throw {@code ArgumentOutOfRangeException} inside the contract constructor.
     *
     * <p>The source is shipped uncompiled; the ORK auto-detects a pre-compiled DLL by its
     * {@code MZ} PE header, which a TideMemory block never starts with.
     */
    static byte[] contractUploadPayload(String source, String entryType) {
        byte[] inner = Tools.CreateTideMemory(
                source.getBytes(StandardCharsets.UTF_8),
                entryType.getBytes(StandardCharsets.UTF_8));
        return Tools.CreateTideMemory(
                PolicySignRequest.ContractType.forseti.name().getBytes(StandardCharsets.UTF_8),
                inner);
    }

    /**
     * The firstAdmin authorizer pack binds the VRK public point that was active when the wallet
     * was finalized. Rotating the VRK leaves that pack bound to the retired key, so the ORK's
     * VRKAuthorizationFlow rejects the sign with "VRK signature of this request could not be
     * verified", a message that says nothing about rotation. Catch it here instead.
     */
    private void requireFirstAdminPackMatchesActiveVrk() {
        String authorizer = vrk.store().get(org.minidauth.store.VendorKeyStore.AUTHORIZER);
        String gvrk = vrk.store().get(org.minidauth.store.VendorKeyStore.GVRK);
        String packPoint = authorizerPackPublicPoint(authorizer);
        String gvrkPoint = authorizerPackPublicPoint(gvrk);
        if (packPoint == null || gvrkPoint == null) return; // shape unknown; let the ORK decide
        if (!packPoint.equalsIgnoreCase(gvrkPoint)) {
            throw GovernanceException.conflict(
                    "The firstAdmin authorizer pack is bound to a retired VRK (pack point "
                            + packPoint.substring(0, 16) + "…, active key " + gvrkPoint.substring(0, 16)
                            + "…). Policy signing uses that pack, and the ORK will reject it. "
                            + "The pack is minted by wallet finalization and is not re-issued by a "
                            + "VRK rotation.");
        }
    }

    /** The 32-byte Ed25519 point an authorizer pack carries, as uppercase hex, or null. */
    static String authorizerPackPublicPoint(String packHex) {
        if (packHex == null) return null;
        java.util.regex.Matcher m = PACK_POINT.matcher(packHex);
        return m.find() ? m.group(1).toUpperCase(Locale.ROOT) : null;
    }

    // ================================================================== policy

    /** Build (and thereby validate) the policy a spec describes. No network, no side effects. */
    @SuppressWarnings("unchecked")
    /* Which policy wire version to emit.
     *
     * The bindings build version 4, which the released ORK network does not know: it answers a 500
     * whose body says "Could not find specified policy version: 4", and Midgard discards that body,
     * so it surfaces as an unexplained failure to sign Policy:1. Set MC_POLICY_VERSION=3 to talk to
     * a network that has not caught up yet.
     *
     * Version 3 is version 4 without the optional expiry field, so with no expiry set the two are
     * byte for byte identical apart from the version character itself. That is why this can rewrite
     * one into the other rather than needing a second serializer. */
    private static final String POLICY_VERSION = System.getenv("MC_POLICY_VERSION");

    /** Where the one character version sits: outer header and length, inner header, field length. */
    private static final int VERSION_OFFSET = 16;

    /**
     * Re-emit a policy at the configured wire version.
     *
     * <p>Refuses rather than guesses if the bytes are not shaped as expected, because a policy is
     * signed once and a malformed one is not something to discover later.
     */
    private static Policy atConfiguredVersion(Policy policy) {
        if (POLICY_VERSION == null || POLICY_VERSION.isBlank() || "4".equals(POLICY_VERSION)) {
            return policy;
        }
        if (!"3".equals(POLICY_VERSION)) {
            throw GovernanceException.badRequest("MC_POLICY_VERSION must be 3 or 4, got " + POLICY_VERSION);
        }
        if (policy.getExpiry() != null) {
            throw GovernanceException.badRequest(
                    "A version 3 policy has no expiry field, so this policy cannot be expressed on "
                    + "this network. Drop the expiry or use a network that understands version 4.");
        }

        byte[] bytes = policy.ToBytes();
        if (bytes.length <= VERSION_OFFSET || bytes[VERSION_OFFSET] != (byte) '4') {
            throw new IllegalStateException(
                    "Expected the policy version at offset " + VERSION_OFFSET + "; the serialized "
                    + "layout has changed and this downgrade is no longer safe");
        }
        bytes[VERSION_OFFSET] = (byte) '3';
        return Policy.From(bytes);
    }

    private Policy buildPolicy(Map<String, Object> spec) {
        String contractId = str(spec, "contractId");
        if (contractId == null) throw GovernanceException.badRequest("contractId is required");
        if (!CONTRACT_ID.matcher(contractId).matches()
                && !BUILTIN_CONTRACT_ID.matcher(contractId).matches()) {
            throw GovernanceException.badRequest(
                    "contractId must be either 128 UPPERCASE hex characters (SHA-512 of a Forseti "
                            + "contract's source; the ORKs compare it case-sensitively, so a lowercase "
                            + "digest is rejected) or a built-in contract id such as "
                            + "GenericRealmAccessThresholdRole:1.");
        }

        Object rawModels = spec.get("modelIds");
        String[] modelIds;
        if (rawModels instanceof List<?> list && !list.isEmpty()) {
            modelIds = list.stream().map(String::valueOf).toArray(String[]::new);
        } else if (rawModels instanceof String s && !s.isBlank()) {
            modelIds = new String[]{s};
        } else {
            throw GovernanceException.badRequest("modelIds is required (a string or a non-empty array)");
        }

        String keyId = str(spec, "keyId");
        if (keyId == null) {
            // The policy is scoped to this vendor's key by default.
            keyId = vrk.store().get(org.minidauth.store.VendorKeyStore.VENDOR_ID);
            if (keyId == null) {
                throw GovernanceException.badRequest("keyId is required (no vvkId available to default to)");
            }
        }

        ApprovalType approvalType = enumOrDefault(str(spec, "approvalType"), ApprovalType.class, ApprovalType.EXPLICIT);
        ExecutionType executionType = enumOrDefault(str(spec, "executionType"), ExecutionType.class, ExecutionType.PUBLIC);

        PolicyParameters params = new PolicyParameters();
        Object rawParams = spec.get("params");
        if (rawParams instanceof Map<?, ?> m) {
            for (Map.Entry<?, ?> e : m.entrySet()) {
                params.put(String.valueOf(e.getKey()), coerceParam(String.valueOf(e.getKey()), e.getValue()));
            }
        } else if (rawParams != null) {
            throw GovernanceException.badRequest("params must be an object");
        }

        Long expiry = null;
        Object rawExpiry = spec.get("expiry");
        if (rawExpiry instanceof Number n) {
            expiry = n.longValue();
            if (expiry <= Instant.now().getEpochSecond()) {
                throw GovernanceException.badRequest(
                        "expiry is in the past; the ORKs refuse an expired policy and it would never verify");
            }
        } else if (rawExpiry != null) {
            throw GovernanceException.badRequest("expiry must be a number (epoch seconds)");
        }

        return atConfiguredVersion(
                new Policy(contractId, modelIds, keyId, approvalType, executionType, params, expiry));
    }

    /**
     * PolicyParameters serialises exactly String / Integer / BigInteger / Boolean / byte[]. Jackson
     * hands back Integer, Long, Double and String, so coerce explicitly and refuse the rest rather
     * than let a Double reach the serializer and throw from inside the wire format.
     */
    private static Object coerceParam(String key, Object value) {
        if (value instanceof String || value instanceof Boolean || value instanceof Integer
                || value instanceof BigInteger || value instanceof byte[]) {
            return value;
        }
        if (value instanceof Long l) {
            // "num" is a 4-byte little-endian int; anything wider must go as a bignum.
            return (l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE)
                    ? Integer.valueOf(l.intValue())
                    : BigInteger.valueOf(l);
        }
        if (value == null) {
            throw GovernanceException.badRequest("Policy parameter '" + key + "' is null");
        }
        throw GovernanceException.badRequest("Policy parameter '" + key + "' has unsupported type "
                + value.getClass().getSimpleName() + "; use a string, integer or boolean");
    }

    private static <E extends Enum<E>> E enumOrDefault(String raw, Class<E> type, E fallback) {
        if (raw == null || raw.isBlank()) return fallback;
        try {
            return Enum.valueOf(type, raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw GovernanceException.badRequest("Unknown " + type.getSimpleName() + ": " + raw);
        }
    }

    private static String str(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v == null) return null;
        String s = String.valueOf(v);
        return s.isBlank() ? null : s;
    }

    private ChangeRequest require(String id) {
        return store.changeRequest(id)
                .orElseThrow(() -> GovernanceException.notFound("No change request " + id));
    }

    /** SHA-512 of the exact source, UPPERCASE hex, what the ORKs compare against. */
    public static String contractId(String source) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] digest = md.digest(source.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-512 unavailable", e);
        }
    }
}

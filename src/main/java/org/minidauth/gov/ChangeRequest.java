package org.minidauth.gov;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * One governed change, awaiting a quorum.
 *
 * <p>Field names follow TideCloak's IGA change request where they mean the same thing, notably
 * {@code authorizationCount} and {@code readyToCommit}, which are what a UI reads.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class ChangeRequest {
    public String id;
    public Kind kind;
    public Status status = Status.PENDING;

    public String requestedBy;
    /**
     * The subject four-eyes and de-duplication are computed over: the filer's proven Tide vuid when
     * they filed with an enclave approval, otherwise their operator name. Keeping one notion of
     * "who" lets operator-token and enclave approvals be counted in the same tally.
     */
    public String requestedBySubject;
    public String createdAt;
    public String resolvedAt;
    public String resolvedBy;

    /** The change itself: a contract source, or a policy spec. */
    public Map<String, Object> payload;

    /** Approvals needed. Snapshotted at filing so a later roster change cannot move the bar. */
    public int threshold = 1;
    public int authorizationCount;
    public List<Authorization> authorizers = new ArrayList<>();

    /**
     * The Base64 request the ORKs will eventually sign, once enough admins have approved it.
     *
     * <p>Only set for a policy deployment that has to go through the admin policy, that is, every
     * one after the first. It starts as a vendor-created request with no approvals on it, and each
     * admin's enclave returns it with their doken appended, so this field is rewritten as the
     * quorum assembles. It is opaque here on purpose: the accumulated signatures cover its exact
     * bytes, so anything that rebuilt or reformatted it would silently invalidate every approval
     * already collected.
     */
    public String approvalCarrier;

    /**
     * The exact attestation units the carrier was built over, base64.
     *
     * <p>Kept rather than recomputed. The cohort signs these bytes, and the signatures are stored
     * against them, so rebuilding them at commit time from state that may have moved on would pair
     * a signature with a unit it does not cover.
     */
    public java.util.List<String> carrierUnits;

    /** How many admin dokens the carrier currently holds. */
    public int carrierApprovals;

    /** True once {@code authorizationCount >= threshold}. Authorizing never commits. */
    public boolean readyToCommit;

    /** Set on commit: the contractId or policyId that resulted. */
    public String resultId;
    /** Set when a commit attempt failed, so a retry is possible without re-approving. */
    public String lastError;

    public ChangeRequest() {}

    public boolean hasAuthorized(String subject) {
        return authorizers.stream().anyMatch(a -> subject.equalsIgnoreCase(a.subject));
    }

    public void recount() {
        authorizationCount = authorizers.size();
        readyToCommit = status == Status.PENDING && authorizationCount >= threshold;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class Authorization {
        /** Who this approval counts as, the vuid when Tide-approved, else the operator name. */
        public String subject;
        /** The operator token that carried the approval. Transport, not identity. */
        public String operator;
        /** The proven Tide identity, when the approval came through the enclave. */
        public String vuid;
        /** {@code operator} or {@code tide-enclave}. */
        public String method;
        public String timestamp;

        public Authorization() {}

        public static Authorization byOperator(String operator, String timestamp) {
            Authorization a = new Authorization();
            a.subject = operator;
            a.operator = operator;
            a.method = "operator";
            a.timestamp = timestamp;
            return a;
        }

        public static Authorization byEnclave(String vuid, String operator, String timestamp) {
            Authorization a = new Authorization();
            a.subject = vuid;
            a.operator = operator;
            a.vuid = vuid;
            a.method = "tide-enclave";
            a.timestamp = timestamp;
            return a;
        }
    }
}

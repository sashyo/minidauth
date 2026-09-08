package org.minidauth.gov;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

/** A policy that has been signed by the ORK cohort and is therefore live. */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class DeployedPolicy {
    /** SHA-512 of the policy's signed payload, uppercase hex, the policy's own identity. */
    public String policyId;
    public String name;
    public String contractId;
    public List<String> modelIds;
    public String keyId;
    public String approvalType;
    public String executionType;
    public Map<String, Object> params;
    public Long expiry;
    /** Base64 of the VVK threshold signature returned by the cohort. */
    public String signature;
    /** Base64 of {@code Policy.ToBytes()} WITH the signature attached, the shippable artifact. */
    public String policyBytes;
    public String deployedBy;
    public String deployedAt;
    public String changeRequestId;

    public DeployedPolicy() {}
}

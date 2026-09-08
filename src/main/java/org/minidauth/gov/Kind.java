package org.minidauth.gov;

public enum Kind {
    /** Register a Forseti contract's source under its content hash. */
    DEPLOY_CONTRACT,
    /** Sign and deploy a policy that binds a contract to a set of models. */
    DEPLOY_POLICY,
    /** Give a Tide identity a role. The role reaches the doken only once this commits. */
    GRANT_ROLE,
    /** Take a role away from a Tide identity. */
    REVOKE_ROLE
}

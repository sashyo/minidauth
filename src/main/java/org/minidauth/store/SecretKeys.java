package org.minidauth.store;

/**
 * The private-key bundle. Field names match TideCloak's {@code org.tidecloak.tidecustom.SecretKeys}
 * so a store written here deserialises there unchanged.
 */
public class SecretKeys {
    public String activeVrk;
    public String pendingVrk;
    public String VZK;
}

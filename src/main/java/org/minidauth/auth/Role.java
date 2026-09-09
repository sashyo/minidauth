package org.minidauth.auth;

import java.util.Locale;

/** What an operator is allowed to do. */
public enum Role {
    /** May drive the VRK lifecycle: create, stage, certify, promote. */
    VRK_ADMIN,
    /** May file, authorize and commit governed policy/contract changes. */
    APPROVER,
    /**
     * An application integrating against this service. Grants nothing on its own.
     *
     * <p>No route requires it, which is the point: holding it lets an app start a Tide sign-in,
     * finish one, and read what an identity has been granted, because those routes only ask for a
     * known caller. Everything that changes anything asks for one of the roles above, so the app
     * cannot approve a change or touch the key even though it holds a token.
     *
     * <p>An operator with an empty role list would do the same job, but the loader refuses one, and
     * rightly: a credential with no stated purpose is how privilege gets added later by accident.
     */
    RELYING_PARTY;

    public String wire() {
        return name().toLowerCase(Locale.ROOT).replace('_', '-');
    }

    public static Role fromWire(String s) {
        if (s == null) throw new IllegalArgumentException("role is required");
        try {
            return Role.valueOf(s.trim().toUpperCase(Locale.ROOT).replace('-', '_'));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown role '" + s + "'; expected vrk-admin, approver or relying-party");
        }
    }
}

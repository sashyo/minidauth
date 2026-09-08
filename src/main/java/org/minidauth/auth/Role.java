package org.minidauth.auth;

import java.util.Locale;

/** What an operator is allowed to do. Two roles is all this service needs. */
public enum Role {
    /** May drive the VRK lifecycle: create, stage, certify, promote. */
    VRK_ADMIN,
    /** May file, authorize and commit governed policy/contract changes. */
    APPROVER;

    public String wire() {
        return name().toLowerCase(Locale.ROOT).replace('_', '-');
    }

    public static Role fromWire(String s) {
        if (s == null) throw new IllegalArgumentException("role is required");
        try {
            return Role.valueOf(s.trim().toUpperCase(Locale.ROOT).replace('-', '_'));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown role '" + s + "'; expected vrk-admin or approver");
        }
    }
}

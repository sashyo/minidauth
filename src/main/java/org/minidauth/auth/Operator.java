package org.minidauth.auth;

import java.util.Set;

/**
 * An operator of this service.
 *
 * <p>Not a user account and not an identity this service issues: operators are declared in
 * configuration and read at boot. The only thing governance needs from one is a stable name to
 * attribute an approval to, and the roles that say what it may do.
 */
public record Operator(String name, Set<Role> roles) {

    public boolean has(Role role) {
        return roles.contains(role);
    }

    public void require(Role role) {
        if (!has(role)) {
            throw new Unauthorized(name + " is missing the " + role.wire() + " role");
        }
    }

    /** Thrown when an authenticated operator lacks the role a route requires. */
    public static final class Unauthorized extends RuntimeException {
        public Unauthorized(String message) { super(message); }
    }
}

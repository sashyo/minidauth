package org.minidauth.auth;

import org.minidauth.tide.Doken;

import java.time.Instant;
import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * Authenticates an operator by the doken they signed in with, instead of a shared secret.
 *
 * <h2>Why this replaces the static token</h2>
 *
 * A bearer token that authorises governance has to be stored somewhere by whatever holds it, and
 * in the deployments this service exists to protect, that somewhere was the tidified application's
 * own database. That inverts the threat model: the application is the component we assume gets
 * compromised, and a static governance credential sitting inside it means a compromise of the
 * application can grant itself a role, and therefore read the data the application was never
 * supposed to be able to read.
 *
 * <p>A doken has none of those properties. It is minted by the ORK cohort only after a real
 * enclave sign-in, it expires, and it is bound to a session key held inside the enclave, so a copy
 * lifted from anywhere is useless without the browser it was issued to. Nothing durable needs to be
 * stored by anyone.
 *
 * <h2>Where the roles come from</h2>
 *
 * From the doken's {@code realm_access}, which the cohort put there, the vendor cannot write that
 * claim itself, because the ORK validates it against attested {@code user_role_mapping_set} and
 * {@code role_definition} units before signing.
 *
 * <p>The grant record is then checked <b>again</b>, locally, and both must agree. That is not
 * redundant: a doken is valid for hours, so a role revoked through the quorum would otherwise keep
 * working until the token expired. Requiring the live record means a revocation takes effect at the
 * next request. The cost is that the two can disagree in the other direction, a role granted after
 * sign-in does not apply until the operator signs in again, which is the safe way round.
 */
public final class DokenOperators {

    /** The authorization scheme. Deliberately not "Bearer": these are not interchangeable. */
    public static final String SCHEME = "Doken ";

    /**
     * The two governance roles, and why they are named this way.
     *
     * <p>Not {@code tide-*}: the Tide network is what this runs on, not what this is, and a role
     * called {@code tide-admin} inside someone else's identity system reads as "administers Tide",
     * which is not what it grants. Not {@code realm-*} either, that is a Keycloak concept, and
     * there are no realms here.
     *
     * <p>{@code governance-} says exactly what the authority is over: the keys, the policies, and
     * who holds which role. It is also distinctive enough not to collide with the roles the host
     * application already has, every system has an {@code admin} or an {@code administrator}, and
     * a governance role that could be satisfied by one of those would be a serious mistake.
     *
     * <p>Deliberately just two. This is not a permission matrix; it is "may change the rules" and
     * "may co-sign a change", which is the whole of what the quorum needs to express.
     */
    public static final String ROLE_ADMIN = "governance-admin";
    public static final String ROLE_APPROVER = "governance-approver";

    private final java.util.function.Supplier<String> vvkPublic;
    private final java.util.function.Supplier<String> vendorId;
    private final Function<String, Collection<String>> grantedRoles;

    /**
     * @param vvkPublic    the vendor key's public point, as the doken must verify against
     * @param vendorId     the vvkId, which a doken must name as its audience
     * @param grantedRoles the live governed grant record for a vuid
     */
    public DokenOperators(java.util.function.Supplier<String> vvkPublic,
                          java.util.function.Supplier<String> vendorId,
                          Function<String, Collection<String>> grantedRoles) {
        this.vvkPublic = vvkPublic;
        this.vendorId = vendorId;
        this.grantedRoles = grantedRoles;
    }

    /**
     * Check that a doken is genuine, unexpired, and minted for this vendor key.
     *
     * <p>Identity only. It says nothing about what the holder may do, which is why the vault uses
     * this rather than {@link #authenticate}: someone who can read vault data is not thereby an
     * operator, and requiring a governance role to decrypt would be the wrong gate entirely.
     */
    public Optional<Doken> verify(String token) {
        if (token == null || token.isBlank()) return Optional.empty();

        String vvk = vvkPublic.get();
        if (vvk == null || vvk.isBlank()) {
            // No vendor key yet, so nothing can have been signed by it.
            return Optional.empty();
        }

        Doken doken;
        try {
            doken = Doken.verify(token.trim(), vvk);
        } catch (Exception e) {
            // Any failure to verify is simply "not authenticated". The reason is not reported back:
            // telling a caller whether it was the signature or the audience helps someone probing
            // the endpoint more than it helps anyone legitimate.
            return Optional.empty();
        }

        if (doken.expiresAt <= Instant.now().getEpochSecond()) return Optional.empty();

        // A doken minted for a different vendor key must not work here, even if that key happened
        // to share a public point.
        String vid = vendorId.get();
        if (vid == null || !vid.equals(doken.audience)) return Optional.empty();

        return Optional.of(doken);
    }

    /**
     * Verify a doken and resolve the operator it stands for.
     *
     * @param token the raw doken JWS
     * @return the operator, or empty when the doken is unusable for governance
     */
    public Optional<Operator> authenticate(String token) {
        Optional<Doken> verified = verify(token);
        if (verified.isEmpty()) return Optional.empty();
        Doken doken = verified.get();

        Set<String> claimed = realmRoles(doken);
        if (claimed.isEmpty()) return Optional.empty();

        // Intersect with the live record, so a revocation bites immediately.
        Collection<String> current = grantedRoles.apply(doken.vuid);
        Set<String> effective = new LinkedHashSet<>(claimed);
        effective.retainAll(current == null ? Set.of() : Set.copyOf(current));

        Set<Role> roles = toServiceRoles(effective);
        if (roles.isEmpty()) return Optional.empty();

        return Optional.of(new Operator(doken.vuid, roles));
    }

    /** {@code realm_access.roles} as a set; empty when the claim is absent or malformed. */
    static Set<String> realmRoles(Doken doken) {
        Set<String> out = new LinkedHashSet<>();
        var realmAccess = doken.payload.get("realm_access");
        if (realmAccess == null || !realmAccess.isObject()) return out;
        var roles = realmAccess.get("roles");
        if (roles == null || !roles.isArray()) return out;
        roles.forEach(node -> {
            if (node.isTextual()) out.add(node.asText().trim().toLowerCase(Locale.ROOT));
        });
        return out;
    }

    /**
     * Map realm roles onto what this service lets an operator do.
     *
     * <p>A realm admin is also an approver. Splitting them would mean an admin could deploy a
     * policy but not approve one, which is not a distinction anyone asked for and would mostly
     * produce confusing refusals.
     */
    public static Set<Role> toServiceRoles(Collection<String> realmRoles) {
        Set<Role> roles = EnumSet.noneOf(Role.class);
        if (realmRoles == null) return roles;
        for (String role : realmRoles) {
            String r = role == null ? "" : role.trim().toLowerCase(Locale.ROOT);
            if (ROLE_ADMIN.equals(r)) {
                roles.add(Role.VRK_ADMIN);
                roles.add(Role.APPROVER);
            } else if (ROLE_APPROVER.equals(r)) {
                roles.add(Role.APPROVER);
            }
        }
        return roles;
    }

    /** The realm roles that mean anything here, for the console to show and the docs to name. */
    public static Map<String, String> governanceRoles() {
        return Map.of(
                ROLE_ADMIN, "Full control: key lifecycle, policies, and approvals",
                ROLE_APPROVER, "May file, approve and commit governed changes");
    }
}

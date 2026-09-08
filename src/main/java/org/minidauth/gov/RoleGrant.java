package org.minidauth.gov;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The authoritative record of what a Tide identity is allowed to do.
 *
 * <p>This is the thing the doken's {@code realm_access.roles} is built from, which makes it the
 * hinge of the whole access model. It is deliberately <b>not</b> writable by the application: a role
 * only lands here by way of a committed change request, so granting yourself decryption rights takes
 * a quorum rather than a database write.
 *
 * <p>That distinction is the entire reason this record exists separately from the app's own user
 * table. An app-owned role store would mean a compromise of the app, SQL injection, a stolen
 * backup, a rogue admin, silently yields decryption rights, and the ORKs would enforce the lie
 * faithfully because the doken signature would be perfectly valid.
 *
 * <h2>Why the signed units matter more than the role list</h2>
 *
 * The role names below are a convenience, not the authority. What actually grants anything is
 * {@link #signedUnits}: the attestation units the ORK cohort signed when the change was committed.
 *
 * <p>Without them this file would be the weak point of the whole design. The ORK refuses any claim
 * with no attested unit behind it, but if this service built those units fresh from a local JSON
 * file every time it minted a token, then editing the file by hand would produce units that verify
 * perfectly. Anyone who owned the machine could grant themselves anything, silently.
 *
 * <p>Signing once, at commit time, and replaying the stored bytes closes that. Editing the role
 * list now changes nothing, because the units are not rebuilt from it; and forging a unit is not
 * possible without the cohort. The machine can present what was already agreed, and nothing else.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class RoleGrant {

    /** The Tide identity these roles belong to. */
    public String vuid;

    /** Roles currently held. Ordered for a stable doken payload. */
    public Set<String> roles = new LinkedHashSet<>();

    /**
     * The cohort-signed attestation units that make the roles above real.
     *
     * <p>Replayed verbatim when a doken is minted. They are bytes and a signature over exactly
     * those bytes, so they cannot be edited, only replaced by another committed change.
     */
    public List<SignedUnit> signedUnits = new ArrayList<>();

    /** Change request that last altered this record, for audit. */
    public String changeRequestId;
    public String updatedAt;

    /** One attestation unit and the cohort's signature over it, both base64. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class SignedUnit {
        public String unit;
        public String signature;

        public SignedUnit() {}

        public SignedUnit(String unit, String signature) {
            this.unit = unit;
            this.signature = signature;
        }
    }

    public RoleGrant() {}

    public RoleGrant(String vuid) {
        this.vuid = vuid;
    }
}

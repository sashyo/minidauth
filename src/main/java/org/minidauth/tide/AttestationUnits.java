package org.minidauth.tide;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds the attestation-unit envelopes the ORK validates a token against.
 *
 * <p>The ORK does not take a vendor's word for what is in a token. Before signing a session-start
 * request it verifies every attached unit against the VVK and then runs the token's claims through
 * a validation engine seeded with those units, so a claim with no attesting unit behind it is not
 * merely unsupported, it makes the whole request fail. That is what stops a compromised vendor
 * server from minting itself a token that says whatever it likes.
 *
 * <p>Envelope shape, common to every unit type:
 * <pre>
 * { "unit_type": &lt;int ordinal&gt;, "schema_version": 1, "target_id": &lt;primary key&gt;, "payload": {...} }
 * </pre>
 * encoded as CTAP2-canonical CBOR. {@code unit_type} is the enum <b>ordinal</b>, not the name, so
 * the declared order of that enum is part of the wire format.
 */
public final class AttestationUnits {

    /**
     * The only attribute names a fresh self-registered identity may carry.
     *
     * <p>The ORK hard-fails a unit carrying anything outside this set, it never strips or filters,
     * it refuses the whole request. The guard exists to stop an attribute-writing mapper injecting
     * an authorization-bearing attribute into an identity at registration.
     */
    public static final String ATTR_VUID = "vuid";
    /** camelCase on the entity, distinct from the lowercase {@code tideuserkey} claim it projects. */
    public static final String ATTR_TIDE_USER_KEY = "tideUserKey";

    /** Ordinals from the ORK's {@code AttestationUnitType} enum. Never reorder that enum. */
    public static final int REALM_CONFIG = 0;
    public static final int CLIENT_CONFIG = 1;
    public static final int PROTOCOL_MAPPER = 3;
    public static final int ROLE_DEFINITION = 4;
    public static final int USER_IDENTITY = 6;
    public static final int USER_ROLE_MAPPING_SET = 7;
    public static final int CLIENT_SCOPE_ASSIGNMENT_SET = 11;
    public static final int CLIENT_MAPPER_SET = 12;

    /** The only schema version the ORK accepts today. */
    public static final int SCHEMA_VERSION = 1;

    private AttestationUnits() {}

    /**
     * A {@code user_identity} unit.
     *
     * <p>Note what this unit does <b>not</b> carry: roles. Those live in a separate
     * {@code user_role_mapping_set} unit, so attesting an identity alone yields a token with an
     * empty {@code realm_access}, which is correct, and is why a role has to be attested
     * separately rather than asserted alongside the name.
     *
     * <p>{@code target_id} must equal {@code user_id}; the ORK checks it and rejects a mismatch.
     *
     * @param userId   the vuid, as proven by the enclave sign-in
     * @param username display name; the vuid itself is a reasonable value when there is no other
     * @param email    may be null
     * @param firstName may be null
     * @param lastName  may be null
     * @param attributes custom attributes as name to values
     */
    public static byte[] userIdentity(String userId, String username, String email,
                                      boolean emailVerified, String firstName, String lastName,
                                      Map<String, List<String>> attributes) {
        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("A user_identity unit needs a user_id");
        }

        List<Object> attrs = new ArrayList<>();
        if (attributes != null) {
            for (Map.Entry<String, List<String>> e : attributes.entrySet()) {
                Map<String, Object> nv = new LinkedHashMap<>();
                nv.put("name", e.getKey());
                nv.put("values", new ArrayList<Object>(e.getValue()));
                attrs.add(nv);
            }
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("user_id", userId);
        payload.put("username", username == null ? userId : username);
        payload.put("email", email);
        payload.put("email_verified", emailVerified);
        payload.put("first_name", firstName);
        payload.put("last_name", lastName);
        payload.put("attributes", attrs);

        return envelope(USER_IDENTITY, userId, payload);
    }

    /**
     * The identity unit a self-registration admits.
     *
     * <p>Carries exactly the two attributes the ORK binds against, and nothing else: it verifies
     * the blind signature under {@code tideUserKey} and requires {@code vuid} to equal the
     * authenticated user. Adding any other attribute, even a harmless-looking one, makes the ORK
     * refuse the whole request.
     *
     * @param vuid       the proven Tide identity
     * @param userPublic that user's public key, as returned by the sign-in verification
     */
    public static byte[] selfRegisteredIdentity(String vuid, String userPublic) {
        if (userPublic == null || userPublic.isBlank()) {
            throw new IllegalArgumentException(
                    "A self-registered identity must carry the user's public key as tideUserKey");
        }
        /* Only these two, and only ever these two.
         *
         * A fresh self-registered identity may carry vuid, tideUserKey, username, firstName,
         * lastName and email, and nothing else: the ORK refuses the whole unit over any other
         * attribute rather than dropping it. So a claim that needs a per-deployment value cannot be
         * smuggled in here as an attribute; it needs a mapper that carries the value itself. */
        Map<String, List<String>> attributes = new LinkedHashMap<>();
        attributes.put(ATTR_VUID, List.of(vuid));
        attributes.put(ATTR_TIDE_USER_KEY, List.of(userPublic));
        return userIdentity(vuid, vuid, null, false, null, null, attributes);
    }

    /**
     * A {@code realm_config} unit.
     *
     * <p>The token validation engine looks this up with {@code .Single()}, so exactly one must be
     * attached to any session-start request, its absence is the "Sequence contains no elements"
     * failure, which names neither the unit nor the engine.
     *
     * <p>This unit has no target-matching rule: it <em>is</em> the realm, so {@code target_id} is
     * simply the realm's own id.
     */
    public static byte[] realmConfig(String realmId, String name, long accessTokenLifespanSeconds,
                                     long ssoSessionIdleTimeoutSeconds, long ssoSessionMaxLifespanSeconds,
                                     Map<String, String> attributes) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("name", name);
        payload.put("access_token_lifespan_seconds", accessTokenLifespanSeconds);
        payload.put("access_token_lifespan_for_implicit_flow_seconds", accessTokenLifespanSeconds);
        payload.put("sso_session_idle_timeout_seconds", ssoSessionIdleTimeoutSeconds);
        payload.put("sso_session_max_lifespan_seconds", ssoSessionMaxLifespanSeconds);
        payload.put("client_session_idle_timeout_seconds", ssoSessionIdleTimeoutSeconds);
        payload.put("client_session_max_lifespan_seconds", ssoSessionMaxLifespanSeconds);
        payload.put("offline_session_idle_timeout_seconds", ssoSessionIdleTimeoutSeconds);
        payload.put("offline_session_max_lifespan_enabled", false);
        payload.put("offline_session_max_lifespan_seconds", ssoSessionMaxLifespanSeconds);
        payload.put("attributes", nameValues(attributes));
        return envelope(REALM_CONFIG, realmId, payload);
    }

    /**
     * A {@code client_config} unit.
     *
     * <p>Selected by matching {@code client_id} against the TokenRequest's ClientId, the engine
     * reports "requested client_id names no attested client_config" when nothing matches. Picking
     * the client from the attested set rather than the token's own {@code azp} is deliberate on the
     * ORK's part: a forged azp must not be able to steer which config governs the checks.
     *
     * <p>{@code target_id} must equal {@code client_id_uuid}.
     */
    public static byte[] clientConfig(String clientIdUuid, String clientId, boolean fullScopeAllowed,
                                      List<String> webOrigins, Map<String, String> attributes) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("client_id_uuid", clientIdUuid);
        payload.put("client_id", clientId);
        payload.put("protocol", "openid-connect");
        payload.put("full_scope_allowed", fullScopeAllowed);
        payload.put("service_accounts_enabled", false);
        payload.put("web_origins", webOrigins == null ? List.of() : new ArrayList<Object>(webOrigins));
        payload.put("attributes", nameValues(attributes));
        return envelope(CLIENT_CONFIG, clientIdUuid, payload);
    }

    /**
     * A {@code client_scope_assignment_set} unit.
     *
     * <p>Also a {@code .Single()} lookup, so one is always required, but the assignment list may be
     * empty. An empty list is what keeps {@code client_scope_config} units out of the picture
     * entirely: the engine only dereferences those while walking assignments.
     *
     * @param assignments client-scope id to whether it is a default scope
     */
    public static byte[] clientScopeAssignmentSet(String clientIdUuid, Map<String, Boolean> assignments) {
        List<Object> list = new ArrayList<>();
        if (assignments != null) {
            for (Map.Entry<String, Boolean> e : assignments.entrySet()) {
                Map<String, Object> a = new LinkedHashMap<>();
                a.put("client_scope_id", e.getKey());
                a.put("default", e.getValue());
                list.add(a);
            }
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("client_id_uuid", clientIdUuid);
        payload.put("assignments", list);
        return envelope(CLIENT_SCOPE_ASSIGNMENT_SET, clientIdUuid, payload);
    }

    /**
     * A {@code protocol_mapper} unit.
     *
     * <p><b>Why every custom claim needs one.</b> The ORK's token validation engine builds the set
     * of claims it <em>expects</em> by running the attested mappers, then compares that set against
     * the token in both directions. A claim the token asserts with no mapper behind it is rejected
     * with "has no attested source", the vendor does not get to state a claim, it has to attest the
     * configuration that would have produced it. That is what stops a compromised vendor server from
     * asserting {@code tideuserkey} for a key it does not hold.
     *
     * <p>{@code target_id} must equal {@code protocolMapperId}, and the mapper's {@code protocol}
     * must match the client's or the whole request is refused rather than the mapper dropped.
     *
     * @param parentType {@code client} or {@code client_scope}; the ORK parses this by name
     * @param factory    a Keycloak factory id the ORK has a handler for, e.g.
     *                   {@code oidc-usermodel-attribute-mapper}
     */
    public static byte[] protocolMapper(String protocolMapperId, String parentType, String parentId,
                                        String factory, Map<String, String> config) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("protocol_mapper_id", protocolMapperId);
        payload.put("parent_type", parentType);
        payload.put("parent_id", parentId);
        payload.put("protocol", "openid-connect");
        payload.put("protocol_mapper", factory);
        payload.put("config", nameValues(config));
        return envelope(PROTOCOL_MAPPER, protocolMapperId, payload);
    }

    /**
     * Projects a user attribute into a token claim.
     *
     * <p>The attribute name is the camelCase one on the identity unit; the claim name is the
     * lowercase one in the token. They are deliberately different for {@code tideUserKey} to
     * {@code tideuserkey}, which is exactly the kind of mismatch this mapper exists to declare.
     */
    public static byte[] attributeMapper(String protocolMapperId, String clientIdUuid,
                                         String userAttribute, String claimName) {
        Map<String, String> config = new LinkedHashMap<>();
        config.put("user.attribute", userAttribute);
        config.put("claim.name", claimName);
        config.put("access.token.claim", "true");
        return protocolMapper(protocolMapperId, "client", clientIdUuid,
                "oidc-usermodel-attribute-mapper", config);
    }

    /**
     * Escape a claim name so it stays one claim.
     *
     * <p>A dot in a mapper's claim name is a path separator: the ORK splits on it and nests, so
     * {@code t.uho} would be attested as {@code {"t":{"uho":...}}} while the token carries it flat,
     * and the two never match. Backslash escaping the dots is what says "this is a name, not a
     * path".
     */
    private static String escapeClaimName(String claimName) {
        return claimName.replace(".", "\\.");
    }

    /**
     * Puts a fixed value in a claim.
     *
     * <p>For claims whose value belongs to the deployment rather than the user, so there is no
     * attribute to project. The value travels inside the mapper, which means it is attested as
     * configuration: the cohort signs the mapper that would produce the claim, and the validation
     * engine then reproduces it and compares. A token asserting a different value than the attested
     * mapper produces is refused, which is the property that matters.
     */
    public static byte[] hardcodedClaimMapper(String protocolMapperId, String clientIdUuid,
                                              String claimName, String claimValue) {
        Map<String, String> config = new LinkedHashMap<>();
        config.put("claim.name", escapeClaimName(claimName));
        config.put("claim.value", claimValue);
        config.put("jsonType.label", "String");
        config.put("access.token.claim", "true");
        return protocolMapper(protocolMapperId, "client", clientIdUuid,
                "oidc-hardcoded-claim-mapper", config);
    }

    /**
     * Backs the token's {@code aud}.
     *
     * <p>On the access surface {@code aud} is mapper-derived, not a base claim, so a token carrying
     * an audience without this unit is unbacked. The ORK resolves {@code included.client.audience}
     * against the attested {@code client_config} set rather than trusting the string, so the name
     * here must be a client that is itself attested.
     */
    public static byte[] audienceMapper(String protocolMapperId, String clientIdUuid,
                                        String includedClientId) {
        Map<String, String> config = new LinkedHashMap<>();
        config.put("included.client.audience", includedClientId);
        config.put("access.token.claim", "true");
        return protocolMapper(protocolMapperId, "client", clientIdUuid,
                "oidc-audience-mapper", config);
    }

    /**
     * A {@code client_mapper_set} unit: the complete list of mappers attached to the client.
     *
     * <p>"Complete" is the point, it is how the ORK detects a mapper that was added or removed
     * behind its back. A mapper unit that is not named here never enters mapper assembly, so
     * attesting the mapper alone is not enough to back its claim.
     */
    public static byte[] clientMapperSet(String clientIdUuid, List<String> protocolMapperIds) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("client_id_uuid", clientIdUuid);
        payload.put("protocol_mapper_ids", new ArrayList<Object>(protocolMapperIds));
        return envelope(CLIENT_MAPPER_SET, clientIdUuid, payload);
    }

    /**
     * A {@code role_definition} unit, what a role <em>is</em>.
     *
     * <p>Separate from the grant on purpose. The ORK resolves a granted role id against these, and
     * a role id with no definition behind it is dropped rather than trusted, so a grant cannot
     * conjure a role that was never defined.
     *
     * @param clientRole   false for a realm role; only realm roles reach {@code realm_access}
     * @param containerId  the realm (or owning client) the role belongs to
     */
    public static byte[] roleDefinition(String roleId, String name, boolean clientRole,
                                        String containerId) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("role_id", roleId);
        payload.put("name", name);
        payload.put("client_role", clientRole);
        payload.put("container_id", containerId);
        return envelope(ROLE_DEFINITION, roleId, payload);
    }

    /**
     * A {@code user_role_mapping_set} unit, the user's direct role grants.
     *
     * <p>This is the unit that carries authorization, and it is why a role has to be attested
     * rather than asserted: the ORK reads the granted set from here, not from the token. Looked up
     * by {@code user_id} with {@code SingleOrDefault}, so at most one may be attached per user;
     * absent simply means no direct grants.
     */
    public static byte[] userRoleMappingSet(String userId, List<String> roleIds) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("user_id", userId);
        payload.put("role_ids", new ArrayList<Object>(roleIds));
        return envelope(USER_ROLE_MAPPING_SET, userId, payload);
    }

    /**
     * Projects the user's granted realm roles into {@code realm_access.roles}.
     *
     * <p>The dotted claim name is what nests the array under {@code realm_access}; a flat name
     * would put the roles at the top level and the doken's own {@code realm_access} would then have
     * no attested source.
     */
    public static byte[] realmRoleMapper(String protocolMapperId, String clientIdUuid) {
        Map<String, String> config = new LinkedHashMap<>();
        config.put("claim.name", "realm_access.roles");
        config.put("multivalued", "true");
        config.put("access.token.claim", "true");
        return protocolMapper(protocolMapperId, "client", clientIdUuid,
                "oidc-usermodel-realm-role-mapper", config);
    }

    /** Config units carry single-valued attributes ({@code name}/{@code value}), unlike an identity. */
    private static List<Object> nameValues(Map<String, String> attributes) {
        List<Object> out = new ArrayList<>();
        if (attributes != null) {
            for (Map.Entry<String, String> e : attributes.entrySet()) {
                Map<String, Object> nv = new LinkedHashMap<>();
                nv.put("name", e.getKey());
                nv.put("value", e.getValue());
                out.add(nv);
            }
        }
        return out;
    }

    /** Wrap a payload in the common envelope and encode it canonically. */
    public static byte[] envelope(int unitType, String targetId, Map<String, Object> payload) {
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("unit_type", unitType);
        envelope.put("schema_version", SCHEMA_VERSION);
        envelope.put("target_id", targetId);
        envelope.put("payload", payload);
        // Key order here is irrelevant: the encoder sorts to CTAP2 order itself.
        return CanonicalCbor.encode(envelope);
    }
}

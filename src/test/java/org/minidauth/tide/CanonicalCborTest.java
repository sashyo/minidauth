package org.minidauth.tide;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * These bytes are attested: the ORK re-encodes each unit and compares, so a non-canonical encoding
 * yields a signature mismatch reported nowhere near its cause. The ordering rule is the easy thing
 * to get wrong, so it is pinned explicitly.
 */
class CanonicalCborTest {

    private static final ObjectMapper CBOR = new ObjectMapper(new CBORFactory());

    private static String hex(byte[] b) {
        return java.util.HexFormat.of().formatHex(b);
    }

    @Test
    void integersUseTheirShortestForm() {
        assertEquals("00", hex(CanonicalCbor.encode(0)));
        assertEquals("17", hex(CanonicalCbor.encode(23)));
        assertEquals("1818", hex(CanonicalCbor.encode(24)));
        assertEquals("18ff", hex(CanonicalCbor.encode(255)));
        assertEquals("190100", hex(CanonicalCbor.encode(256)));
        assertEquals("1a00010000", hex(CanonicalCbor.encode(65536)));
    }

    @Test
    void simpleValuesAreTheCanonicalOnes() {
        assertEquals("f6", hex(CanonicalCbor.encode(null)));
        assertEquals("f5", hex(CanonicalCbor.encode(true)));
        assertEquals("f4", hex(CanonicalCbor.encode(false)));
    }

    @Test
    void containersAreDefiniteLength() {
        // 0x82 = array(2) definite; an indefinite array would start 0x9f.
        assertTrue(hex(CanonicalCbor.encode(List.of(1, 2))).startsWith("82"));
        // 0xa1 = map(1) definite; indefinite would be 0xbf.
        assertTrue(hex(CanonicalCbor.encode(Map.of("a", 1))).startsWith("a1"));
    }

    /**
     * CTAP2 sorts keys by <b>length first</b>, then bytewise. Plain lexicographic order would put
     * "attributes" before "last_name"; canonical order does not, because "last_name" is shorter.
     */
    @Test
    void mapKeysSortByLengthThenBytes() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("first_name", 1);   // 10
        m.put("email", 2);        // 5
        m.put("attributes", 3);   // 10
        m.put("last_name", 4);    // 9
        m.put("email_verified", 5); // 14

        byte[] encoded = CanonicalCbor.encode(m);
        String h = hex(encoded);

        int email = h.indexOf(hex("email".getBytes()));
        int lastName = h.indexOf(hex("last_name".getBytes()));
        int attributes = h.indexOf(hex("attributes".getBytes()));
        int firstName = h.indexOf(hex("first_name".getBytes()));
        int verified = h.indexOf(hex("email_verified".getBytes()));

        assertTrue(email < lastName, "shorter keys first");
        assertTrue(lastName < attributes, "9 before 10, even though 'l' > 'a'");
        assertTrue(attributes < firstName, "same length falls back to bytes");
        assertTrue(firstName < verified, "longest last");
    }

    @Test
    void insertionOrderDoesNotAffectTheEncoding() {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("zzz", 1);
        a.put("a", 2);
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("a", 2);
        b.put("zzz", 1);
        assertArrayEquals(CanonicalCbor.encode(a), CanonicalCbor.encode(b),
                "a unit built in a different order must attest identically");
    }

    @Test
    void bytewiseComparisonIsUnsigned() {
        // A naive char comparison would misorder anything above 0x7F.
        assertTrue(CanonicalCbor.compareBytewise("a", "ÿ") < 0);
    }

    @Test
    void anUnsupportedTypeIsRefusedRatherThanGuessed() {
        assertThrows(IllegalArgumentException.class, () -> CanonicalCbor.encode(1.5d));
        assertThrows(IllegalArgumentException.class, () -> CanonicalCbor.encode(Map.of(1, "int key")));
    }

    // ------------------------------------------------------------ the unit itself

    @Test
    void theUserIdentityEnvelopeHasTheFourCommonKeysAndParsesBack() throws Exception {
        byte[] unit = AttestationUnits.userIdentity(
                "vuid-1", "alice", "a@example.com", true, "Alice", "Smith",
                Map.of("dept", List.of("eng")));

        JsonNode e = CBOR.readTree(unit);
        assertEquals(AttestationUnits.USER_IDENTITY, e.get("unit_type").asInt(),
                "unit_type is the enum ordinal, not the name");
        assertEquals(1, e.get("schema_version").asInt());
        assertEquals("vuid-1", e.get("target_id").asText());

        JsonNode p = e.get("payload");
        assertEquals("vuid-1", p.get("user_id").asText());
        assertEquals("alice", p.get("username").asText());
        assertEquals("a@example.com", p.get("email").asText());
        assertTrue(p.get("email_verified").asBoolean());
        assertEquals("Alice", p.get("first_name").asText());
        assertEquals("Smith", p.get("last_name").asText());
        assertEquals("dept", p.get("attributes").get(0).get("name").asText());
        assertEquals("eng", p.get("attributes").get(0).get("values").get(0).asText());
    }

    /** The ORK rejects a unit whose target_id does not match the payload's primary key. */
    @Test
    void theTargetIdMatchesTheUserId() throws Exception {
        JsonNode e = CBOR.readTree(AttestationUnits.userIdentity(
                "vuid-2", null, null, false, null, null, null));
        assertEquals(e.get("payload").get("user_id").asText(), e.get("target_id").asText());
    }

    @Test
    void absentFieldsAreNullNotOmitted() throws Exception {
        JsonNode p = CBOR.readTree(AttestationUnits.userIdentity(
                "vuid-3", null, null, false, null, null, null)).get("payload");
        for (String key : List.of("email", "first_name", "last_name")) {
            assertTrue(p.has(key), key + " must be present");
            assertTrue(p.get(key).isNull(), key + " must be null, not missing");
        }
        assertEquals("vuid-3", p.get("username").asText(), "username falls back to the vuid");
        assertTrue(p.get("attributes").isArray());
        assertEquals(0, p.get("attributes").size());
    }

    @Test
    void aUnitWithoutAUserIdIsRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> AttestationUnits.userIdentity(null, "x", null, false, null, null, null));
        assertThrows(IllegalArgumentException.class,
                () -> AttestationUnits.userIdentity("  ", "x", null, false, null, null, null));
    }

    /**
     * The three units a session-start needs beyond the identity. Two are looked up with
     * {@code .Single()} and the third by client_id, so all three must be present and well-formed.
     */
    @Test
    void theConfigUnitsCarryTheFieldsTheEngineReads() throws Exception {
        JsonNode realm = CBOR.readTree(AttestationUnits.realmConfig("r1", "realm", 300, 1800, 36000, null));
        assertEquals(AttestationUnits.REALM_CONFIG, realm.get("unit_type").asInt());
        assertEquals("r1", realm.get("target_id").asText());
        assertEquals("realm", realm.get("payload").get("name").asText());
        assertEquals(300, realm.get("payload").get("access_token_lifespan_seconds").asLong());
        assertTrue(realm.get("payload").has("offline_session_max_lifespan_enabled"));

        JsonNode client = CBOR.readTree(AttestationUnits.clientConfig(
                "cid", "my-client", true, List.of("https://example.test"), Map.of("a", "b")));
        assertEquals(AttestationUnits.CLIENT_CONFIG, client.get("unit_type").asInt());
        assertEquals("cid", client.get("target_id").asText(), "target_id must equal client_id_uuid");
        assertEquals("my-client", client.get("payload").get("client_id").asText());
        assertEquals("openid-connect", client.get("payload").get("protocol").asText());
        assertEquals("https://example.test", client.get("payload").get("web_origins").get(0).asText());
        // config units use single-valued attributes, unlike an identity's name/values
        assertEquals("b", client.get("payload").get("attributes").get(0).get("value").asText());

        JsonNode scopes = CBOR.readTree(AttestationUnits.clientScopeAssignmentSet("cid", null));
        assertEquals(AttestationUnits.CLIENT_SCOPE_ASSIGNMENT_SET, scopes.get("unit_type").asInt());
        assertEquals("cid", scopes.get("target_id").asText());
        assertTrue(scopes.get("payload").get("assignments").isArray());
        assertEquals(0, scopes.get("payload").get("assignments").size(),
                "an empty assignment list keeps client_scope_config units out of the graph");
    }

    /**
     * Without these the engine rejects every custom claim as having "no attested source", the
     * vendor does not get to state a claim, only to attest the config that would produce it.
     */
    @Test
    void theMapperUnitsDeclareWhatProducesEachClaim() throws Exception {
        JsonNode m = CBOR.readTree(AttestationUnits.attributeMapper(
                "pm-1", "cid", "tideUserKey", "tideuserkey"));
        assertEquals(AttestationUnits.PROTOCOL_MAPPER, m.get("unit_type").asInt());
        assertEquals("pm-1", m.get("target_id").asText(), "target_id must equal protocol_mapper_id");
        assertEquals("client", m.get("payload").get("parent_type").asText(),
                "the ORK parses parent_type by name, case-sensitively");
        assertEquals("cid", m.get("payload").get("parent_id").asText());
        assertEquals("openid-connect", m.get("payload").get("protocol").asText(),
                "a mapper whose protocol differs from the client's fails the whole request");
        assertEquals("oidc-usermodel-attribute-mapper", m.get("payload").get("protocol_mapper").asText());

        // config is a name/value list, and the camelCase attribute is distinct from the
        // lowercase claim it feeds.
        JsonNode config = m.get("payload").get("config");
        java.util.Map<String, String> flat = new java.util.HashMap<>();
        config.forEach(nv -> flat.put(nv.get("name").asText(), nv.get("value").asText()));
        assertEquals("tideUserKey", flat.get("user.attribute"));
        assertEquals("tideuserkey", flat.get("claim.name"));
        assertEquals("true", flat.get("access.token.claim"));

        JsonNode aud = CBOR.readTree(AttestationUnits.audienceMapper("pm-2", "cid", "cid"));
        assertEquals("oidc-audience-mapper", aud.get("payload").get("protocol_mapper").asText());

        JsonNode set = CBOR.readTree(AttestationUnits.clientMapperSet("cid", List.of("pm-1", "pm-2")));
        assertEquals(AttestationUnits.CLIENT_MAPPER_SET, set.get("unit_type").asInt());
        assertEquals("cid", set.get("target_id").asText());
        assertEquals(2, set.get("payload").get("protocol_mapper_ids").size(),
                "a mapper missing from the set never enters mapper assembly");
    }

    /**
     * A role needs three units, not one: what it is, that the user holds it, and that the token may
     * say so. Any one of them missing means the doken's realm_access has no attested source.
     */
    @Test
    void aGrantedRoleNeedsADefinitionAMappingAndAMapper() throws Exception {
        JsonNode def = CBOR.readTree(
                AttestationUnits.roleDefinition("tide-vault-reader", "tide-vault-reader", false, "realm-1"));
        assertEquals(AttestationUnits.ROLE_DEFINITION, def.get("unit_type").asInt());
        assertEquals("tide-vault-reader", def.get("target_id").asText());
        assertFalse(def.get("payload").get("client_role").asBoolean(),
                "only a realm role reaches realm_access");
        assertEquals("realm-1", def.get("payload").get("container_id").asText());

        JsonNode grant = CBOR.readTree(
                AttestationUnits.userRoleMappingSet("vuid-1", List.of("tide-vault-reader")));
        assertEquals(AttestationUnits.USER_ROLE_MAPPING_SET, grant.get("unit_type").asInt());
        assertEquals("vuid-1", grant.get("target_id").asText(),
                "the set is looked up by user id, so target_id must be the vuid");
        assertEquals("tide-vault-reader", grant.get("payload").get("role_ids").get(0).asText());

        JsonNode mapper = CBOR.readTree(AttestationUnits.realmRoleMapper("pm-roles", "cid"));
        java.util.Map<String, String> config = new java.util.HashMap<>();
        mapper.get("payload").get("config").forEach(
                nv -> config.put(nv.get("name").asText(), nv.get("value").asText()));
        assertEquals("realm_access.roles", config.get("claim.name"),
                "the dot is what nests the array under realm_access");
        assertEquals("true", config.get("multivalued"));
        assertEquals("oidc-usermodel-realm-role-mapper",
                mapper.get("payload").get("protocol_mapper").asText());
    }

    @Test
    void theSameUnitEncodesIdenticallyEveryTime() {
        byte[] a = AttestationUnits.userIdentity("v", "u", null, false, null, null, null);
        byte[] b = AttestationUnits.userIdentity("v", "u", null, false, null, null, null);
        assertArrayEquals(a, b, "attested bytes must be reproducible or the signature cannot be rechecked");
    }
}

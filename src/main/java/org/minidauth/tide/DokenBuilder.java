package org.minidauth.tide;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.stream.Collectors;

/**
 * Assembles a doken byte-for-byte the way the ORK does.
 *
 * <p><b>Why this is hand-rolled instead of using a JSON library.</b> The ORK builds its own copy of
 * the doken from the access token it is handed, signs <em>that</em>, and returns only the signature.
 * The token this service then hands to the browser must therefore reproduce the ORK's bytes exactly
 *, a different field order, a space after a colon, or an omitted-versus-empty claim all yield a
 * token whose signature does not verify, and the failure surfaces much later as an opaque
 * "Doken signature failed". A serializer that guarantees field order and spacing is the only way to
 * be sure, so this mirrors {@code Cryptide/Models/Doken.cs GetDataToSign()} literally.
 *
 * <p>The rules that are easy to get wrong, all taken from that method:
 * <ul>
 *   <li>{@code t.ssk} and {@code t.uho} are omitted entirely when absent, not emitted as null.</li>
 *   <li>{@code realm_access} and {@code resource_access} are emitted <b>unconditionally</b>,
 *       defaulting to {@code {}}. The C# comment records a real bug from getting this wrong: the
 *       signer omitted an absent claim while the delivered token carried {@code {}}.</li>
 *   <li>{@code resource_access} is last, and {@code exp} is a bare number, not a string.</li>
 * </ul>
 */
public final class DokenBuilder {

    /** The header is fixed; the ORK writes these two fields in this order. */
    private static final String HEADER_JSON = "{\"alg\":\"EdDSA\",\"typ\":\"doken\"}";

    /** An absent access map is the empty object, never an omitted field. */
    public static final String EMPTY_ACCESS = "{}";

    private String sessionKey;
    private String sessionId;
    private String userKey;
    private String vuid;
    private String homeOrk;
    private long expiresAt;
    private long issuedAt;
    private String audience;
    private String realmAccess = EMPTY_ACCESS;
    private String resourceAccess = EMPTY_ACCESS;

    /** @param sessionKey the browser's session public key, as the enclave reported it */
    public DokenBuilder sessionKey(String sessionKey) {
        this.sessionKey = sessionKey;
        return this;
    }

    /**
     * The enclave sign-in's session id.
     *
     * <p>Required on the <b>access token</b>: the ORK asserts it equals the session id inside the
     * blind-signed auth request before it will sign anything, which is what binds the token to
     * <em>this</em> sign-in rather than to any session the vendor cares to name. Like {@code iat} it
     * is not part of the doken's signed payload, the ORK's own copy never carries it.
     *
     * <p>It needs no attested mapper for the same reason: the value is authenticated at the request
     * layer, out of band from the attestation units.
     */
    public DokenBuilder sessionId(String sessionId) {
        this.sessionId = sessionId;
        return this;
    }

    public DokenBuilder userKey(String userKey) {
        this.userKey = userKey;
        return this;
    }

    public DokenBuilder vuid(String vuid) {
        this.vuid = vuid;
        return this;
    }

    public DokenBuilder homeOrk(String homeOrk) {
        this.homeOrk = homeOrk;
        return this;
    }

    /** Epoch seconds. Emitted as a bare number. */
    public DokenBuilder expiresAt(long expiresAt) {
        this.expiresAt = expiresAt;
        return this;
    }

    /**
     * Epoch seconds the token was issued.
     *
     * <p>Required on the <b>access token</b>, the ORK refuses the request with
     * "iat missing from token" without it. It is deliberately <b>not</b> part of the doken's own
     * signed payload, which carries no {@code iat} at all.
     */
    public DokenBuilder issuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
        return this;
    }

    /** The vvkId. The ORK sets this from the vendor's own user id. */
    public DokenBuilder audience(String audience) {
        this.audience = audience;
        return this;
    }

    /**
     * Realm roles, rendered as {@code {"roles":["a","b"]}}, or {@code {}} when there are none.
     *
     * <p>This is the claim a Forseti contract reads to decide who may decrypt, so the set handed in
     * here must be the governed grant record, never something the calling application asserted.
     */
    public DokenBuilder realmRoles(Collection<String> roles) {
        this.realmAccess = rolesJson(roles);
        return this;
    }

    public DokenBuilder realmAccessJson(String json) {
        this.realmAccess = (json == null || json.isBlank()) ? EMPTY_ACCESS : json;
        return this;
    }

    public DokenBuilder resourceAccessJson(String json) {
        this.resourceAccess = (json == null || json.isBlank()) ? EMPTY_ACCESS : json;
        return this;
    }

    /** {@code {"roles":["a","b"]}}, or {@code {}} for an empty set. No spaces. */
    public static String rolesJson(Collection<String> roles) {
        if (roles == null || roles.isEmpty()) return EMPTY_ACCESS;
        return "{\"roles\":[" + roles.stream()
                .map(DokenBuilder::quote)
                .collect(Collectors.joining(",")) + "]}";
    }

    /** The claims the ORK must see on the access token so its own copy matches this one. */
    public String accessTokenPayloadJson() {
        StringBuilder b = new StringBuilder("{");
        b.append("\"tideuserkey\":").append(quote(userKey)).append(',');
        b.append("\"vuid\":").append(quote(vuid)).append(',');
        if (homeOrk != null) {
            b.append("\"t.uho\":").append(quote(homeOrk)).append(',');
        }
        if (sessionId != null) {
            b.append("\"sid\":").append(quote(sessionId)).append(',');
        }
        b.append("\"iat\":").append(issuedAt).append(',');
        b.append("\"exp\":").append(expiresAt).append(',');
        b.append("\"aud\":").append(quote(audience));
        // Emitted only when non-empty. The ORK's own copy of the doken defaults an absent access
        // claim to {} (Doken.cs), which is what dataToSign() writes unconditionally, so omitting an
        // empty one here still yields identical signed bytes. It has to be omitted, because on the
        // access surface realm_access is mapper-derived: asserting {} with no attested role mapper
        // behind it is an unbacked claim and the engine rejects the whole request.
        if (!EMPTY_ACCESS.equals(realmAccess)) {
            b.append(",\"realm_access\":").append(realmAccess);
        }
        if (!EMPTY_ACCESS.equals(resourceAccess)) {
            b.append(",\"resource_access\":").append(resourceAccess);
        }
        return b.append('}').toString();
    }

    /**
     * A two-segment {@code header.payload} access token.
     *
     * <p>The ORK's {@code ToParseableJws} appends the empty signature segment itself, so no
     * signature is needed, the ORK is being told what to sign, not shown something already signed.
     */
    public String accessTokenJws() {
        return b64(HEADER_JSON) + "." + b64(accessTokenPayloadJson());
    }

    /**
     * The exact bytes the ORK signs: {@code base64url(header).base64url(payload)}.
     *
     * <p>Mirrors {@code Doken.GetDataToSign()}.
     */
    public String dataToSign() {
        StringBuilder b = new StringBuilder("{");
        if (sessionKey != null) {
            b.append("\"t.ssk\":").append(quote(sessionKey)).append(',');
        }
        b.append("\"tideuserkey\":").append(quote(userKey)).append(',');
        b.append("\"vuid\":").append(quote(vuid)).append(',');
        if (homeOrk != null) {
            b.append("\"t.uho\":").append(quote(homeOrk)).append(',');
        }
        b.append("\"exp\":").append(expiresAt).append(',');
        b.append("\"aud\":").append(quote(audience));
        b.append(",\"realm_access\":").append(realmAccess);
        b.append(",\"resource_access\":").append(resourceAccess);
        b.append('}');

        return b64(HEADER_JSON) + "." + b64(b.toString());
    }

    /** The finished token, with the cohort's signature attached. */
    public String build(String base64UrlSignature) {
        if (base64UrlSignature == null || base64UrlSignature.isBlank()) {
            throw new IllegalArgumentException("A doken cannot be assembled without its signature");
        }
        return dataToSign() + "." + toBase64Url(base64UrlSignature);
    }

    /** The cohort returns standard base64; a JWT segment needs base64url without padding. */
    static String toBase64Url(String base64) {
        return base64.replace('+', '-').replace('/', '_').replaceAll("=+$", "");
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    /** Minimal JSON string escaping. These values are keys, ids and role names, not free text. */
    private static String quote(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        return b.append('"').toString();
    }
}

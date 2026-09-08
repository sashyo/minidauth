package org.minidauth.tide;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.midgard.Midgard;
import org.midgard.models.ModelRequest;
import org.midgard.models.SignatureResponse;
import org.midgard.models.AuthRequest;
import org.midgard.models.TideAuthData;
import org.midgard.models.TokenType;
import org.midgard.models.TokenRequest;
import org.midgard.models.RequestExtensions.TidecloakSessionStartTokenSignRequest;
import org.midgard.models.RequestExtensions.AttestationUnitSignRequest;
import org.midgard.models.RequestExtensions.UserIdentityAttestationUnitSignRequest;
import org.midgard.models.VendorData;
import org.midgard.models.VendorSettings;
import org.minidauth.Log;
import org.minidauth.store.VendorKeyStore;
import org.minidauth.vrk.Trace;
import org.minidauth.vrk.VrkLifecycle;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The VRK-dependent half of a Tide sign-in.
 *
 * <p>The browser talks to the enclave directly; this service does only the parts that need the
 * private VRK, which is the reason the split exists at all:
 *
 * <ul>
 *   <li><b>sign the settings + redirect URIs</b>, a {@code TidecloakUpdateSettings:1} ceremony.
 *       The enclave verifies the served settings blob byte-for-byte and refuses to return to a URI
 *       it has no signature for.</li>
 *   <li><b>build the enclave URL</b>, assembled here so a caller cannot substitute its own
 *       authorizer pack or redirect.</li>
 *   <li><b>decrypt the callback payload</b>, {@code DecryptVendorData} needs the VRK.</li>
 *   <li><b>issue vouchers</b>, {@code GetVouchers} needs the VRK.</li>
 * </ul>
 */
public final class TideAuthService {
    private static final Log log = Log.of(TideAuthService.class);

    /** Config keys for the ceremony's output, stored alongside the key material. */
    public static final String SETTINGS_SIGNED_BLOB = "settingsSignedBlob";
    public static final String SETTINGS_SIG = "settingsSig";
    /** Prefix for a per-redirect-URI signature: {@code redirectSig:<uri>}. */
    public static final String REDIRECT_SIG_PREFIX = "redirectSig:";
    /** Prefix for a per-client-origin signature: {@code originSig:<origin>}. */
    public static final String ORIGIN_SIG_PREFIX = "originSig:";
    public static final String ENCLAVE_TYPE = "enclaveType";

    /**
     * The enclave entry the browser is sent to for sign-in.
     *
     * <p>The enclave dispatches on this and throws "Enclave not found" for anything it does not
     * recognise. The registered entries are {@code cmkOnly} (sign-in / registration),
     * {@code request} (the hidden iframe that performs crypto), {@code approval} / {@code approvalNew},
     * and {@code dpopApproval}.
     */
    /**
     * Mapper ids. Stable strings rather than random uuids: the ORK keys attested units by
     * (type, target), so a fresh id each session would only churn the graph.
     */
    private static final String MAPPER_TIDE_USER_KEY = "mc-pm-tideuserkey";
    private static final String MAPPER_VUID = "mc-pm-vuid";
    private static final String MAPPER_AUDIENCE = "mc-pm-audience";
    private static final String MAPPER_REALM_ROLES = "mc-pm-realm-roles";

    private static final String DEFAULT_ENCLAVE_TYPE = "cmkOnly";

    /** How long a minted session doken is good for. */
    private static final long SESSION_TTL_SECONDS = 8 * 60 * 60;

    private final ObjectMapper mapper = new ObjectMapper();
    private final VendorKeyStore store;
    private final VrkLifecycle vrk;
    /**
     * Where the doken's realm roles come from.
     *
     * <p>A function rather than a direct dependency so the authority stays explicit at the wiring
     * point: this must be the governed grant record, never anything the calling application
     * asserted about its own user.
     */
    private final java.util.function.Function<String, java.util.Set<String>> rolesForVuid;

    /**
     * The cohort-signed role units for an identity, as stored when the grant was committed.
     *
     * <p>Replayed rather than rebuilt. Rebuilding them here from the local role list would mean
     * anyone able to edit that list could mint themselves any role, since the units would be freshly
     * signed and verify perfectly.
     */
    private final java.util.function.Function<String, java.util.List<String[]>> signedRoleUnitsFor;

    /**
     * Asks the cohort to sign attestation units, by whichever route is currently available.
     *
     * <p>Owned by governance rather than here, because the choice depends on which policies are
     * deployed: the VRK pack during bootstrap, a policy once one exists. Minting a token must not
     * care which.
     */
    private final UnitSigner unitSigner;

    /** Signs attestation units, returning one base64 signature per unit. */
    @FunctionalInterface
    public interface UnitSigner {
        String[] sign(byte[][] units) throws Exception;
    }

    public TideAuthService(VendorKeyStore store, VrkLifecycle vrk,
                           java.util.function.Function<String, java.util.Set<String>> rolesForVuid,
                           java.util.function.Function<String, java.util.List<String[]>> signedRoleUnitsFor,
                           UnitSigner unitSigner) {
        this.store = store;
        this.vrk = vrk;
        this.rolesForVuid = rolesForVuid;
        this.signedRoleUnitsFor = signedRoleUnitsFor;
        this.unitSigner = unitSigner;
    }

    // ============================================================ settings ceremony

    /**
     * Sign the vendor settings and every redirect URI in one {@code TidecloakUpdateSettings:1}
     * ceremony, then store the results.
     *
     * <p>The signature list comes back positionally: one per URI in the order sent, then one per
     * client origin, and the settings signature <b>last</b>. This service declares no client
     * origins, so it is {@code n} URI signatures followed by the settings signature.
     *
     * <p>The stored blob is built in the ORK's own C# field order
     * ({@code RegOn, BackupOn, LogoURL, ImageURL}) and served verbatim afterwards. Reconstructing it
     * per request is the latent bug TideCloak documents: the enclave verifies the served bytes
     * against the signature, so a re-serialisation in a different field order fails to verify.
     */
    public synchronized Map<String, Object> signSettings(EnclaveSettings settings) throws Exception {
        Trace.start();
        if (settings.redirectUris == null || settings.redirectUris.isEmpty()) {
            throw new IllegalArgumentException("At least one redirect URI is required");
        }
        for (String uri : settings.redirectUris) {
            URI.create(uri); // reject a malformed URI before it reaches the cohort
        }

        // The draft the ORK signs. Field order inside vendorSettings is irrelevant, the ORK
        // re-serialises in C# declaration order before signing, but the three-part pipe framing
        // and the URI ordering are not.
        List<String> origins = settings.clientOrigins == null ? List.of() : settings.clientOrigins;
        for (String origin : origins) {
            URI.create(origin);
        }

        VendorSettings vendorSettings = new VendorSettings(
                settings.regOn, settings.backupOn, settings.imageUrl, settings.logoUrl);
        String vendorSettingsString = mapper.writeValueAsString(vendorSettings);
        String jsonUrls = mapper.writeValueAsString(settings.redirectUris);
        String clientJsonUrls = mapper.writeValueAsString(origins);
        String draft = jsonUrls + "|" + clientJsonUrls + "|" + vendorSettingsString;

        ModelRequest req = ModelRequest.New("TidecloakUpdateSettings", "1", "VRK:1",
                draft.getBytes(StandardCharsets.UTF_8));
        SignatureResponse response = vrk.signWithVrk(req);

        // Signatures come back positionally: one per redirect URI in the order sent, then one per
        // client origin, then the settings signature last.
        int expected = settings.redirectUris.size() + origins.size() + 1;
        if (response.Signatures.length < expected) {
            throw new IllegalStateException("Tide network returned " + response.Signatures.length
                    + " signatures for " + settings.redirectUris.size() + " redirect URIs and "
                    + origins.size() + " client origins; expected at least " + expected);
        }

        for (int i = 0; i < settings.redirectUris.size(); i++) {
            store.put(REDIRECT_SIG_PREFIX + settings.redirectUris.get(i), response.Signatures[i]);
        }
        for (int i = 0; i < origins.size(); i++) {
            store.put(ORIGIN_SIG_PREFIX + origins.get(i),
                    response.Signatures[settings.redirectUris.size() + i]);
        }
        // The settings signature is always last, however many URIs were sent.
        store.put(SETTINGS_SIG, response.Signatures[response.Signatures.length - 1]);

        ObjectNode blob = mapper.createObjectNode();
        blob.put("RegOn", settings.regOn);
        blob.put("BackupOn", settings.backupOn);
        blob.put("LogoURL", settings.logoUrl);
        blob.put("ImageURL", settings.imageUrl);
        store.put(SETTINGS_SIGNED_BLOB, blob.toString());
        store.put(ENCLAVE_TYPE, DEFAULT_ENCLAVE_TYPE);
        store.commit();

        log.info("Signed enclave settings and %d redirect URI(s)", settings.redirectUris.size());

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("signedSettings", blob.toString());
        out.put("settingsSignature", store.get(SETTINGS_SIG));
        out.put("redirectUris", settings.redirectUris);
        out.put("clientOrigins", origins);
        return out;
    }

    // ================================================================ enclave URL

    /** Everything a client needs to know about the enclave. No private material. */
    public synchronized Map<String, Object> enclaveConfig() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("homeOrkUrl", store.get(VendorKeyStore.SYSTEM_HOME_ORK_URL));
        out.put("gVVK", store.get(VendorKeyStore.VVK_PUBLIC));
        out.put("vvkId", store.get(VendorKeyStore.VENDOR_ID));
        out.put("gVRK", store.get(VendorKeyStore.GVRK));
        out.put("gVRKSignature", store.get(VendorKeyStore.GVRK_SIG));
        out.put("signedSettings", store.get(SETTINGS_SIGNED_BLOB));
        out.put("settingsSignature", store.get(SETTINGS_SIG));
        out.put("enclaveType", store.get(ENCLAVE_TYPE) == null ? DEFAULT_ENCLAVE_TYPE : store.get(ENCLAVE_TYPE));
        out.put("settingsSigned", store.get(SETTINGS_SIGNED_BLOB) != null);
        List<String> signedUris = new ArrayList<>();
        List<String> signedOrigins = new ArrayList<>();
        for (String k : store.keys()) {
            if (k.startsWith(REDIRECT_SIG_PREFIX)) signedUris.add(k.substring(REDIRECT_SIG_PREFIX.length()));
            if (k.startsWith(ORIGIN_SIG_PREFIX)) signedOrigins.add(k.substring(ORIGIN_SIG_PREFIX.length()));
        }
        out.put("signedRedirectUris", signedUris);
        out.put("signedClientOrigins", signedOrigins);
        return out;
    }

    /**
     * Build the URL the browser is sent to.
     *
     * <p>Assembled here rather than in the client so the authorizer pack, the settings blob and the
     * redirect signature all come from this service's own state, a caller can choose the session
     * id and which registered redirect to use, and nothing else.
     */
    public synchronized URI loginUrl(String sessionId, String redirectUri, String voucherUrl,
                                     String extraQuery, String enclaveType) throws Exception {
        requireSettingsSigned();
        String redirectSig = store.get(REDIRECT_SIG_PREFIX + redirectUri);
        if (redirectSig == null) {
            throw new IllegalArgumentException("Redirect URI '" + redirectUri
                    + "' has no signature. Register it with POST /tide/enclave/settings first, the "
                    + "enclave refuses to return to an unsigned URI.");
        }
        return Midgard.CreateURL(
                sessionId,
                redirectUri,
                redirectSig,
                store.get(VendorKeyStore.SYSTEM_HOME_ORK_URL),
                store.get(VendorKeyStore.VVK_PUBLIC),
                store.get(VendorKeyStore.GVRK),
                store.get(VendorKeyStore.GVRK_SIG),
                store.get(SETTINGS_SIGNED_BLOB),
                enclaveType == null || enclaveType.isBlank()
                        ? (store.get(ENCLAVE_TYPE) == null ? DEFAULT_ENCLAVE_TYPE : store.get(ENCLAVE_TYPE))
                        : enclaveType,
                store.get(SETTINGS_SIG),
                voucherUrl,
                extraQuery);
    }

    /**
     * The enclave types this service will build a URL for.
     *
     * <p>An allow-list rather than a passthrough. The type selects which flow the enclave runs, and
     * an unrecognised one produces "Enclave not found" from inside the iframe, where the reason is
     * invisible to everything outside it.
     */
    private static final java.util.Set<String> ENCLAVE_TYPES =
            java.util.Set.of("cmkOnly", "request", "approval", "approvalNew", "dpopApproval");

    /** Refuse an unknown enclave type here, where the message can still be read. */
    public static String requireEnclaveType(String type) {
        if (type == null || type.isBlank()) return null;
        if (!ENCLAVE_TYPES.contains(type)) {
            throw new IllegalArgumentException("Unknown enclave type '" + type + "'; expected one of "
                    + String.join(", ", ENCLAVE_TYPES));
        }
        return type;
    }

    // ================================================================== callback

    /**
     * Turn an enclave callback into a Tide identity.
     *
     * <p>{@code DecryptVendorData} needs the VRK, so it can only happen here. {@code VerifySignIn}
     * then checks the blind signature over the session, it is what makes the returned vuid a
     * proven identity rather than a value the browser chose.
     */
    public synchronized SignInResult verifySignIn(String encryptedVendorData, String sessionId,
                                                  String knownUserPublic) throws Exception {
        Trace.start();
        String vrkKey = store.getVRK();
        if (vrkKey == null) throw new IllegalStateException("No active VRK, create the vendor key first");

        VendorData vendorData = Midgard.DecryptVendorData(encryptedVendorData, vrkKey);

        // Both the identity and, on a first link, the key to check it against come out of the
        // decrypted payload. A returning user should be checked against the key stored at link
        // time instead, so a later enclave response cannot quietly present a different one.
        String vuid = vendorData.VUID;
        if (vuid == null || vuid.isBlank()) {
            throw new IllegalStateException("The enclave payload carried no VUID");
        }
        String userPublic = (knownUserPublic == null || knownUserPublic.isBlank())
                ? vendorData.gCMKAuth
                : knownUserPublic;
        if (userPublic == null || userPublic.isBlank()) {
            throw new IllegalStateException("No user public key: the payload carried no gCMKAuth and "
                    + "no previously stored key was supplied");
        }

        // Throws if the blind signature does not verify. This is what makes the vuid a proven
        // identity rather than a value the browser chose.
        String authData = Midgard.VerifySignIn(vuid, userPublic, sessionId, vendorData);

        // Cosmetic only, and optional on purpose. JNA resolves symbols lazily, so a jar paired with
        // a native library that predates this export throws UnsatisfiedLinkError, an Error, not an
        // Exception, which would otherwise kill the worker thread and drop the connection with no
        // response at all. A missing display name must not cost a successful sign-in.
        String tideUsername = null;
        try {
            tideUsername = Midgard.GetTideUsername(vuid);
        } catch (Throwable t) {
            log.warn("Could not derive a Tide username (%s); continuing without one", t.getMessage());
        }

        String doken = mintDoken(authData, vuid, userPublic);

        log.info("Verified Tide sign-in for vuid %s and minted a session doken", vuid);
        return new SignInResult(vuid, tideUsername == null ? "" : tideUsername, userPublic, authData, doken);
    }

    /**
     * Mint the session doken from the sign-in proof.
     *
     * <p>This can only happen here. {@code TidecloakSessionStartTokenSign:1} consumes the blind
     * signature the enclave just produced, so a doken cannot be issued by some later standalone
     * call, the proof is spent at login or not at all.
     *
     * <p>The session key is <b>not</b> chosen by this service or by the caller: the enclave and the
     * browser establish it, and it arrives inside the auth request. The ORK binds the doken to it,
     * which is what makes a captured doken useless to anyone who does not hold the private half.
     */
    private String mintDoken(String authData, String vuid, String userPublic) throws Exception {
        TideAuthData tideAuthData = TideAuthData.From(authData);
        AuthRequest authRequest = AuthRequest.From(tideAuthData.AuthRequest);
        if (authRequest.Key == null || authRequest.Key.isBlank()) {
            throw new IllegalStateException("The enclave auth request carried no session key, so a "
                    + "doken could not be bound to this browser");
        }

        String vvkId = store.get(VendorKeyStore.VENDOR_ID);
        long exp = Instant.now().getEpochSecond() + SESSION_TTL_SECONDS;

        // The roles come from the governed grant record. Sourcing them from the application would
        // mean a write to the app's database granted decryption rights, and the ORKs would enforce
        // that faithfully because the signature would be perfectly valid.
        // Read the governed grant ONCE. The token's realm_access and the attested role units must
        // agree exactly, the ORK compares them, so they cannot come from two separate reads.
        java.util.List<String> roles = new java.util.ArrayList<>(rolesForVuid.apply(vuid));

        DokenBuilder builder = new DokenBuilder()
                .sessionKey(authRequest.Key)
                // Binds the token to this sign-in: the ORK checks it against the session id inside
                // the blind-signed auth request before it will sign.
                .sessionId(authRequest.SessionId)
                .userKey(userPublic)
                .vuid(vuid)
                // No t.uho: the home-ORK claim has no mapper behind it, and every claim on the
                // access token must trace back to an attested source or the request is refused.
                .issuedAt(Instant.now().getEpochSecond())
                .expiresAt(exp)
                .audience(vvkId)
                .realmRoles(roles);

        // The ORK validates the token's claims against attested units and refuses a request that
        // carries none ("Sequence contains no elements"). A vendor cannot simply assert who a user
        // is, the identity has to be attested by the cohort first.
        byte[] identityEnvelope = AttestationUnits.selfRegisteredIdentity(vuid, userPublic);
        byte[] identitySignature = signAttestationUnit(identityEnvelope, tideAuthData);

        // The validation engine resolves the realm and the requesting client from attested config
        // before it will look at a single claim, so the identity alone is not enough. These three
        // are the minimum: two are unconditional .Single() lookups and the third is matched by
        // client_id. The scope assignments are deliberately empty, the engine only dereferences
        // client_scope_config units while walking assignments, so an empty list keeps a whole
        // further tier of units out of the picture.
        byte[] realmEnvelope = AttestationUnits.realmConfig(
                vvkId, vvkId, SESSION_TTL_SECONDS, SESSION_TTL_SECONDS, SESSION_TTL_SECONDS, null);
        byte[] clientEnvelope = AttestationUnits.clientConfig(
                vvkId, vvkId, true, java.util.List.of(), null);
        byte[] scopeEnvelope = AttestationUnits.clientScopeAssignmentSet(vvkId, null);

        // Every claim the token carries beyond the structural ones (iat, exp) must be produced by
        // an attested mapper, or the engine rejects it as having "no attested source". The vendor
        // does not get to state a claim; it has to attest the configuration that would produce it.
        // tideuserkey and vuid are projected from the identity unit's attributes, and aud is
        // mapper-derived on the access surface, it is not a base claim there.
        byte[] userKeyMapper = AttestationUnits.attributeMapper(
                MAPPER_TIDE_USER_KEY, vvkId, AttestationUnits.ATTR_TIDE_USER_KEY, "tideuserkey");
        byte[] vuidMapper = AttestationUnits.attributeMapper(
                MAPPER_VUID, vvkId, AttestationUnits.ATTR_VUID, "vuid");
        byte[] audienceMapper = AttestationUnits.audienceMapper(MAPPER_AUDIENCE, vvkId, vvkId);

        // Roles, when the governed record grants any. Three units are needed, not one: what each
        // role IS (role_definition), that this user HOLDS it (user_role_mapping_set), and that the
        // token may SAY so (the realm-role mapper). Splitting it that way is what stops a grant
        // naming a role nobody ever defined, and stops a token claiming a role nobody granted.
        java.util.List<byte[]> units = new java.util.ArrayList<>(
                java.util.List.of(realmEnvelope, clientEnvelope, scopeEnvelope,
                        userKeyMapper, vuidMapper, audienceMapper));
        java.util.List<String[]> preSigned = java.util.List.of();
        java.util.List<String> mapperIds = new java.util.ArrayList<>(
                java.util.List.of(MAPPER_TIDE_USER_KEY, MAPPER_VUID, MAPPER_AUDIENCE));

        if (!roles.isEmpty()) {
            // The role units were signed when the grant was committed, so they are replayed here
            // rather than rebuilt. That is what stops the local grant file being an authority: edit
            // it and these bytes no longer match, so the cohort refuses.
            preSigned = signedRoleUnitsFor.apply(vuid);
            if (preSigned == null || preSigned.isEmpty()) {
                throw new IllegalStateException("Identity " + vuid + " holds roles with no attested "
                        + "units behind them. The grant record was written without being attested, "
                        + "or has been altered; re-commit the grant.");
            }
            units.add(AttestationUnits.realmRoleMapper(MAPPER_REALM_ROLES, vvkId));
            mapperIds.add(MAPPER_REALM_ROLES);
        }

        units.add(AttestationUnits.clientMapperSet(vvkId, mapperIds));
        byte[][] configUnits = units.toArray(new byte[0][]);
        String[] configSignatures = signConfigUnits(configUnits);

        TidecloakSessionStartTokenSignRequest req = new TidecloakSessionStartTokenSignRequest();
        // The ORK rebuilds the doken from these claims and signs its own copy, so the access token
        // must carry exactly what the builder will render locally.
        req.AddRequestedAccessToken(builder.accessTokenJws(),
                new TokenRequest(TokenType.AccessToken, vvkId, "openid"));
        req.AddAttestedUnit(identityEnvelope, identitySignature);
        for (int i = 0; i < configUnits.length; i++) {
            req.AddAttestedUnit(configUnits[i], Base64.getDecoder().decode(configSignatures[i]));
        }
        // The role units travel exactly as the cohort signed them.
        for (String[] signed : preSigned) {
            req.AddAttestedUnit(Base64.getDecoder().decode(signed[0]),
                    Base64.getDecoder().decode(signed[1]));
        }
        req.AddTideUserAuthentication(tideAuthData, null);

        SignatureResponse response = vrk.signWithVrk(req);
        String dokenSignature = req.ProcessSignatures(response.Signatures).GetDokenSignature();
        if (dokenSignature == null || dokenSignature.isBlank()) {
            throw new IllegalStateException("The Tide network returned no doken signature");
        }
        return builder.build(dokenSignature);
    }

    /**
     * Ask the cohort for one VVK signature over an attestation unit.
     *
     * <p>Self-registration mode: the unit travels with the same sign-in proof that authorised this
     * callback, plus the signed settings blob. The ORK signs exactly the envelope bytes given, which
     * is why they must be canonically encoded, see {@link CanonicalCbor}.
     */
    private byte[] signAttestationUnit(byte[] envelope, TideAuthData tideAuthData) throws Exception {
        requireSettingsSigned();

        UserIdentityAttestationUnitSignRequest req = new UserIdentityAttestationUnitSignRequest();
        req.SetUserIdentityEnvelope(envelope);
        req.SetTideAuth(tideAuthData.AuthRequest, Base64.getDecoder().decode(tideAuthData.BlindSig));
        req.SetSignedSettings(
                store.get(SETTINGS_SIGNED_BLOB).getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode(store.get(SETTINGS_SIG)));

        SignatureResponse response = vrk.signWithVrk(req);
        if (response.Signatures == null || response.Signatures.length == 0) {
            throw new IllegalStateException(
                    "The Tide network returned no signature for the identity attestation unit");
        }
        return Base64.getDecoder().decode(response.Signatures[0]);
    }

    /**
     * Ask the cohort for one VVK signature per config unit, in one ceremony.
     *
     * <p>Uses the generic {@code AttestationUnit:1} model rather than the user-identity one: these
     * units are vendor configuration, not an admitted identity, so they carry no sign-in proof.
     *
     * <p>Authorized by the <b>firstAdmin</b> pack. The main VRK cannot carry this model at all, the
     * ORK refuses the wallet with "Main VRK cannot allow AttestationUnit:1 model", because the key
     * that speaks to the swarm is deliberately not the key that attests configuration.
     */
    private String[] signConfigUnits(byte[][] units) throws Exception {
        return unitSigner.sign(units);
    }

    // ================================================================== vouchers

    /** The enclave asks for a voucher mid-flow; issuing one needs the VRK. */
    public synchronized String vouchers(String voucherRequest) {
        String vrkKey = store.getVRK();
        if (vrkKey == null) throw new IllegalStateException("No active VRK, create the vendor key first");
        return Midgard.GetVouchers(
                voucherRequest,
                store.get(VendorKeyStore.VVK_PUBLIC),
                store.get(VendorKeyStore.SYSTEM_PAYER_PUBLIC),
                vrkKey);
    }

    /**
     * The signature authorising {@code origin} to hold a postMessage channel with the enclave.
     *
     * <p>Returned to the browser deliberately: it is a signature over a public origin, it grants
     * nothing on its own, and the enclave will not open the channel without it.
     */
    public synchronized String originSignature(String origin) {
        String sig = store.get(ORIGIN_SIG_PREFIX + origin);
        if (sig == null) {
            throw new IllegalArgumentException("Origin '" + origin + "' is not signed. Register it "
                    + "in clientOrigins via POST /tide/enclave/settings, the enclave refuses a "
                    + "channel with an origin it cannot verify.");
        }
        return sig;
    }

    private void requireSettingsSigned() {
        if (store.get(SETTINGS_SIGNED_BLOB) == null || store.get(SETTINGS_SIG) == null) {
            throw new IllegalStateException("Enclave settings have not been signed. "
                    + "POST /tide/enclave/settings first, the enclave verifies the settings blob "
                    + "byte-for-byte and rejects an unsigned one.");
        }
    }

    /**
     * @param vuid       the proven Tide identity
     * @param userPublic the user's key this sign-in was checked against, store it and pass it back
     *                   on the next link so a later response cannot substitute a different key
     * @param authData   the blind-signature proof
     */
    public record SignInResult(String vuid, String tideUsername, String userPublic, String authData,
                               String doken) {}

    /** Base64 of the VRK's signature over an arbitrary message. Used for ad-hoc binding. */
    public synchronized String signWithVrk(String message) {
        String vrkKey = store.getVRK();
        if (vrkKey == null) throw new IllegalStateException("No active VRK");
        return Base64.getEncoder().encodeToString(Midgard.SignWithVrk(message, vrkKey));
    }
}

package org.minidauth.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.midgard.models.SignRequestSettingsMidgard;
import org.minidauth.Log;
import org.minidauth.vrk.LicenseState;
import org.minidauth.vrk.VendorKeyState;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * The vendor key material and its lifecycle state.
 *
 * <p>A port of TideCloak's {@code TideLicenseComponentManager}: the same config keys, the same
 * derived-state rules, and the same working-copy / committed-snapshot discipline, but persisted
 * to a JSON file instead of a Keycloak {@code tide-vendor-key} component.
 *
 * <p><b>The snapshot discipline is load bearing.</b> Mutators write to the working copy only.
 * {@link #commit()} makes them durable; {@link #rollback()} discards them. A minted VRK is the
 * only handle on a wallet that now exists on the ORK network, so it must be committed before any
 * further remote call can fail and roll the rest back.
 */
public final class VendorKeyStore {
    private static final Log log = Log.of(VendorKeyStore.class);

    // --- Config keys. Identical to TideLicenseComponentManager's, for interop. ---
    public static final String SYSTEM_HOME_ORK_URL = "systemHomeOrk";
    public static final String SYSTEM_PAYER_PUBLIC = "payerPublic";
    public static final String REALM_CUSTOMER_ID = "customerId";
    public static final String REALM_MAX_USER_COUNT = "maxUserAcc";
    public static final String CLIENT_SECRET = "clientSecret";
    public static final String VENDOR_ID = "vvkId";
    public static final String SUBSCRIPTION_ID = "subscriptionId";
    public static final String INITIAL_STRIPE_SESS_ID = "initialSessionId";
    public static final String PENDING_GVRK = "pendingGVRK";
    public static final String PENDING_GVRK_SIG = "pendingGVRKSignature";
    public static final String PENDING_YTMP = "pendingYtmp";
    public static final String OBF_GVVK = "obfGVVK";
    public static final String BACKUP_ON = "backupOn";
    public static final String AUTHORIZER = "authorizer";
    public static final String AUTHORIZER_SIG = "authorizerCertificate";
    public static final String GVRK_SIG = "gVRKCertificate";
    public static final String VVK_PUBLIC = "clientId";
    public static final String ENCRYPTED_VVK = "eVVK";
    public static final String PENDING_WALLET_ID = "pendingWalletId";
    public static final String WALLET_ID = "walletId";
    public static final String GVRK = "gVRK";
    public static final String LATEST_CHECKOUT_URL = "latestCheckoutUrl";
    public static final String LATEST_ROTATION_ERROR = "latestRotationError";

    private final ObjectMapper mapper = new ObjectMapper();
    private final Path file;
    private final int thresholdT;
    private final int thresholdN;

    private Map<String, String> config;
    private Map<String, String> snapshot;

    public VendorKeyStore(Path file, int thresholdT, int thresholdN) {
        this.file = file;
        this.thresholdT = thresholdT;
        this.thresholdN = thresholdN;
        this.config = load(file);
        this.snapshot = new LinkedHashMap<>(this.config);
    }

    private static Map<String, String> load(Path file) {
        if (!Files.exists(file)) return new LinkedHashMap<>();
        try {
            String json = Files.readString(file, StandardCharsets.UTF_8);
            if (json.isBlank()) return new LinkedHashMap<>();
            @SuppressWarnings("unchecked")
            Map<String, String> m = new ObjectMapper().readValue(json, LinkedHashMap.class);
            return m;
        } catch (IOException e) {
            throw new IllegalStateException("Could not read vendor key store at " + file, e);
        }
    }

    // ---------------------------------------------------------------- reads

    public synchronized String get(String key) {
        String v = config.get(key);
        return v == null || v.isEmpty() ? null : v;
    }

    /** The raw value including empty string, for the state predicates that distinguish the two. */
    private String raw(String key) {
        return config.get(key);
    }

    public synchronized String getVRK() {
        SecretKeys keys = secretKeys();
        if (keys == null || keys.activeVrk == null || keys.activeVrk.isEmpty()) return null;
        return keys.activeVrk;
    }

    public synchronized String getVZK() {
        SecretKeys keys = secretKeys();
        if (keys == null || keys.VZK == null || keys.VZK.isEmpty()) return null;
        return keys.VZK;
    }

    public synchronized PendingVRKInfo getPendingVRKInfo() {
        SecretKeys keys = secretKeys();
        if (keys == null) return null;
        if (keys.pendingVrk == null || keys.pendingVrk.isEmpty()) return null;
        return new PendingVRKInfo(
                keys.pendingVrk,
                get(PENDING_GVRK),
                get(PENDING_GVRK_SIG),
                get(PENDING_YTMP),
                get(OBF_GVVK));
    }

    private SecretKeys secretKeys() {
        String current = raw(CLIENT_SECRET);
        if (current == null || current.isEmpty()) return null;
        try {
            return mapper.readValue(current, SecretKeys.class);
        } catch (Exception e) {
            throw new IllegalStateException("Malformed secret keys in the vendor key store", e);
        }
    }

    private SecretKeys secretKeysOrNew() {
        SecretKeys keys = secretKeys();
        return keys == null ? new SecretKeys() : keys;
    }

    /**
     * Derived, never stored: no secret keys at all means no VRK; a VRK but no vendor id means the
     * wallet is minted and licensing has not completed.
     */
    public synchronized VendorKeyState vendorKeyState() {
        if (isEmpty(raw(CLIENT_SECRET))) return VendorKeyState.NotCreated;
        if (isEmpty(raw(VENDOR_ID))) return VendorKeyState.AwaitingPayment;
        return VendorKeyState.Created;
    }

    public synchronized LicenseState licenseState() {
        if (isEmpty(raw(CLIENT_SECRET))) return LicenseState.NotCreated;
        if (isEmpty(raw(VVK_PUBLIC))) return LicenseState.NotCreated_AwaitingPayment;
        if (!isEmpty(raw(LATEST_ROTATION_ERROR))) return LicenseState.Active_NeedsAttention;
        return LicenseState.Active;
    }

    public SignRequestSettingsMidgard midgardSettings() {
        return midgardSettings(null, null);
    }

    /**
     * @param vendorId overrides the stored vvkId (used before one exists)
     * @param vrk      overrides the active VRK (used to exercise a pending one)
     */
    public synchronized SignRequestSettingsMidgard midgardSettings(String vendorId, String vrk) {
        SignRequestSettingsMidgard s = new SignRequestSettingsMidgard();
        s.VVKId = vendorId != null ? vendorId : get(VENDOR_ID);
        s.HomeOrkUrl = get(SYSTEM_HOME_ORK_URL);
        s.PayerPublicKey = get(SYSTEM_PAYER_PUBLIC);
        s.ObfuscatedVendorPublicKey = get(OBF_GVVK);
        s.VendorRotatingPrivateKey = vrk != null ? vrk : getVRK();
        s.Threshold_T = thresholdT;
        s.Threshold_N = thresholdN;
        return s;
    }

    /** Every config key currently held, for prefix scans. */
    public synchronized java.util.Set<String> keys() {
        return new java.util.LinkedHashSet<>(config.keySet());
    }

    // --------------------------------------------------------------- writes

    /**
     * Set an arbitrary config value. For material the typed setters do not model, the enclave
     * settings ceremony's per-redirect-URI signatures, for instance.
     */
    public synchronized void put(String key, String value) {
        if (key == null || key.isBlank()) throw new IllegalArgumentException("key is required");
        if (CLIENT_SECRET.equals(key)) {
            throw new IllegalArgumentException("Refusing to write key material through the generic setter");
        }
        config.put(key, nullToEmpty(value));
    }


    public synchronized void setSystemSettings(String homeOrkUrl, String payerPublic) {
        config.put(SYSTEM_HOME_ORK_URL, homeOrkUrl);
        config.put(SYSTEM_PAYER_PUBLIC, payerPublic);
    }

    public synchronized void setPendingVRKInfo(String pendingVRK, String pendingGVRK,
                                               String pendingGVRKSignature, String pendingYtmp,
                                               String pendingWalletId, String obfGVVK) {
        SecretKeys keys = secretKeysOrNew();
        keys.pendingVrk = pendingVRK;
        putSecretKeys(keys);

        config.put(PENDING_GVRK, pendingGVRK);
        config.put(PENDING_GVRK_SIG, pendingGVRKSignature);
        config.put(PENDING_YTMP, pendingYtmp);
        if (obfGVVK != null) config.put(OBF_GVVK, obfGVVK);
        config.put(PENDING_WALLET_ID, pendingWalletId);
    }

    public synchronized void setPendingGVRK(String pendingGVRK) {
        config.put(PENDING_GVRK, pendingGVRK);
    }

    public synchronized void setPendingGVRKSignature(String signature) {
        config.put(PENDING_GVRK_SIG, signature);
    }

    public synchronized void setVZK(String vzk) {
        SecretKeys keys = secretKeysOrNew();
        keys.VZK = vzk;
        putSecretKeys(keys);
    }

    public synchronized void setSubscriptionId(String subscriptionId) {
        config.put(SUBSCRIPTION_ID, subscriptionId);
    }

    public synchronized void setInitialCustomerInfo(String customerId, String maxUserAccounts,
                                                    String initialSessionId, String subscriptionId,
                                                    String checkoutUrl) {
        config.put(INITIAL_STRIPE_SESS_ID, nullToEmpty(initialSessionId));
        config.put(REALM_CUSTOMER_ID, nullToEmpty(customerId));
        config.put(REALM_MAX_USER_COUNT, nullToEmpty(maxUserAccounts));
        config.put(SUBSCRIPTION_ID, nullToEmpty(subscriptionId));
        config.put(LATEST_CHECKOUT_URL, nullToEmpty(checkoutUrl));
    }

    public synchronized void setRotationError(String message) {
        config.put(LATEST_ROTATION_ERROR, nullToEmpty(message));
    }

    /** Promote the pending VRK to active and clear the pending slot. */
    public synchronized void switchPendingVRK() {
        SecretKeys keys = secretKeys();
        if (keys == null) throw new IllegalStateException("No existing keys available");
        if (isEmpty(keys.pendingVrk)) throw new IllegalStateException("No pending vrk keys available");
        if (isEmpty(raw(PENDING_GVRK))) throw new IllegalStateException("No pending gVRK available");

        keys.activeVrk = keys.pendingVrk;
        keys.pendingVrk = "";
        putSecretKeys(keys);

        config.put(GVRK, nullToEmpty(raw(PENDING_GVRK)));
        config.put(GVRK_SIG, nullToEmpty(raw(PENDING_GVRK_SIG)));
        config.put(WALLET_ID, nullToEmpty(raw(PENDING_WALLET_ID)));

        config.put(PENDING_GVRK, "");
        config.put(PENDING_GVRK_SIG, "");
        config.put(PENDING_WALLET_ID, "");
        config.put(PENDING_YTMP, "");

        config.put(LATEST_ROTATION_ERROR, "");
    }

    public synchronized void finalizeVendorInfo(String vendorId, String firstAdmin,
                                                String firstAdminSignature, String gVRKSignature,
                                                String vvkPublic, String eVVK) {
        // The finalize response carries the gVRK's certificate; park it in the pending slot so the
        // one promotion path stays the only way key material becomes active.
        config.put(PENDING_GVRK_SIG, nullToEmpty(gVRKSignature));
        switchPendingVRK();

        config.put(VENDOR_ID, nullToEmpty(vendorId));
        config.put(AUTHORIZER, nullToEmpty(firstAdmin));
        config.put(AUTHORIZER_SIG, nullToEmpty(firstAdminSignature));
        config.put(VVK_PUBLIC, nullToEmpty(vvkPublic));
        config.put(OBF_GVVK, nullToEmpty(vvkPublic));
        if (eVVK != null) config.put(ENCRYPTED_VVK, eVVK);
    }

    private void putSecretKeys(SecretKeys keys) {
        try {
            config.put(CLIENT_SECRET, mapper.writeValueAsString(keys));
        } catch (Exception e) {
            throw new IllegalStateException("Could not serialise secret keys", e);
        }
    }

    // ----------------------------------------------------- commit / rollback

    /** Persist the working copy and make it the committed snapshot. */
    public synchronized void commit() {
        try {
            Files.createDirectories(file.getParent());
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.writeString(tmp, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(config),
                    StandardCharsets.UTF_8);
            // Atomic swap, so a crash mid-write cannot leave a half-written key store.
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new IllegalStateException("Could not persist vendor key store to " + file, e);
        }
        snapshot = new LinkedHashMap<>(config);
    }

    /** Discard uncommitted working-copy changes. */
    public synchronized void rollback() {
        config = new LinkedHashMap<>(snapshot);
    }

    /**
     * Roll back, record the error, and commit only that. Mirrors TideCloak's LogRotationError:
     * a failed rotation must not leave half-written key material behind, but the operator still
     * needs to see why.
     */
    public synchronized void logRotationError(String message) {
        log.error("%s", message);
        rollback();
        setRotationError(message);
        commit();
    }

    public synchronized void logRotationError(Throwable t) {
        java.io.StringWriter sw = new java.io.StringWriter();
        try (java.io.PrintWriter pw = new java.io.PrintWriter(sw)) {
            pw.println("time=" + java.time.Instant.now());
            t.printStackTrace(pw);
        }
        logRotationError(sw.toString());
    }

    /** Everything except private key material, for the state endpoint. */
    public synchronized Map<String, String> redactedView() {
        Map<String, String> out = new TreeMap<>(config);
        if (out.containsKey(CLIENT_SECRET)) {
            SecretKeys keys = secretKeys();
            out.put(CLIENT_SECRET, "<redacted:"
                    + (keys != null && !isEmpty(keys.activeVrk) ? "activeVrk " : "")
                    + (keys != null && !isEmpty(keys.pendingVrk) ? "pendingVrk " : "")
                    + (keys != null && !isEmpty(keys.VZK) ? "VZK" : "")
                    + ">");
        }
        return out;
    }

    private static boolean isEmpty(String s) { return s == null || s.isEmpty(); }
    private static String nullToEmpty(String s) { return s == null ? "" : s; }

    public record PendingVRKInfo(String pendingVrk, String pendingGVRK, String pendingGVRKSignature,
                                 String pendingYtmp, String obfGVVK) {}
}

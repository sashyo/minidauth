package org.minidauth.config;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Environment-driven configuration.
 *
 * <p>{@code THRESHOLD_T} / {@code THRESHOLD_N} / {@code SYSTEM_HOME_ORK} / {@code PAYER_PUBLIC}
 * deliberately keep the names TideCloak uses, so an existing deployment's env carries over
 * verbatim.
 */
public final class Config {

    /** Default cohort thresholds, matching TideLicenseComponentManager. */
    private static final int DEFAULT_THRESHOLD_T = 14;
    private static final int DEFAULT_THRESHOLD_N = 20;

    public final int port;
    public final Path dataDir;
    public final String homeOrkUrl;
    public final String payerPublic;
    public final int thresholdT;
    public final int thresholdN;
    /** Single all-roles operator token, for a one-operator deployment. */
    public final String adminToken;
    /** Name that token is attributed to in the approval record. */
    public final String adminName;
    /** Optional JSON roster of operators. Configuration, not state, never written by the service. */
    public final Path operatorsFile;
    /** Optional override of the VRK's authorised model list. Null = the built-in default. */
    public final String[] vrkModels;
    /** Days before gVRK expiry at which the rotation switch is attempted. */
    public final int graceDays;
    /** When true, governed approvals must come through the Tide enclave, not a bearer token. */
    public final boolean requireTideApproval;
    /** Where the enclave fetches vouchers. Must be reachable from the user's browser. */
    public final String voucherUrl;

    /**
     * Where a browser reaches this service's voucher endpoint, when that is not {@link #publicUrl}.
     *
     * <p>The enclave runs on the ORK's public origin and fetches vouchers from here, and a browser
     * refuses a public page's request to a loopback address ("Permission was denied for this request
     * to access the loopback address space"). A deployed service on a public URL never sees this;
     * running on localhost does, and this is the way out without putting the whole service on the
     * internet.
     */
    public final String voucherPublicUrl;

    /**
     * A file to read {@link #voucherPublicUrl} from, when it is not known at startup.
     *
     * <p>A tunnel does not have an address until it has connected, which is after this service is
     * already running. Reading it per request rather than at boot means neither has to wait for the
     * other, and an absent file simply means no tunnel.
     */
    public final String voucherPublicUrlFile;
    /**
     * This service's externally reachable base URL.
     *
     * <p>Needed because the console's redirect URI has to be a signed, fixed value the enclave will
     * accept, and behind a proxy the service cannot infer its own public address from the request.
     * Defaults to localhost on the bound port, which is right for development and wrong in
     * production, where it must be set, or sign-in will bounce operators to a URL that is not the
     * one that was signed.
     */
    public final String publicUrl;

    /**
     * Optional. When set, the voucher and sign endpoints verify an end user's own token and take the
     * user id from it, instead of trusting the calling application to assert the user id. This is the
     * boundary the ORKs never see: they honour whatever voucher this service issues, so moving the
     * identity check here from the app is a change to this service alone. Null unless
     * {@code MC_USER_TOKEN_SECRET} is set, in which case the legacy app-asserted uid path stays.
     */
    public final UserTokenConfig userToken;

    /**
     * How this service verifies an end user's token. Prefer {@code publicKey}: the issuing app signs
     * tokens with an Ed25519 private key and this service holds only the public half, so there is no
     * shared symmetric secret that, once published or leaked from any holder, forges any user. The
     * {@code secret} (HS256) path is kept for a quick start but should not be used in production.
     */
    public static final class UserTokenConfig {
        public final String secret;    // HS256 shared secret (fallback; avoid in production)
        public final String publicKey; // Ed25519 SPKI public key, base64 (preferred)
        public final String issuer;    // required iss claim, or null to skip
        public final String audience;  // required aud claim, or null to skip
        public final String uidClaim;  // claim that carries the user id; defaults to "sub"

        public UserTokenConfig(String secret, String publicKey, String issuer, String audience, String uidClaim) {
            this.secret = secret;
            this.publicKey = publicKey;
            this.issuer = issuer;
            this.audience = audience;
            this.uidClaim = (uidClaim == null || uidClaim.isBlank()) ? "sub" : uidClaim;
        }
    }

    private Config(int port, Path dataDir, String homeOrkUrl, String payerPublic,
                   int thresholdT, int thresholdN, String adminToken, String adminName,
                   Path operatorsFile, String[] vrkModels, int graceDays,
                   boolean requireTideApproval, String voucherUrl, String publicUrl,
                   String voucherPublicUrl, String voucherPublicUrlFile,
                   UserTokenConfig userToken) {
        this.port = port;
        this.dataDir = dataDir;
        this.homeOrkUrl = homeOrkUrl;
        this.payerPublic = payerPublic;
        this.thresholdT = thresholdT;
        this.thresholdN = thresholdN;
        this.adminToken = adminToken;
        this.adminName = adminName;
        this.operatorsFile = operatorsFile;
        this.vrkModels = vrkModels;
        this.graceDays = graceDays;
        this.requireTideApproval = requireTideApproval;
        this.voucherUrl = voucherUrl;
        this.publicUrl = publicUrl;
        this.voucherPublicUrl = voucherPublicUrl;
        this.voucherPublicUrlFile = voucherPublicUrlFile;
        this.userToken = userToken;
    }

    public static Config fromEnv() {
        String models = str("MC_VRK_MODELS", null);
        String userSecret = str("MC_USER_TOKEN_SECRET", null);
        String userPublicKey = str("MC_USER_TOKEN_PUBLIC_KEY", null);
        UserTokenConfig userToken = (userSecret == null && userPublicKey == null) ? null : new UserTokenConfig(
                userSecret,
                userPublicKey,
                str("MC_USER_TOKEN_ISSUER", null),
                str("MC_USER_TOKEN_AUDIENCE", null),
                str("MC_USER_TOKEN_UID_CLAIM", "sub"));
        return new Config(
                intOrDefault("MC_PORT", 8081),
                Paths.get(str("MC_DATA_DIR", "./data")).toAbsolutePath().normalize(),
                str("SYSTEM_HOME_ORK", null),
                str("PAYER_PUBLIC", null),
                intOrDefault("THRESHOLD_T", DEFAULT_THRESHOLD_T),
                intOrDefault("THRESHOLD_N", DEFAULT_THRESHOLD_N),
                str("MC_ADMIN_TOKEN", null),
                str("MC_ADMIN_NAME", "admin"),
                Paths.get(str("MC_OPERATORS_FILE", "./operators.json")).toAbsolutePath().normalize(),
                models == null ? null : models.split("\\s*,\\s*"),
                intOrDefault("MC_GRACE_DAYS", 7),
                Boolean.parseBoolean(str("MC_REQUIRE_TIDE_APPROVAL", "false")),
                str("MC_VOUCHER_URL", null),
                str("MC_PUBLIC_URL", null),
                str("MC_VOUCHER_PUBLIC_URL", null),
                str("MC_VOUCHER_PUBLIC_URL_FILE", null),
                userToken);
    }

    /**
     * The wallet-backed VRK path cannot run without a reachable home ORK and the payer's public
     * key, so refuse to start rather than fail at the first ORK round trip.
     */
    public void requireOrkNetwork() {
        if (isBlank(homeOrkUrl)) {
            throw new IllegalStateException("SYSTEM_HOME_ORK is required (e.g. http://localhost:1001)");
        }
        if (isBlank(payerPublic)) {
            throw new IllegalStateException("PAYER_PUBLIC is required (the payer ORK's public key, hex)");
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static String str(String name, String fallback) {
        String raw = System.getenv(name);
        if (raw == null || raw.isBlank()) {
            raw = System.getProperty(name);
        }
        return (raw == null || raw.isBlank()) ? fallback : raw.trim();
    }

    private static int intOrDefault(String name, int fallback) {
        String raw = str(name, null);
        if (raw == null) return fallback;
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            throw new IllegalStateException(name + " must be an integer, got: " + raw, e);
        }
    }
}

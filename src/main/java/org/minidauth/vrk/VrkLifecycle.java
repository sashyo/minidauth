package org.minidauth.vrk;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.midgard.Midgard;
import org.midgard.models.InitWalletResponse;
import org.midgard.models.KeyGenerationResponse;
import org.midgard.models.ModelRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.midgard.models.VendorSettings;
import org.midgard.models.WalletLifecycleState;
import org.midgard.models.licensing.ActivationPackage;
import org.midgard.models.licensing.LicenseResponse;
import org.minidauth.Log;
import org.minidauth.config.Config;
import org.minidauth.store.VendorKeyStore;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

/**
 * The VRK's whole life: mint, license, finalize, rotate, promote, and use.
 *
 * <p>A port of TideCloak's {@code TideVendorLifecycleManager} with the Keycloak realm/component
 * coupling removed. The Midgard call sequence and its ordering are preserved exactly, since those
 * are what the ORK network checks.
 */
public final class VrkLifecycle {
    private static final Log log = Log.of(VrkLifecycle.class);

    /** Free tier activates on creation instead of going through a Stripe checkout. */
    public static final String FREE_LICENSING_TIER = "free";

    /**
     * The models this VRK is authorised to sign. {@code RotateVRK:1} must be present or the key can
     * never rotate itself.
     *
     * <p><b>Do not add to this list casually.</b> Every model name is serialised into the gVRK
     * authorizer pack, the pack is shipped to the payer as Stripe subscription metadata, and Stripe
     * caps a metadata value at {@value #STRIPE_METADATA_LIMIT} characters. This exact six-model list
     * serialises to 483 characters of metadata, 17 characters of headroom. Adding
     * {@code Policy:1} and {@code AttestationUnit:1} takes it to 549 and licensing fails at the
     * payer with a StripeException.
     *
     * <p><b>{@code AttestationUnit:1} must NOT be added here.</b> The ORK refuses the wallet outright
     *, "Main VRK cannot allow AttestationUnit:1 model", because attestation units are signed under
     * the firstAdmin authorizer pack, not the main VRK. That pack carries
     * {@code EnableOffboard:1, Policy:1, AttestationUnit:1}, and the split is the point: the key that
     * talks to the swarm is not the key that attests configuration.
     *
     * <p>Policy signing does not need an entry here: a {@code Policy:1} sign is authorized by the
     * <b>firstAdmin</b> authorizer pack minted by {@code FinalizeWallet} (whose own ModelIds include
     * {@code Policy:1}), not by this main gVRK pack. See
     * {@link #authorizeRequestWithFirstAdmin(ModelRequest)}.
     */
    private static final String[] DEFAULT_VRK_MODELS = new String[]{
            "RotateVRK:1",
            "TidecloakUpdateSettings:1",
            "TidecloakSessionStartTokenSign:1",
            "EnableOffboard:1",
            "TideRequestInitialization:1",
            "UserIdentityAttestationUnit:1"
    };

    /** Stripe's hard cap on a single metadata value. The gVRK pack travels in one. */
    static final int STRIPE_METADATA_LIMIT = 500;

    private final ObjectMapper mapper = new ObjectMapper();
    private final VendorKeyStore store;
    private final Config config;

    public VrkLifecycle(VendorKeyStore store, Config config) {
        this.store = store;
        this.config = config;
    }

    public VendorKeyStore store() { return store; }

    private String[] vrkModels() {
        return config.vrkModels != null ? config.vrkModels : DEFAULT_VRK_MODELS;
    }

    // ==================================================================== create

    /**
     * Drive the vendor key from wherever it is toward {@link VendorKeyState#Created}, resuming
     * rather than restarting: a minted wallet is never minted twice.
     */
    public synchronized CreateVendorKeyResponse createVendorKey(String redirectUrl, String licensingTier,
                                                                String lineItemsJson, String email) {
        Trace.start();
        VendorKeyState state = store.vendorKeyState();
        if (state == VendorKeyState.Created) {
            log.info("Vendor key already created");
            return new CreateVendorKeyResponse(false, state, null);
        }

        String checkoutUrl = null;
        boolean success;
        boolean finalizeNow = false;
        VendorKeyState intendedFinalState;

        switch (state) {
            case NotCreated -> {
                try {
                    requireLicensingArgs(redirectUrl, licensingTier);
                    createInitialVRKAndWallet();
                    checkoutUrl = createLicense(redirectUrl, licensingTier, lineItemsJson, email);
                    intendedFinalState = VendorKeyState.AwaitingPayment;
                    success = true;
                    finalizeNow = isFreeTierWithEmail(licensingTier, email) && customerCreated();
                    log.info("Initialized subscription on tier %s, awaiting payment", licensingTier);
                } catch (Exception e) {
                    log.error(e, "Could not initialize wallet");
                    store.rollback();
                    // Roll back to the last COMMITTED state. A minted VRK is already durable and
                    // must never be reported as never-created.
                    intendedFinalState = store.vendorKeyState();
                    success = false;
                }
            }
            case AwaitingPayment -> {
                try {
                    if (!customerCreated()) {
                        // The wallet is committed but licensing never completed. Resume that step
                        // against the existing wallet instead of minting a second one.
                        requireLicensingArgs(redirectUrl, licensingTier);
                        checkoutUrl = createLicense(redirectUrl, licensingTier, lineItemsJson, email);
                        intendedFinalState = VendorKeyState.AwaitingPayment;
                        success = true;
                        finalizeNow = isFreeTierWithEmail(licensingTier, email) && customerCreated();
                    } else {
                        FinalizeVendorResponse resp = finalizeVendor();
                        if (resp.awaitingPayment()) {
                            checkoutUrl = resp.checkoutUrl();
                            log.info("Still awaiting payment for customer %s",
                                    store.get(VendorKeyStore.REALM_CUSTOMER_ID));
                            store.rollback();
                            success = true;
                            intendedFinalState = VendorKeyState.AwaitingPayment;
                        } else if (resp.success()) {
                            intendedFinalState = VendorKeyState.Created;
                            store.commit();
                            success = true;
                            log.info("Finalized wallet, vvkId %s", store.get(VendorKeyStore.VENDOR_ID));
                        } else {
                            throw new IllegalStateException("Could not check wallet status against the Tide network");
                        }
                    }
                } catch (Exception e) {
                    intendedFinalState = VendorKeyState.AwaitingPayment;
                    log.error(e, "Could not finalize wallet");
                    store.rollback();
                    success = false;
                }
            }
            default -> throw new IllegalStateException("Unknown vendor key state: " + state);
        }

        // Free tier is active on creation, so finalize now rather than waiting for a payment that
        // will never arrive.
        if (finalizeNow) {
            log.info("Free tier with email, finalizing vendor creation now");
            return createVendorKey(redirectUrl, licensingTier, lineItemsJson, email);
        }

        VendorKeyState actual = store.vendorKeyState();
        if (actual != intendedFinalState) {
            throw new IllegalStateException("Vendor key creation robustness check failed: intended "
                    + intendedFinalState + " but store reports " + actual);
        }
        return new CreateVendorKeyResponse(success, actual, checkoutUrl);
    }

    /**
     * Mint the VRK + pending wallet and COMMIT before any further remote call. The private key is
     * the only handle on the wallet that now exists on the network, so it must be durable before
     * anything else can fail and roll the config back.
     */
    private void createInitialVRKAndWallet() {
        LicenseState licenseState = store.licenseState();
        if (licenseState != LicenseState.NotCreated) {
            throw new IllegalStateException("createInitialVRKAndWallet needs license state NotCreated, got " + licenseState);
        }

        // This expiry governs the key's use with the ORKs. The payer ORKs holding the wallet
        // enforce their own, shorter, wallet expiry, so an over-long value here buys nothing.
        long vrkExpiry = ZonedDateTime.now(ZoneOffset.UTC)
                .plusMonths(1)
                .plusDays(config.graceDays)
                .toEpochSecond();

        InitWalletResponse init = Midgard.InitializeWallet(
                store.get(VendorKeyStore.SYSTEM_HOME_ORK_URL),
                store.get(VendorKeyStore.SYSTEM_PAYER_PUBLIC),
                vrkModels(),
                vrkExpiry,
                null, // no customer yet
                Trace.current());

        store.setPendingVRKInfo(
                init.VRK,
                init.GVRK,
                "", // no certificate yet, the finalize response carries it
                init.Ytmp,
                init.GVRK,
                init.ObfGVVK);
        store.setVZK(init.VRK);
        store.commit();
        log.info("Minted initial VRK, gVRK expiry %d", vrkExpiry);
    }

    /**
     * Create the licence against the committed pending gVRK, then commit. Split from
     * {@link #createInitialVRKAndWallet()} so a licensing failure can be resumed without minting a
     * second wallet.
     */
    private String createLicense(String redirectUri, String licensingTier, String lineItemsJson,
                                 String email) throws Exception {
        String homeOrk = store.get(VendorKeyStore.SYSTEM_HOME_ORK_URL);
        String payerPublic = store.get(VendorKeyStore.SYSTEM_PAYER_PUBLIC);
        String gvrk = store.get(VendorKeyStore.PENDING_GVRK);
        String vendorData = mapper.writeValueAsString(Map.of("GVRK", gvrk));
        requireFitsStripeMetadata(vendorData, "licence vendorData");

        String result = isFreeTierWithEmail(licensingTier, email)
                ? Midgard.CreateFreeTierLicense(homeOrk, payerPublic, vendorData, redirectUri, email, Trace.current())
                : Midgard.CreateStripeCheckoutSession(homeOrk, payerPublic, vendorData, redirectUri,
                        licensingTier, lineItemsJson, Trace.current());
        requireOk(result, isFreeTierWithEmail(licensingTier, email)
                ? "CreateFreeTierLicense" : "CreateStripeCheckoutSession");

        LicenseResponse response = mapper.readValue(result, LicenseResponse.class);
        if (response.activationPackage == null) {
            throw new IllegalStateException("The Tide network returned a licence with no activation package: " + result);
        }
        ActivationPackage pack = mapper.readValue(response.activationPackage, ActivationPackage.class);
        store.setInitialCustomerInfo(pack.customerId, pack.maxUserAcc, pack.sessionId,
                pack.subscriptionId, response.redirectUrl);
        store.commit();
        return response.redirectUrl;
    }

    /** Confirm payment, finalize the wallet into a VVK, then queue the next month's key. */
    private FinalizeVendorResponse finalizeVendor() throws Exception {
        LicenseState licenseState = store.licenseState();
        if (licenseState != LicenseState.NotCreated_AwaitingPayment) {
            throw new IllegalStateException("finalizeVendor needs license state NotCreated_AwaitingPayment, got " + licenseState);
        }

        WalletLifecycleState walletState = pendingWalletState();

        if (walletState.Status != WalletLifecycleState.StatusType.OK) {
            if (walletState.Status == WalletLifecycleState.StatusType.NO_CUSTOMER
                    || walletState.Status == WalletLifecycleState.StatusType.NO_SUBSCRIPTION) {
                // Checkout is still outstanding, hand back the URL so it can be completed.
                return new FinalizeVendorResponse(false, true,
                        store.get(VendorKeyStore.LATEST_CHECKOUT_URL));
            }
            throw new IllegalStateException("Could not determine wallet state. Status: " + walletState.Status);
        }
        if (walletState.WalletState != WalletLifecycleState.WalletStateType.ACTIVE) {
            // Checkout completed but the payment has not settled yet.
            return new FinalizeVendorResponse(false, true, null);
        }

        String customerId = store.get(VendorKeyStore.REALM_CUSTOMER_ID);
        String pendingGVRK = store.get(VendorKeyStore.PENDING_GVRK);
        String vvkId = UUID.randomUUID().toString();
        VendorKeyStore.PendingVRKInfo pending = store.getPendingVRKInfo();

        SignRequestSettingsMidgard settings = store.midgardSettings(vvkId, pending.pendingVrk());
        settings.VendorAuthorizer = pendingGVRK;
        settings.TraceParent = Trace.current();

        boolean backupOn = "true".equalsIgnoreCase(String.valueOf(store.get(VendorKeyStore.BACKUP_ON)));

        KeyGenerationResponse resp = Midgard.FinalizeWallet(settings, backupOn, pending.pendingYtmp(),
                pending.pendingVrk(), customerId, Trace.current());

        store.finalizeVendorInfo(vvkId, resp.FIRST_ADMIN, resp.FIRST_ADMIN_SIGNATURE,
                resp.VRK_SIGNATURE, resp.VVK_PUBLIC, resp.eVVK);
        store.commit();

        // Get ready for next month.
        createNextVRKAndWallet();

        return new FinalizeVendorResponse(true, false, null);
    }

    // ==================================================================== rotate

    /**
     * Mint next month's VRK + wallet, have the CURRENT VRK certify it, and park it in the pending
     * slot. The current key stays active until {@link #trySwitchToNextVRK()} promotes this one.
     */
    public synchronized void createNextVRKAndWallet() throws Exception {
        LicenseState licenseState = store.licenseState();
        switch (licenseState) {
            case NotCreated, NotCreated_AwaitingPayment -> {
                log.warn("Cannot create the next VRK without an existing license; use createVendorKey first");
                return;
            }
            case Active, Active_NeedsAttention -> log.info("Creating next VRK and wallet, license state %s", licenseState);
            default -> throw new IllegalStateException("Unknown license state " + licenseState);
        }

        long newVrkExpiry = nextVrkExpiry();

        InitWalletResponse init = Midgard.InitializeWallet(
                store.get(VendorKeyStore.SYSTEM_HOME_ORK_URL),
                store.get(VendorKeyStore.SYSTEM_PAYER_PUBLIC),
                vrkModels(),
                newVrkExpiry,
                store.get(VendorKeyStore.REALM_CUSTOMER_ID),
                Trace.current());

        // Prepare the new wallet against the existing VVK.
        Midgard.AnonSignWallet(
                store.midgardSettings(null, init.VRK),
                init.Ytmp,
                store.get(VendorKeyStore.VVK_PUBLIC),
                store.get(VendorKeyStore.REALM_CUSTOMER_ID),
                Trace.current());

        // The CURRENT key certifies the NEXT one. This is the RotateVRK:1 ceremony.
        String newVrkSignature = signRotateVrk(init.GVRK);

        store.setPendingVRKInfo(init.VRK, init.GVRK, newVrkSignature, init.Ytmp, init.GVRK, null);

        updateSubscriptionWithPendingGVRK();
        store.commit();

        // Switch at the billing boundary, graceDays before the current VRK actually dies, so a
        // failed switch can be retried while the current key is still valid.
        long currentVrkExpiry = currentGvrkExpiry();
        Instant runAt = Instant.ofEpochSecond(currentVrkExpiry).minus(Duration.ofDays(config.graceDays));
        log.info("Next VRK staged; switch due at %s", runAt);
    }

    /** Ask the ORK cohort to certify {@code gvrkHex} under the current VRK's authority. */
    private String signRotateVrk(String gvrkHex) throws Exception {
        ModelRequest req = ModelRequest.New("RotateVRK", "1", "VRK:1", HexFormat.of().parseHex(gvrkHex));
        authorizeRequestWithVRK(req);
        SignRequestSettingsMidgard settings = store.midgardSettings();
        settings.TraceParent = Trace.current();
        SignatureResponse response = Midgard.SignModel(settings, req);
        if (response.Signatures == null || response.Signatures.length == 0) {
            throw new IllegalStateException("Tide network returned no signature for the RotateVRK request");
        }
        return response.Signatures[0];
    }

    /**
     * Prove the pending VRK can actually sign before making it the only key we have, then promote
     * it and immediately stage the one after.
     */
    public synchronized boolean trySwitchToNextVRK() {
        Trace.start();
        VendorKeyStore.PendingVRKInfo pending = store.getPendingVRKInfo();
        if (pending == null) {
            store.logRotationError("No pending VRK to switch to");
            return false;
        }

        SignRequestSettingsMidgard settings = store.midgardSettings(null, pending.pendingVrk());
        settings.TraceParent = Trace.current();

        try {
            // A no-op settings sign, purely to prove the pending key is honoured by the cohort.
            String draft = "[]" + "|" + "[]" + "|"
                    + mapper.writeValueAsString(new VendorSettings(false, false, "http://test.com", "http://test.com"));
            ModelRequest req = ModelRequest.New("TidecloakUpdateSettings", "1", "VRK:1",
                    draft.getBytes(StandardCharsets.UTF_8));
            authorizeRequestWithVRK(req, true);

            SignatureResponse response = Midgard.SignModel(settings, req);
            if (response.Signatures == null || response.Signatures.length == 0) {
                throw new IllegalStateException("Tide network returned no signatures for the pending VRK test sign");
            }

            store.switchPendingVRK();
            store.commit();
            log.info("Promoted the pending VRK to active");
        } catch (Exception e) {
            store.logRotationError(e);
            log.error(e, "Could not switch to the pending VRK");
            return false;
        }

        // The promotion above is committed and durable. Staging next month's key is a SEPARATE
        // outcome and must be reported as one: folding it into the same try would return
        // "not switched" for a switch that did happen, sending the scheduler back to retry a
        // promotion with nothing left to promote. The payer also answers 409 to a second live
        // pending wallet, which is exactly what an early manual switch provokes.
        try {
            createNextVRKAndWallet();
        } catch (Exception e) {
            store.logRotationError(e);
            log.error(e, "Promoted the VRK, but could not stage its successor. "
                    + "The active key is valid; re-stage with POST /vrk/rotate/stage.");
        }
        return true;
    }

    // ------------------------------------------------- manual rotation levers

    /**
     * Mint a replacement pending VRK. If a pending wallet is already ACTIVE the key is regenerated
     * onto that same wallet (no second wallet); if none exists, a fresh wallet is initialized.
     *
     * <p>Leaves the new key UNCERTIFIED, {@link #manualSignNewVRK()} is the next step.
     */
    public synchronized void manualGenerateNewVRK() throws Exception {
        Trace.start();
        WalletLifecycleState walletState = pendingWalletState();
        if (walletState.Status != WalletLifecycleState.StatusType.OK) {
            throw new IllegalStateException("Cannot determine the pending wallet state, status " + walletState.Status);
        }
        if (walletState.WalletState == WalletLifecycleState.WalletStateType.PENDING) {
            throw new IllegalStateException("The pending wallet is awaiting payment; cannot generate a new VRK until it is active");
        }

        long newVrkExpiry = nextVrkExpiry();

        if (walletState.WalletState == WalletLifecycleState.WalletStateType.ACTIVE) {
            // That pending wallet is already paid for. Re-key onto it; do NOT mint another.
            var keys = Midgard.RegenerateVrk(vrkModels(), store.get(VendorKeyStore.PENDING_GVRK), newVrkExpiry);
            store.setPendingGVRK(keys.gVRK);
            store.setPendingGVRKSignature(""); // no longer certified, must be re-signed
            store.commit();
            log.info("Regenerated the pending gVRK onto the existing wallet");
            return;
        }

        // ABSENT: a new wallet and a new key.
        InitWalletResponse init = Midgard.InitializeWallet(
                store.get(VendorKeyStore.SYSTEM_HOME_ORK_URL),
                store.get(VendorKeyStore.SYSTEM_PAYER_PUBLIC),
                vrkModels(),
                newVrkExpiry,
                store.get(VendorKeyStore.REALM_CUSTOMER_ID),
                Trace.current());

        Midgard.AnonSignWallet(
                store.midgardSettings(null, init.VRK),
                init.Ytmp,
                store.get(VendorKeyStore.VVK_PUBLIC),
                store.get(VendorKeyStore.REALM_CUSTOMER_ID),
                Trace.current());

        store.setPendingVRKInfo(init.VRK, init.GVRK, "", init.Ytmp, init.GVRK, null);
        store.commit();

        updateSubscriptionWithPendingGVRK();
        store.commit();
        log.info("Minted a new pending VRK and wallet");
    }

    /** Have the CURRENT VRK certify whatever is in the pending slot, overwriting any signature. */
    public synchronized void manualSignNewVRK() throws Exception {
        Trace.start();
        VendorKeyStore.PendingVRKInfo pending = store.getPendingVRKInfo();
        if (pending == null || pending.pendingGVRK() == null) {
            throw new IllegalStateException("No pending gVRK to sign");
        }
        String signature = signRotateVrk(pending.pendingGVRK());
        store.setPendingGVRKSignature(signature);
        store.commit();
        log.info("Certified the pending gVRK");
    }

    /** Promote the pending VRK, provided it can sign. */
    public synchronized boolean manualUseNewVRK() {
        return trySwitchToNextVRK();
    }

    // ==================================================================== use

    /**
     * Attach the VRK authorization triplet to a request: the VRK's signature over the request's
     * authorize-string, the gVRK authorizer pack, and the pack's certificate.
     *
     * <p>This is the "usage" half of the key's life, every Policy, contract and governance sign
     * this service performs goes through here.
     */
    public void authorizeRequestWithVRK(ModelRequest request) {
        authorizeRequestWithVRK(request, false);
    }

    public synchronized void authorizeRequestWithVRK(ModelRequest request, boolean usePendingInfo) {
        String vrk;
        String gVrk;
        String gVrkSignature;

        if (usePendingInfo) {
            VendorKeyStore.PendingVRKInfo pending = store.getPendingVRKInfo();
            if (pending == null) throw new IllegalStateException("No pending VRK available");
            if (pending.pendingGVRKSignature() == null || pending.pendingGVRKSignature().isEmpty()) {
                throw new IllegalStateException("Cannot use the pending VRK: it has not been certified yet");
            }
            vrk = pending.pendingVrk();
            gVrk = pending.pendingGVRK();
            gVrkSignature = pending.pendingGVRKSignature();
        } else {
            vrk = store.getVRK();
            gVrk = store.get(VendorKeyStore.GVRK);
            gVrkSignature = store.get(VendorKeyStore.GVRK_SIG);
            if (vrk == null || gVrk == null || gVrkSignature == null) {
                throw new IllegalStateException("No active VRK, the vendor key has not been created yet");
            }
        }

        request.SetAuthorization(Midgard.SignWithVrk(request.GetDataToAuthorize(), vrk));
        request.SetAuthorizer(HexFormat.of().parseHex(gVrk));
        request.SetAuthorizerCertificate(Base64.getDecoder().decode(gVrkSignature));
    }

    /** Authorize with the active VRK and ask the cohort to sign. */
    public synchronized SignatureResponse signWithVrk(ModelRequest request) throws Exception {
        authorizeRequestWithVRK(request);
        SignRequestSettingsMidgard settings = store.midgardSettings();
        settings.TraceParent = Trace.current();
        SignatureResponse response = Midgard.SignModel(settings, request);
        if (response.Signatures == null || response.Signatures.length == 0) {
            throw new IllegalStateException("Tide network returned no signature for " + request.Id());
        }
        return response;
    }

    /**
     * Stamp a request with the VRK's creation authorization.
     *
     * <p>Not the same thing as authorizing the request's own model. Underneath this is a
     * {@code TideRequestInitialization:1} request that records who created this one and when, and
     * it is what makes a carrier approvable: an enclave asked to approve a request with no creation
     * authorization finds a zero-length signature where the vendor's should be and refuses, with a
     * message about buffer length that says nothing about the cause.
     *
     * <p>It must use the <b>main</b> gVRK pack rather than the firstAdmin one, because only the
     * main pack lists {@code TideRequestInitialization:1} among its models.
     */
    public synchronized void initializeRequestWithVrk(ModelRequest request) throws Exception {
        String gvrk = store.get(VendorKeyStore.GVRK);
        String cert = store.get(VendorKeyStore.GVRK_SIG);
        if (gvrk == null || gvrk.isBlank() || cert == null || cert.isBlank()) {
            throw new IllegalStateException("No main gVRK authorizer material, create the vendor key first");
        }

        SignRequestSettingsMidgard settings = store.midgardSettings();
        settings.TraceParent = Trace.current();

        ModelRequest.InitializeTideRequestWithVrk(
                request,
                settings,
                request.Id(),
                java.util.HexFormat.of().parseHex(gvrk),
                java.util.Base64.getDecoder().decode(cert));
    }

    /** Authorize with the firstAdmin pack and ask the cohort to sign. */
    public synchronized SignatureResponse signWithFirstAdmin(ModelRequest request) throws Exception {
        authorizeRequestWithFirstAdmin(request);
        SignRequestSettingsMidgard settings = store.midgardSettings();
        settings.TraceParent = Trace.current();
        SignatureResponse response = Midgard.SignModel(settings, request);
        if (response.Signatures == null || response.Signatures.length == 0) {
            throw new IllegalStateException("Tide network returned no signature for " + request.Id());
        }
        return response;
    }

    /**
     * The firstAdmin authorizer pack minted by {@code FinalizeWallet}. A Policy:1 sign is
     * authorized by this pack, not by the main gVRK pack, and so is an {@code AttestationUnit:1}
     * sign, which the main VRK is explicitly forbidden from carrying.
     */
    public synchronized void authorizeRequestWithFirstAdmin(ModelRequest request) {
        String authorizer = store.get(VendorKeyStore.AUTHORIZER);
        String authorizerCert = store.get(VendorKeyStore.AUTHORIZER_SIG);
        if (authorizer == null || authorizerCert == null) {
            throw new IllegalStateException("No firstAdmin authorizer material, finalize the vendor key first");
        }
        String vrk = store.getVRK();
        if (vrk == null) throw new IllegalStateException("No active VRK");

        request.SetAuthorization(Midgard.SignWithVrk(request.GetDataToAuthorize(), vrk));
        request.SetAuthorizer(HexFormat.of().parseHex(authorizer));
        request.SetAuthorizerCertificate(Base64.getDecoder().decode(authorizerCert));
    }

    // ==================================================================== state

    public WalletLifecycleState pendingWalletState() throws Exception {
        String vzk = store.getVZK();
        if (vzk == null) {
            throw new IllegalStateException("No VZK, the vendor key has not been created yet, so there is no wallet to query");
        }
        String customerId = store.get(VendorKeyStore.REALM_CUSTOMER_ID);
        String subscriptionId = store.get(VendorKeyStore.SUBSCRIPTION_ID);
        String pendingGVRK = store.get(VendorKeyStore.PENDING_GVRK);

        String timestamp = Long.toString(Instant.now().toEpochMilli());
        String message = timestamp + "|"
                + customerId + "|"
                + (subscriptionId != null ? subscriptionId : "") + "|"
                + (pendingGVRK != null ? pendingGVRK : "");

        String vzkTimeSig = Base64.getEncoder().encodeToString(Midgard.SignWithVrk(message, vzk));
        return WalletLifecycleState.From(requireOk(Midgard.GetWalletState(
                store.get(VendorKeyStore.SYSTEM_HOME_ORK_URL),
                store.get(VendorKeyStore.SYSTEM_PAYER_PUBLIC),
                customerId, subscriptionId, pendingGVRK,
                timestamp, vzkTimeSig, Trace.current()), "GetWalletState"));
    }

    /** Epoch seconds at which the ACTIVE gVRK authorizer pack expires. */
    public long currentGvrkExpiry() {
        String gvrk = store.get(VendorKeyStore.GVRK);
        if (gvrk == null) return 0;
        return Midgard.GetAuthorizerPackExpiry(gvrk);
    }

    /** Exactly one month past the current expiry, keeping the grace period the initial key added. */
    private long nextVrkExpiry() {
        long currentVrkExpiry = currentGvrkExpiry();
        if (currentVrkExpiry <= 0) {
            throw new IllegalStateException("No expiry on the current VRK; cannot derive the next expiry from it");
        }
        return Instant.ofEpochSecond(currentVrkExpiry)
                .atZone(ZoneId.of("UTC")) // keep in step with the billing calendar
                .plusMonths(1)
                .toEpochSecond();
    }

    /** The instant the rotation switch should be attempted, or null if there is no active key. */
    public Instant nextSwitchAt() {
        long expiry = currentGvrkExpiry();
        if (expiry <= 0) return null;
        return Instant.ofEpochSecond(expiry).minus(Duration.ofDays(config.graceDays));
    }

    private void updateSubscriptionWithPendingGVRK() throws Exception {
        String timestamp = Long.toString(Instant.now().toEpochMilli());
        String vzkTimeSig = Base64.getEncoder().encodeToString(Midgard.SignWithVrk(timestamp, store.getVZK()));

        UpdateRequest updateRequest = new UpdateRequest(
                store.get(VendorKeyStore.INITIAL_STRIPE_SESS_ID),
                new VendorGvrk(store.get(VendorKeyStore.PENDING_GVRK)),
                store.get(VendorKeyStore.SUBSCRIPTION_ID));
        requireFitsStripeMetadata(
                mapper.writeValueAsString(new VendorGvrk(store.get(VendorKeyStore.PENDING_GVRK))),
                "rotation vendorData");

        String raw = requireOk(Midgard.UpdateSubscription(
                store.get(VendorKeyStore.SYSTEM_HOME_ORK_URL),
                store.get(VendorKeyStore.SYSTEM_PAYER_PUBLIC),
                mapper.writeValueAsString(updateRequest),
                store.get(VendorKeyStore.REALM_CUSTOMER_ID),
                timestamp, vzkTimeSig, Trace.current()), "UpdateSubscription");

        UpdateSubscriptionResponse parsed = mapper.readValue(raw, UpdateSubscriptionResponse.class);
        String subscriptionId = parsed.subscription() == null ? null : parsed.subscription().id();
        String existing = store.get(VendorKeyStore.SUBSCRIPTION_ID);

        if (subscriptionId == null && existing == null) {
            throw new IllegalStateException("Tide network returned no subscription id for customer "
                    + store.get(VendorKeyStore.REALM_CUSTOMER_ID));
        }
        if (existing == null) store.setSubscriptionId(subscriptionId);
    }

    private boolean customerCreated() {
        return store.get(VendorKeyStore.REALM_CUSTOMER_ID) != null;
    }

    /**
     * Several Midgard exports return a raw String and signal failure in-band, as {@code null} or a
     * {@code --FAILED--[status=NNN]} envelope, rather than by throwing. Handing that straight to
     * Jackson produces an opaque "argument content is null" deep inside the mapper; this turns it
     * into the actual error, with the payer's status code.
     */
    /**
     * Fail before the ORK round trip rather than after it. Stripe refuses an over-long metadata
     * value with a 500 from the payer, which surfaces as an opaque licensing failure a long way
     * from its cause, the VRK model list.
     */
    private void requireFitsStripeMetadata(String value, String what) {
        if (value == null || value.length() <= STRIPE_METADATA_LIMIT) return;
        throw new IllegalStateException(String.format(
                "The %s is %d characters, over Stripe's %d-character metadata limit. "
                        + "The gVRK authorizer pack grows with every entry in the VRK model list, "
                        + "currently %s. Remove a model, policy signing uses the firstAdmin pack, "
                        + "not this one.",
                what, value.length(), STRIPE_METADATA_LIMIT, String.join(", ", vrkModels())));
    }

    private static String requireOk(String response, String operation) {
        if (!Midgard.IsFailed(response)) return response;
        int status = Midgard.FailedStatus(response);
        throw new IllegalStateException("Tide network call " + operation + " failed"
                + (status >= 0 ? " with status " + status : "")
                + (response == null ? " (null response)" : ": " + response));
    }

    private static void requireLicensingArgs(String redirectUrl, String licensingTier) {
        if (redirectUrl == null || licensingTier == null) {
            throw new IllegalArgumentException("redirectUrl and licensingTier are required to create a vendor key");
        }
    }

    private static boolean isFreeTierWithEmail(String licensingTier, String email) {
        return FREE_LICENSING_TIER.equalsIgnoreCase(licensingTier) && email != null && !email.isBlank();
    }

    // ==================================================================== DTOs

    public record CreateVendorKeyResponse(boolean success, VendorKeyState state, String checkoutUrl) {}

    public record FinalizeVendorResponse(boolean success, boolean awaitingPayment, String checkoutUrl) {}

    private static final class UpdateRequest {
        @JsonProperty("InitialSessionId") public final String initialSessionId;
        @JsonProperty("SubscriptionId") public final String subscriptionId;
        @JsonProperty("VendorData") public final VendorGvrk vendorData;

        UpdateRequest(String initialSessionId, VendorGvrk vendorData, String subscriptionId) {
            this.initialSessionId = initialSessionId;
            this.vendorData = vendorData;
            this.subscriptionId = subscriptionId;
        }
    }

    private static final class VendorGvrk {
        @JsonProperty("GVRK") public final String gvrk;
        VendorGvrk(String gvrk) { this.gvrk = gvrk; }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record UpdateSubscriptionResponse(Subscription subscription) {
        @JsonIgnoreProperties(ignoreUnknown = true)
        record Subscription(String id) {}
    }
}

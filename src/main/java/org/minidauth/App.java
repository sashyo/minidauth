package org.minidauth;

import org.minidauth.auth.Operators;
import org.minidauth.config.Config;
import org.minidauth.gov.GovernanceService;
import org.minidauth.gov.GovernanceStore;
import org.minidauth.http.ApiServer;
import org.minidauth.store.VendorKeyStore;
import org.minidauth.tide.TideAuthService;
import org.minidauth.vrk.RotationScheduler;
import org.minidauth.vrk.VrkLifecycle;

import java.nio.file.Files;

/**
 * Minified TideCloak: a standalone service that owns a Tide vendor rotating key end to end, mints it
 * against the ORK network, rotates it on the billing boundary, and uses it to sign governed policy
 * and contract deployments behind a quorum.
 */
public final class App {
    private static final Log log = Log.of(App.class);

    public static void main(String[] args) throws Exception {
        Config config = Config.fromEnv();
        config.requireOrkNetwork();
        Files.createDirectories(config.dataDir);

        VendorKeyStore keyStore = new VendorKeyStore(
                config.dataDir.resolve("vendor-key.json"), config.thresholdT, config.thresholdN);

        // The home ORK and payer key come from the environment on every boot, so a redeploy that
        // moves the network does not need the store edited by hand.
        keyStore.setSystemSettings(config.homeOrkUrl, config.payerPublic);
        keyStore.commit();

        // The roster is configuration, read once at boot. This service does not manage identities.
        Operators operators = Operators.load(config.operatorsFile, config.adminToken, config.adminName);

        VrkLifecycle vrk = new VrkLifecycle(keyStore, config);
        RotationScheduler rotation = new RotationScheduler(vrk);

        GovernanceStore govStore = new GovernanceStore(config.dataDir.resolve("governance.json"));
        Integer thresholdOverride = intOrNull(System.getenv("MC_APPROVAL_THRESHOLD"));
        GovernanceService gov = new GovernanceService(govStore, operators, vrk, thresholdOverride,
                config.requireTideApproval);

        // The doken's roles come from the governed grant record, the quorum-committed one, not
        // anything an application asserts about its own users.
        TideAuthService tideAuth = new TideAuthService(keyStore, vrk, gov::rolesFor, gov::signedRoleUnitsFor,
                gov::signAttestationUnits);
        ApiServer server = new ApiServer(config, operators, keyStore, vrk, rotation, govStore, gov, tideAuth);
        server.start();

        log.info("Data dir      : %s", config.dataDir);
        log.info("Home ORK      : %s", config.homeOrkUrl);
        log.info("Cohort        : T=%d N=%d", config.thresholdT, config.thresholdN);
        log.info("Vendor key    : %s", keyStore.vendorKeyState());
        log.info("License       : %s", keyStore.licenseState());
        log.info("Approval gate : %d of %d approvers%s", gov.currentThreshold(), operators.approverCount(),
                config.requireTideApproval ? " (enclave approval required)" : "");

        rotation.rearm();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Shutting down");
            server.close();
            rotation.close();
        }));

        Thread.currentThread().join();
    }

    private static Integer intOrNull(String raw) {
        if (raw == null || raw.isBlank()) return null;
        try {
            return Integer.valueOf(raw.trim());
        } catch (NumberFormatException e) {
            throw new IllegalStateException("MC_APPROVAL_THRESHOLD must be an integer, got: " + raw, e);
        }
    }
}

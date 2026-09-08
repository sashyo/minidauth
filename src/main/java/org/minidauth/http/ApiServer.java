package org.minidauth.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.minidauth.Log;
import org.minidauth.auth.Operator;
import org.minidauth.auth.Operators;
import org.minidauth.auth.Role;
import org.minidauth.config.Config;
import org.minidauth.gov.ChangeRequest;
import org.minidauth.gov.GovernanceException;
import org.minidauth.gov.GovernanceService;
import org.minidauth.gov.GovernanceStore;
import org.minidauth.gov.Status;
import org.minidauth.store.VendorKeyStore;
import org.minidauth.tide.EnclaveSettings;
import org.minidauth.tide.TideAuthService;
import org.minidauth.vrk.RotationScheduler;
import org.minidauth.vrk.VrkLifecycle;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;

/** The service's whole HTTP surface. */
public final class ApiServer implements AutoCloseable {
    private static final Log log = Log.of(ApiServer.class);

    private final Config config;
    private final Operators operators;
    private final org.minidauth.auth.DokenOperators dokenOperators;
    private final VendorKeyStore keyStore;
    private final VrkLifecycle vrk;
    private final RotationScheduler rotation;
    private final GovernanceStore govStore;
    private final GovernanceService gov;
    private final TideAuthService tideAuth;
    private final Router router = new Router();
    private HttpServer server;

    public ApiServer(Config config, Operators operators, VendorKeyStore keyStore, VrkLifecycle vrk,
                     RotationScheduler rotation, GovernanceStore govStore, GovernanceService gov,
                     TideAuthService tideAuth) {
        this.config = config;
        this.operators = operators;
        this.keyStore = keyStore;
        this.vrk = vrk;
        this.rotation = rotation;
        this.govStore = govStore;
        this.gov = gov;
        this.tideAuth = tideAuth;
        // Roles are read live from the grant record rather than captured, so a revocation committed
        // through the quorum takes effect on the operator's very next request.
        this.dokenOperators = new org.minidauth.auth.DokenOperators(
                () -> keyStore.get(VendorKeyStore.VVK_PUBLIC),
                () -> keyStore.get(VendorKeyStore.VENDOR_ID),
                vuid -> gov.rolesFor(vuid));
        routes();
    }

    // ================================================================= routes

    private void routes() {
        router.get("/health", (ex, p) -> Json.send(ex, 200, Map.of(
                "status", "up",
                "vendorKeyState", keyStore.vendorKeyState().name(),
                "licenseState", keyStore.licenseState().name())));

        // ---------------------------------------------------------- VRK state
        router.get("/vrk/state", (ex, p) -> {
            authenticate(ex);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("vendorKeyState", keyStore.vendorKeyState().name());
            out.put("licenseState", keyStore.licenseState().name());
            out.put("vvkId", keyStore.get(VendorKeyStore.VENDOR_ID));
            out.put("gVRK", keyStore.get(VendorKeyStore.GVRK));
            out.put("gVRKCertified", keyStore.get(VendorKeyStore.GVRK_SIG) != null);
            out.put("pendingGVRK", keyStore.get(VendorKeyStore.PENDING_GVRK));
            out.put("pendingGVRKCertified", keyStore.get(VendorKeyStore.PENDING_GVRK_SIG) != null);
            out.put("homeOrkUrl", keyStore.get(VendorKeyStore.SYSTEM_HOME_ORK_URL));
            out.put("customerId", keyStore.get(VendorKeyStore.REALM_CUSTOMER_ID));
            out.put("latestRotationError", keyStore.get(VendorKeyStore.LATEST_ROTATION_ERROR));
            Json.send(ex, 200, out);
        });

        router.get("/vrk/config", (ex, p) -> {
            require(ex, Role.VRK_ADMIN);
            Json.send(ex, 200, keyStore.redactedView());
        });

        router.get("/vrk/rotation", (ex, p) -> {
            authenticate(ex);
            long expiry = vrk.currentGvrkExpiry();
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("currentGvrkExpiry", expiry == 0 ? null : expiry);
            out.put("nextSwitchAt", Optional.ofNullable(vrk.nextSwitchAt()).map(Object::toString).orElse(null));
            out.put("graceDays", config.graceDays);
            out.put("pendingGVRK", keyStore.get(VendorKeyStore.PENDING_GVRK));
            out.put("pendingGVRKCertified", keyStore.get(VendorKeyStore.PENDING_GVRK_SIG) != null);
            out.put("latestRotationError", keyStore.get(VendorKeyStore.LATEST_ROTATION_ERROR));
            Json.send(ex, 200, out);
        });

        router.get("/vrk/wallet-state", (ex, p) -> {
            require(ex, Role.VRK_ADMIN);
            Json.send(ex, 200, vrk.pendingWalletState());
        });

        // ------------------------------------------------------ VRK lifecycle
        router.post("/vrk/create", (ex, p) -> {
            require(ex, Role.VRK_ADMIN);
            Map<String, Object> body = Json.readBody(ex);
            var resp = vrk.createVendorKey(
                    Json.string(body, "redirectUrl"),
                    Json.string(body, "licensingTier"),
                    Json.string(body, "lineItems"),
                    Json.string(body, "email"));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("success", resp.success());
            out.put("state", resp.state().name());
            out.put("checkoutUrl", resp.checkoutUrl());
            out.put("vvkId", keyStore.get(VendorKeyStore.VENDOR_ID));
            out.put("gVRK", keyStore.get(VendorKeyStore.GVRK));
            // Once the key is live the rotation timer has a boundary to aim at.
            if (resp.state() == org.minidauth.vrk.VendorKeyState.Created) rotation.rearm();
            Json.send(ex, resp.success() ? 200 : 409, out);
        });

        // Rotation, as three explicit steps: mint, certify, promote.
        router.post("/vrk/rotate/generate", (ex, p) -> {
            require(ex, Role.VRK_ADMIN);
            vrk.manualGenerateNewVRK();
            Json.send(ex, 200, Map.of(
                    "pendingGVRK", String.valueOf(keyStore.get(VendorKeyStore.PENDING_GVRK)),
                    "certified", keyStore.get(VendorKeyStore.PENDING_GVRK_SIG) != null,
                    "next", "POST /vrk/rotate/sign"));
        });

        router.post("/vrk/rotate/sign", (ex, p) -> {
            require(ex, Role.VRK_ADMIN);
            vrk.manualSignNewVRK();
            Json.send(ex, 200, Map.of(
                    "pendingGVRK", String.valueOf(keyStore.get(VendorKeyStore.PENDING_GVRK)),
                    "certified", true,
                    "next", "POST /vrk/rotate/switch"));
        });

        router.post("/vrk/rotate/switch", (ex, p) -> {
            require(ex, Role.VRK_ADMIN);
            boolean switched = vrk.manualUseNewVRK();
            if (switched) rotation.rearm();
            Json.send(ex, switched ? 200 : 409, Map.of(
                    "switched", switched,
                    "gVRK", String.valueOf(keyStore.get(VendorKeyStore.GVRK)),
                    "latestRotationError", String.valueOf(keyStore.get(VendorKeyStore.LATEST_ROTATION_ERROR))));
        });

        /** Stage next month's key the way the scheduled path does: mint, certify and park it. */
        router.post("/vrk/rotate/stage", (ex, p) -> {
            require(ex, Role.VRK_ADMIN);
            vrk.createNextVRKAndWallet();
            rotation.rearm();
            Json.send(ex, 200, Map.of(
                    "pendingGVRK", String.valueOf(keyStore.get(VendorKeyStore.PENDING_GVRK)),
                    "certified", keyStore.get(VendorKeyStore.PENDING_GVRK_SIG) != null,
                    "nextSwitchAt", String.valueOf(vrk.nextSwitchAt())));
        });

        /** Run the scheduled rotation check now instead of waiting for the boundary. */
        router.post("/vrk/rotate/run-now", (ex, p) -> {
            require(ex, Role.VRK_ADMIN);
            rotation.runNow();
            Json.send(ex, 202, Map.of("scheduled", true));
        });

        // --------------------------------------------------------- governance
        router.get("/iga/forseti-contracts", (ex, p) -> {
            authenticate(ex);
            Json.send(ex, 200, govStore.contracts());
        });

        router.get("/iga/forseti-contracts/{id}", (ex, p) -> {
            authenticate(ex);
            Json.send(ex, 200, govStore.contract(p.get("id"))
                    .orElseThrow(() -> new Json.HttpError(404, "No contract " + p.get("id"))));
        });

        router.get("/iga/policies", (ex, p) -> {
            authenticate(ex);
            Json.send(ex, 200, govStore.policies());
        });

        router.get("/iga/policies/{id}", (ex, p) -> {
            authenticate(ex);
            Json.send(ex, 200, govStore.policy(p.get("id"))
                    .orElseThrow(() -> new Json.HttpError(404, "No policy " + p.get("id"))));
        });

        router.get("/iga/change-requests", (ex, p) -> {
            authenticate(ex);
            String raw = Router.query(ex).get("status");
            Status filter = null;
            if (raw != null && !raw.isBlank()) {
                try {
                    filter = Status.valueOf(raw.trim().toUpperCase(java.util.Locale.ROOT));
                } catch (IllegalArgumentException e) {
                    throw new Json.HttpError(400, "Unknown status: " + raw);
                }
            }
            Json.send(ex, 200, govStore.changeRequests(filter));
        });

        router.get("/iga/change-requests/{id}", (ex, p) -> {
            authenticate(ex);
            Json.send(ex, 200, govStore.changeRequest(p.get("id"))
                    .orElseThrow(() -> new Json.HttpError(404, "No change request " + p.get("id"))));
        });

        router.post("/iga/change-requests/contract", (ex, p) -> {
            Operator by = authenticate(ex);
            Map<String, Object> body = Json.readBody(ex);
            ChangeRequest cr = gov.fileContractRegistration(by,
                    Json.requireString(body, "name"),
                    Json.requireString(body, "source"),
                    Json.string(body, "type"));
            ex.getResponseHeaders().add("Location", "/iga/change-requests/" + cr.id);
            Json.send(ex, 202, cr);
        });

        router.post("/iga/change-requests/policy", (ex, p) -> {
            Operator by = authenticate(ex);
            ChangeRequest cr = gov.filePolicyDeployment(by, Json.readBody(ex));
            ex.getResponseHeaders().add("Location", "/iga/change-requests/" + cr.id);
            Json.send(ex, 202, cr);
        });

        router.post("/iga/change-requests/{id}/authorize", (ex, p) ->
                Json.send(ex, 200, gov.authorize(authenticate(ex), p.get("id"))));

        router.post("/iga/change-requests/{id}/commit", (ex, p) ->
                Json.send(ex, 200, gov.commit(authenticate(ex), p.get("id"))));

        /* The request an admin's enclave approves, and the way it comes back.
         *
         * Both are governance operations, so both need an operator, but note that approving is not
         * something this service can do on anyone's behalf: the doken is added inside the enclave,
         * by the admin, using a session key this service never sees. */
        router.get("/iga/change-requests/{id}/carrier", (ex, p) -> {
            require(ex, Role.APPROVER);
            Json.send(ex, 200, Map.of("carrier", gov.carrierFor(p.get("id"))));
        });

        router.post("/iga/change-requests/{id}/carrier", (ex, p) -> {
            require(ex, Role.APPROVER);
            Map<String, Object> body = Json.readBody(ex);
            var cr = gov.acceptCarrier(p.get("id"), Json.requireString(body, "carrier"));
            Json.send(ex, 200, Map.of(
                    "id", cr.id,
                    "approvals", cr.carrierApprovals));
        });

        router.post("/iga/change-requests/{id}/deny", (ex, p) -> {
            gov.deny(authenticate(ex), p.get("id"));
            Json.sendNoContent(ex);
        });

        // ------------------------------------------------------- governed grants

        /* The authoritative answer to "who may decrypt". Read-only: the only way in is a
           committed change request. */
        router.get("/iga/grants", (ex, p) -> {
            authenticate(ex);
            Json.send(ex, 200, gov.allGrants());
        });

        router.get("/iga/grants/{vuid}", (ex, p) -> {
            authenticate(ex);
            Json.send(ex, 200, Map.of(
                    "vuid", p.get("vuid"),
                    "roles", gov.rolesFor(p.get("vuid"))));
        });

        /* File a grant or revocation. Takes effect only once the quorum commits it. */
        router.post("/iga/change-requests/role", (ex, p) -> {
            Operator by = authenticate(ex);
            Map<String, Object> body = Json.readBody(ex);
            ChangeRequest cr = gov.fileRoleChange(by,
                    Json.requireString(body, "vuid"),
                    Json.requireString(body, "role"),
                    Boolean.TRUE.equals(body.get("revoke")));
            ex.getResponseHeaders().add("Location", "/iga/change-requests/" + cr.id);
            Json.send(ex, 202, cr);
        });

        // --------------------------------------------------- Tide enclave (step-up)

        /* Sign the enclave settings and every redirect URI in one ceremony. Must be run once
           before any login, and again whenever a redirect URI changes. */
        router.post("/tide/enclave/settings", (ex, p) -> {
            require(ex, Role.VRK_ADMIN);
            EnclaveSettings settings = Json.mapper().convertValue(Json.readBody(ex), EnclaveSettings.class);
            Json.send(ex, 200, tideAuth.signSettings(settings));
        });

        /* The signature that lets an origin hold a postMessage channel with the enclave. */
        router.get("/tide/enclave/origin-signature", (ex, p) -> {
            authenticate(ex);
            String origin = Router.query(ex).get("origin");
            if (origin == null || origin.isBlank()) {
                throw new Json.HttpError(400, "origin is required");
            }
            Json.send(ex, 200, Map.of(
                    "origin", origin,
                    "clientOriginAuth", tideAuth.originSignature(origin)));
        });

        /* Everything the browser side needs to reach the enclave. No private material. */
        router.get("/tide/enclave/config", (ex, p) -> {
            authenticate(ex);
            Json.send(ex, 200, tideAuth.enclaveConfig());
        });

        /* Build the enclave redirect. Assembled here so the caller cannot substitute its own
           authorizer pack, settings blob or redirect target. */
        router.post("/tide/enclave/login-url", (ex, p) -> {
            authenticate(ex);
            Map<String, Object> body = Json.readBody(ex);
            String voucherUrl = Json.string(body, "voucherUrl");
            if (voucherUrl == null) voucherUrl = config.voucherUrl;
            if (voucherUrl == null) {
                throw new Json.HttpError(400, "voucherUrl is required (or set MC_VOUCHER_URL)");
            }
            java.net.URI url = tideAuth.loginUrl(
                    Json.requireString(body, "sessionId"),
                    Json.requireString(body, "redirectUri"),
                    voucherUrl,
                    Json.string(body, "extraQuery"),
                    org.minidauth.tide.TideAuthService.requireEnclaveType(
                            Json.string(body, "enclaveType")));
            Json.send(ex, 200, Map.of("url", url.toString()));
        });

        /* Turn an enclave callback into a proven Tide identity. Decryption needs the VRK, so it
           can only happen here. */
        router.post("/tide/enclave/callback", (ex, p) -> {
            authenticate(ex);
            Map<String, Object> body = Json.readBody(ex);
            var result = tideAuth.verifySignIn(
                    Json.requireString(body, "encryptedVendorData"),
                    Json.requireString(body, "sessionId"),
                    Json.string(body, "userPublic"));
            Json.send(ex, 200, Map.of(
                    "vuid", result.vuid(),
                    "tideUsername", result.tideUsername(),
                    "userPublic", result.userPublic(),
                    // Bound to the browser's session key, so it is useless to anyone else.
                    "doken", result.doken()));
        });

        /* The enclave asks for a voucher mid-flow; issuing one needs the VRK.
         *
         * The reply is returned VERBATIM. The enclave parses the voucher payload itself, so
         * wrapping it in an object leaves the field it reads undefined and the failure surfaces far
         * away as "Cannot read properties of undefined". */
        router.post("/tide/vouchers", (ex, p) -> {
            authenticate(ex);
            Map<String, Object> body = Json.readBody(ex);
            Json.sendRaw(ex, 200,
                    tideAuth.vouchers(Json.requireString(body, "voucherRequest")),
                    "application/json; charset=utf-8");
        });

        /* Kept only to answer clearly. A doken is minted from the blind-signature proof of an
         * enclave sign-in, which is spent at login, so there is no standalone call that can issue
         * one afterwards. /tide/enclave/callback returns it instead. */
        router.post("/tide/session/doken", (ex, p) -> {
            authenticate(ex);
            Json.sendError(ex, 410,
                    "A session doken cannot be issued by a standalone call: it is minted from the "
                            + "enclave sign-in proof, which is consumed at login. The doken is returned by "
                            + "POST /tide/enclave/callback.");
        });

        /* Step-up approval: the doken proves WHO approved, independent of who made the call. */
        router.post("/iga/change-requests/{id}/approve", (ex, p) -> {
            Operator by = authenticate(ex);
            Map<String, Object> body = Json.readBody(ex);
            Json.send(ex, 200, gov.approveWithEnclave(by, p.get("id"),
                    Json.requireString(body, "doken")));
        });

        // Read-only view of the configured roster and the bar it sets. The roster itself is
        // deployment configuration; there is no route that changes it.
        // ------------------------------------------------------- the governance console
        //
        // Served from here, not from the applications this service protects. Those applications are
        // exactly what the threat model assumes gets compromised, so a console rendered inside one, // holding a credential that can grant roles, would put the ability to authorise reads
        // inside the blast radius it is supposed to be outside of.

        router.get("/console", (ex, p) -> Json.sendRaw(ex, 200, console(), "text/html; charset=utf-8"));

        /* Start a sign-in. Unauthenticated on purpose: this IS the way to get a credential, so
           requiring one would be circular. Nothing secret is returned, the login URL carries the
           authorizer pack and signatures over public values, and the redirect target is the
           console's own, taken from configuration rather than from the caller, so this cannot be
           used to point a Tide sign-in at somebody else's page. */
        router.post("/console/session/login-url", (ex, p) -> {
            Map<String, Object> body = Json.readBody(ex);
            String voucherUrl = config.voucherUrl;
            if (voucherUrl == null) {
                throw new Json.HttpError(400, "MC_VOUCHER_URL is not configured, so the enclave has "
                        + "nowhere to fetch a voucher from");
            }
            java.net.URI url = tideAuth.loginUrl(
                    Json.requireString(body, "sessionId"),
                    consoleRedirectUri(),
                    voucherUrl,
                    null,
                    org.minidauth.tide.TideAuthService.requireEnclaveType(
                            Json.string(body, "enclaveType")));
            Json.send(ex, 200, Map.of("url", url.toString()));
        });

        /* Finish a sign-in and hand back the doken.
         *
         * Also unauthenticated, and safe for the same reason: the enclave's proof is verified
         * cryptographically here, so possession of it IS the authentication. The doken returned is
         * only useful for governance if the grant record gives that vuid a governance role, which
         * this endpoint has no way to influence. */
        router.post("/console/session/callback", (ex, p) -> {
            Map<String, Object> body = Json.readBody(ex);
            var result = tideAuth.verifySignIn(
                    Json.requireString(body, "encryptedVendorData"),
                    Json.requireString(body, "sessionId"),
                    Json.string(body, "userPublic"));

            java.util.Set<String> granted = gov.rolesFor(result.vuid());
            Json.send(ex, 200, Map.of(
                    "vuid", result.vuid(),
                    "doken", result.doken(),
                    "roles", granted,
                    // Told plainly, because "signed in but nothing works" is the confusing case.
                    "canGovern", !org.minidauth.auth.DokenOperators
                            .toServiceRoles(granted).isEmpty()));
        });

        /* Encrypt and decrypt used to live here, calling Midgard.Encrypt and Midgard.Decrypt. They
         * are gone, and it is worth saying why so nobody adds them back.
         *
         * Both take a COMPLETE Ed25519 private key, verify the doken against it and sign locally.
         * They make no network calls at all. Using them would mean holding a whole vendor key in
         * this process, which is the single thing this service exists not to do. They are for
         * deployments that have already reconstructed their key and left the network.
         *
         * Encryption here goes through a policy instead, in the browser, with tide-js. The policy
         * bytes are served openly by /vault/encrypt-policy below. */

        router.get("/operators", (ex, p) -> {
            authenticate(ex);
            List<Map<String, Object>> out = operators.all().stream()
                    .map(o -> Map.<String, Object>of(
                            "name", o.name(),
                            "roles", o.roles().stream().map(Role::wire).sorted().toList()))
                    .toList();
            Json.send(ex, 200, Map.of(
                    "operators", out,
                    "approvers", operators.approverCount(),
                    "threshold", gov.currentThreshold(),
                    "enclaveApprovalRequired", gov.requiresTideApproval()));
        });
    }

    // =================================================================== auth

    /**
     * Resolve the caller.
     *
     * <p>Two schemes, and the difference matters. {@code Doken} is the real one: a short-lived
     * token the ORK cohort minted after an enclave sign-in, carrying cohort-attested roles and
     * bound to a browser session key, so nothing durable has to be stored anywhere. {@code Bearer}
     * is the original static operator token, kept for bootstrap and for scripted operations that
     * predate the console, it is a shared secret, and anything holding one can act as that
     * operator for as long as it exists.
     */
    private Operator authenticate(HttpExchange ex) {
        String header = ex.getRequestHeaders().getFirst("Authorization");
        if (header == null) {
            throw new Json.HttpError(401, "Authorization is required: 'Doken <token>' from a Tide "
                    + "sign-in, or 'Bearer <token>' for a configured operator");
        }

        if (header.startsWith(org.minidauth.auth.DokenOperators.SCHEME)) {
            String token = header.substring(
                    org.minidauth.auth.DokenOperators.SCHEME.length()).trim();
            return dokenOperators.authenticate(token)
                    .orElseThrow(() -> new Json.HttpError(401,
                            "The doken is not valid for governance here. It must verify against "
                            + "this vendor key, be unexpired, and carry a governance role that the "
                            + "grant record still shows."));
        }

        if (header.startsWith("Bearer ")) {
            return operators.authenticate(header.substring("Bearer ".length()).trim())
                    .orElseThrow(() -> new Json.HttpError(401, "Unknown operator token"));
        }

        throw new Json.HttpError(401, "Unsupported authorization scheme");
    }

    /**
     * Where the enclave sends an operator back to.
     *
     * <p>Derived from configuration, never from the request: a redirect target a caller could set
     * would turn this into an open redirector for a Tide sign-in, which is the one thing the signed
     * redirect URI exists to prevent.
     */
    private String consoleRedirectUri() {
        String base = config.publicUrl == null || config.publicUrl.isBlank()
                ? "http://localhost:" + config.port
                : config.publicUrl.replaceAll("/+$", "");
        return base + "/console";
    }

    /** The console page, loaded from the jar. */
    private static String console() {
        try (java.io.InputStream in = ApiServer.class.getResourceAsStream("/console/index.html")) {
            if (in == null) throw new Json.HttpError(500, "The console assets are missing from this build");
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            throw new Json.HttpError(500, "Could not read the console assets: " + e.getMessage());
        }
    }

    private Operator require(HttpExchange ex, Role role) {
        Operator o = authenticate(ex);
        o.require(role);
        return o;
    }

    // ================================================================== serve

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(config.port), 0);
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.createContext("/", this::dispatch);
        server.start();
        log.info("Listening on http://localhost:%d", config.port);
    }

    private void dispatch(HttpExchange ex) throws IOException {
        String method = ex.getRequestMethod();
        String path = ex.getRequestURI().getPath();
        try {
            Map<String, String> params = new LinkedHashMap<>();
            Router.Handler handler = router.match(method, path, params);
            if (handler == null) {
                Json.sendError(ex, 404, "No route for " + method + " " + path);
                return;
            }
            handler.handle(ex, params);
        } catch (Json.HttpError e) {
            Json.sendError(ex, e.status, e.getMessage());
        } catch (GovernanceException e) {
            Json.sendError(ex, e.status, e.getMessage());
        } catch (Operator.Unauthorized e) {
            Json.sendError(ex, 403, e.getMessage());
        } catch (IllegalArgumentException e) {
            Json.sendError(ex, 400, String.valueOf(e.getMessage()));
        } catch (IllegalStateException e) {
            // A lifecycle precondition the caller can fix by driving the state machine forward.
            Json.sendError(ex, 409, String.valueOf(e.getMessage()));
        } catch (Exception e) {
            log.error(e, "Unhandled error on %s %s", method, path);
            Json.sendError(ex, 500, String.valueOf(e.getMessage()));
        } catch (Throwable t) {
            // Errors, not just Exceptions: a missing native symbol surfaces as UnsatisfiedLinkError,
            // which would otherwise kill the worker thread and leave the caller with a dropped
            // connection instead of a diagnosis.
            log.error(new RuntimeException(t), "Fatal error on %s %s", method, path);
            Json.sendError(ex, 500, t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    @Override
    public void close() {
        if (server != null) server.stop(0);
    }
}

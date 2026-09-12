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

    /* Assertions are addressed to this service, and each is accepted once.
     *
     * The audience is the public URL rather than a name, so an assertion made for one deployment
     * cannot be replayed against another. */
    private final org.minidauth.auth.ClientAssertion clientAssertions;
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
        this.clientAssertions = new org.minidauth.auth.ClientAssertion(
                config.publicUrl == null || config.publicUrl.isBlank()
                        ? "http://localhost:" + config.port
                        : config.publicUrl.replaceAll("/+$", ""));
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

        /* File a grant or revocation. Takes effect only once the quorum commits it.
         *
         * {@code vuid} is the subject: a Tide identity by default, or an application user id (a Clerk
         * uid, say) when {@code tideless} is true. A tideless grant carries no attestation and is
         * enforced by this service when it signs or vouchers for that user, not by a doken. */
        router.post("/iga/change-requests/role", (ex, p) -> {
            Operator by = authenticate(ex);
            Map<String, Object> body = Json.readBody(ex);
            ChangeRequest cr = gov.fileRoleChange(by,
                    Json.requireString(body, "vuid"),
                    Json.requireString(body, "role"),
                    Boolean.TRUE.equals(body.get("revoke")),
                    Boolean.TRUE.equals(body.get("tideless")));
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
            String sessionId = Json.requireString(body, "sessionId");

            /* Serve our own vouchers unless the caller names an issuer.
             *
             * An integrating app has no business knowing where vouchers come from, and requiring it
             * to pass one meant every integration started with a 400 and a puzzle. Registering the
             * session here is what lets the voucher endpoint recognise the enclave when it calls. */
            String voucherUrl = Json.string(body, "voucherUrl");
            if (voucherUrl == null || voucherUrl.isBlank()) voucherUrl = config.voucherUrl;
            if (voucherUrl == null || voucherUrl.isBlank()) {
                rememberSignInSession(sessionId);
                voucherUrl = voucherBase() + "/tide/vouchers?session="
                        + java.net.URLEncoder.encode(sessionId, java.nio.charset.StandardCharsets.UTF_8);
            }

            java.net.URI url = tideAuth.loginUrl(
                    sessionId,
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
            /* Two ways in. An operator, as before, or a sign-in this service started, which is how
             * the enclave gets here: it runs in the user's browser and has no credential to
             * present. Anything else is turned away, because issuing a voucher spends the VRK and
             * draws on the licence's account quota. */
            if (!isLiveSignInSession(Router.query(ex).get("session"))) {
                authenticate(ex);
            }
            Json.sendRaw(ex, 200,
                    tideAuth.vouchers(voucherRequestFrom(ex)),
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

        /* Sign a payload on behalf of an application user who has no Tide identity.
         *
         * The user never holds a doken. The calling app authenticates here with its own token and
         * passes the user id it verified from its own login (Clerk, say) and the role that gates this
         * operation. This service checks the user's committed, quorum-approved grant holds that role,
         * and only then asks the cohort to sign. The authority over who may sign is a governed record
         * read here, not a doken the cohort checks, which is the whole point of the tideless path.
         *
         * The signature that comes back is an ordinary VVK threshold signature: verifiable by anyone
         * with the vendor public key, over exactly the payload sent. */
        router.post("/vault/sign", (ex, p) -> {
            authenticate(ex);
            Map<String, Object> body = Json.readBody(ex);
            String signature = gov.signForSubject(
                    Json.requireString(body, "uid"),
                    Json.requireString(body, "role"),
                    Json.requireString(body, "payload").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            Json.send(ex, 200, Map.of("signature", signature));
        });

        /* Issue a decrypt voucher on behalf of an application user who has no Tide identity.
         *
         * The browser builds the voucher request (this service cannot: a voucher is bound to values
         * the browser's decrypt flow chooses). What this service decides is WHETHER to issue it: it
         * checks the user's quorum-approved grant holds the gating role first. With the voucher the
         * browser runs the threshold decrypt against the cohort; without it the cohort refuses. So
         * the read gate is this service reading a governed role, and the decrypt still happens in the
         * browser with the key never assembled. */
        router.post("/vault/voucher", (ex, p) -> {
            authenticate(ex);
            Map<String, Object> body = Json.readBody(ex);
            if (!gov.subjectHolds(Json.requireString(body, "uid"), Json.requireString(body, "role"))) {
                throw new Json.HttpError(403, Json.requireString(body, "uid")
                        + " does not hold " + Json.requireString(body, "role")
                        + ", so this service will not voucher a decrypt for them");
            }
            Json.sendRaw(ex, 200,
                    tideAuth.vouchers(Json.requireString(body, "voucherRequest")),
                    "application/json; charset=utf-8");
        });

        // Read-only view of the configured roster and the bar it sets. The roster itself is
        // deployment configuration; there is no route that changes it.
        // ------------------------------------------------------- the governance console
        //
        // Served from here, not from the applications this service protects. Those applications are
        // exactly what the threat model assumes gets compromised, so a console rendered inside one, // holding a credential that can grant roles, would put the ability to authorise reads
        // inside the blast radius it is supposed to be outside of.

        router.get("/console", (ex, p) -> Json.sendRaw(ex, 200, console(), "text/html; charset=utf-8"));

        /* A page that runs one encrypt and one decrypt through the enclave, end to end.
         *
         * Served from the console's own origin so it can reuse that sign-in: the doken is bound to
         * a session key that lives in the enclave window, so a page on another origin would have to
         * start its own sign-in and would get a different key. */
        router.get("/console/vault", (ex, p) ->
                Json.sendRaw(ex, 200, asset("/console/vault.html"), "text/html; charset=utf-8"));

        /* Start a sign-in. Unauthenticated on purpose: this IS the way to get a credential, so
           requiring one would be circular. Nothing secret is returned, the login URL carries the
           authorizer pack and signatures over public values, and the redirect target is the
           console's own, taken from configuration rather than from the caller, so this cannot be
           used to point a Tide sign-in at somebody else's page. */
        router.post("/console/session/login-url", (ex, p) -> {
            Map<String, Object> body = Json.readBody(ex);
            String sessionId = Json.requireString(body, "sessionId");
            rememberSignInSession(sessionId);

            /* Serve our own vouchers unless pointed elsewhere. The console is meant to work on its
             * own, and an unset MC_VOUCHER_URL used to mean it could not sign anyone in at all. */
            String voucherUrl = config.voucherUrl;
            if (voucherUrl == null || voucherUrl.isBlank()) {
                voucherUrl = voucherBase() + "/tide/vouchers?session="
                        + java.net.URLEncoder.encode(sessionId, java.nio.charset.StandardCharsets.UTF_8);
            }

            java.net.URI url = tideAuth.loginUrl(
                    sessionId,
                    consoleRedirectUri(),
                    voucherUrl,
                    null,
                    org.minidauth.tide.TideAuthService.requireEnclaveType(
                            Json.string(body, "enclaveType")));
            Json.send(ex, 200, Map.of("url", url.toString()));
        });

        /* A voucher URL for an enclave window this page is about to open.
         *
         * Every enclave flow needs one, not just sign-in: the enclave refuses to start without it
         * and dies before it announces itself, so a caller that omits it sees a window that never
         * replies rather than an error. Registering the session here is what lets the voucher
         * endpoint tell this window apart from an anonymous caller. */
        router.post("/console/session/voucher-url", (ex, p) -> {
            authenticate(ex);
            String sessionId = "enclave-" + java.util.UUID.randomUUID();
            rememberSignInSession(sessionId);
            Json.send(ex, 200, Map.of("voucherUrl", voucherBase() + "/tide/vouchers?session="
                    + java.net.URLEncoder.encode(sessionId, java.nio.charset.StandardCharsets.UTF_8)));
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

        /* The encrypt policy, for any browser that wants to encrypt.
         *
         * Unauthenticated on purpose. Encrypting is the open half of this design: a public form has
         * to be able to encrypt what it collects, so the writing side holds nothing worth stealing.
         * The bytes here are a signed policy the ORKs already enforce, not a credential, and the
         * cohort checks that signature regardless of who presents it.
         *
         * Only a policy scoped solely to encryption is ever served, so a wider policy that happens
         * to include the encrypt model cannot be handed out here by accident. */
        /* The decrypt policy. Authenticated, unlike its encrypt counterpart, because it is only
         * useful to someone who already holds the role it names, and there is no reason to hand the
         * shape of the reading side to anyone who asks. */
        router.get("/vault/decrypt-policy", (ex, p) -> {
            authenticate(ex);
            var policy = gov.publicDecryptPolicy().orElseThrow(() -> new Json.HttpError(404,
                    "No decryption policy is deployed"));
            Json.send(ex, 200, Map.of(
                    "policyId", policy.policyId,
                    "contractId", policy.contractId,
                    "vvkId", policy.keyId,
                    "modelIds", policy.modelIds,
                    "params", policy.params == null ? Map.of() : policy.params,
                    "policy", policy.policyBytes));
        });

        router.get("/vault/encrypt-policy", (ex, p) -> {
            var policy = gov.publicEncryptPolicy().orElseThrow(() -> new Json.HttpError(404,
                    "No encryption policy is deployed, so there is nothing a browser could encrypt "
                    + "under yet"));
            Json.send(ex, 200, Map.of(
                    "policyId", policy.policyId,
                    "contractId", policy.contractId,
                    "vvkId", policy.keyId,
                    "modelIds", policy.modelIds,
                    "policy", policy.policyBytes));
        });

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
                    + "sign-in, 'Assertion <jwt>' signed by a client's key, or 'Bearer <token>' for "
                    + "a configured operator");
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

        /* A caller proving it holds a private key, rather than repeating a shared one.
         *
         * Preferred for applications: nothing this service stores can be presented as a credential,
         * so a copy of the operators file is worth nothing on its own. */
        if (header.startsWith("Assertion ")) {
            String compact = header.substring("Assertion ".length()).trim();
            String name;
            try {
                name = clientAssertions.verify(compact, operators::publicKeyFor);
            } catch (org.minidauth.auth.ClientAssertion.Invalid e) {
                throw new Json.HttpError(401, e.getMessage());
            }
            return operators.byName(name).orElseThrow(() ->
                    new Json.HttpError(401, "Unknown client"));
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
    /* Sign-in sessions this service started, and when they expire.
     *
     * Their only job is to gate voucher issuance. A voucher costs the VRK and draws on the
     * licence's account quota, so the endpoint cannot simply be open; but the enclave fetching one
     * runs in the user's browser and has no operator credential to present. Recording the session
     * when the login URL is built means the endpoint can tell a sign-in this service started from
     * an anonymous caller, without the enclave having to carry anything extra.
     *
     * In memory on purpose. A session outliving a restart buys nothing: the sign-in it belongs to
     * is over long before. */
    private final Map<String, Long> signInSessions = new java.util.concurrent.ConcurrentHashMap<>();

    private static final long SESSION_TTL_MS = 10 * 60 * 1000L;
    private static final int MAX_SESSIONS = 10_000;

    private void rememberSignInSession(String sessionId) {
        long now = System.currentTimeMillis();
        signInSessions.values().removeIf(expiry -> expiry < now);
        // A cap rather than an eviction policy: this is a bound on memory, not a cache.
        if (signInSessions.size() >= MAX_SESSIONS) {
            throw new Json.HttpError(503, "Too many sign-ins in flight; try again shortly");
        }
        signInSessions.put(sessionId, now + SESSION_TTL_MS);
    }

    private boolean isLiveSignInSession(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) return false;
        Long expiry = signInSessions.get(sessionId);
        if (expiry == null) return false;
        if (expiry < System.currentTimeMillis()) {
            signInSessions.remove(sessionId);
            return false;
        }
        return true;
    }

    /**
     * Allow the enclave, and only the enclave, to call the voucher endpoint from its own origin.
     *
     * <p>Scoped deliberately narrowly. The origin has to match the ORK network this service is
     * configured against, and the path has to be the voucher route, because that is the only thing
     * a browser reaches cross-origin here. Everything else is same-origin from the console.
     *
     * <p>The private-network header is what makes this work at all in current Chrome: a page on a
     * public HTTPS origin reaching {@code localhost} is a private network request, and the preflight
     * is refused without it. Its absence looks like a plain network failure with no status, which is
     * why it is worth naming.
     *
     * @return true if this request is a cross-origin enclave call that was allowed
     */
    /**
     * Pull {@code voucherRequest} out of the request, whatever shape it arrives in.
     *
     * <p>The enclave sends a {@code FormData}, so this is multipart with a boundary rather than the
     * JSON everything else here speaks. That is not negotiable from this end, and reading it wrong
     * shows up as a bare 400 with no hint that the body was the problem, so both shapes are
     * accepted and anything else says plainly what it got.
     */
    @SuppressWarnings("unchecked")
    private static String voucherRequestFrom(HttpExchange ex) throws IOException {
        String contentType = ex.getRequestHeaders().getFirst("Content-Type");
        byte[] raw;
        try (java.io.InputStream in = ex.getRequestBody()) {
            raw = in.readAllBytes();
        }

        if (contentType != null && contentType.toLowerCase(java.util.Locale.ROOT).startsWith("multipart/form-data")) {
            String value = multipartField(raw, contentType, "voucherRequest");
            if (value == null) {
                throw new Json.HttpError(400, "multipart body has no voucherRequest field");
            }
            return value;
        }

        // Anything else is treated as the JSON the rest of the API uses.
        Map<String, Object> body;
        try {
            body = raw.length == 0
                    ? new LinkedHashMap<>()
                    : Json.mapper().readValue(raw, LinkedHashMap.class);
        } catch (com.fasterxml.jackson.core.JacksonException e) {
            throw new Json.HttpError(400, "Expected a multipart form or JSON body, got "
                    + (contentType == null ? "no content type" : contentType));
        }
        return Json.requireString(body, "voucherRequest");
    }

    /**
     * Read one named field out of a multipart body.
     *
     * <p>Deliberately small: the enclave sends a handful of short text fields and no files, so this
     * splits on the boundary and reads the part whose disposition carries the name. It decodes as
     * UTF-8 because every field the enclave sends is text.
     *
     * @return the field's value, or null if the body does not contain it
     */
    private static String multipartField(byte[] raw, String contentType, String name) {
        int at = contentType.toLowerCase(java.util.Locale.ROOT).indexOf("boundary=");
        if (at < 0) return null;
        String boundary = contentType.substring(at + "boundary=".length()).trim();
        if (boundary.startsWith("\"")) {
            int end = boundary.indexOf('"', 1);
            boundary = end < 0 ? boundary.substring(1) : boundary.substring(1, end);
        }
        int semi = boundary.indexOf(';');
        if (semi >= 0) boundary = boundary.substring(0, semi).trim();

        String body = new String(raw, java.nio.charset.StandardCharsets.UTF_8);
        for (String part : body.split(java.util.regex.Pattern.quote("--" + boundary))) {
            // Headers and value are separated by a blank line, as in any multipart part.
            int split = part.indexOf("\r\n\r\n");
            int skip = 4;
            if (split < 0) {
                split = part.indexOf("\n\n");
                skip = 2;
            }
            if (split < 0) continue;

            String headers = part.substring(0, split);
            if (!headers.contains("name=\"" + name + "\"")) continue;

            String value = part.substring(split + skip);
            // Trim the CRLF the next boundary is preceded by.
            while (value.endsWith("\r") || value.endsWith("\n") || value.endsWith("-")) {
                value = value.substring(0, value.length() - 1);
            }
            return value;
        }
        return null;
    }

    private boolean applyEnclaveCors(HttpExchange ex, String path) {
        if (!"/tide/vouchers".equals(path)) return false;

        String origin = ex.getRequestHeaders().getFirst("Origin");
        if (origin == null || origin.isBlank()) return false;
        if (!origin.equals(enclaveOrigin())) return false;

        var out = ex.getResponseHeaders();
        out.set("Access-Control-Allow-Origin", origin);
        out.set("Access-Control-Allow-Methods", "POST, OPTIONS");
        out.set("Access-Control-Allow-Headers", "Content-Type");
        out.set("Access-Control-Allow-Private-Network", "true");
        out.set("Access-Control-Max-Age", "600");
        out.set("Vary", "Origin");
        return true;
    }

    /** True when this request arrived on the address the voucher endpoint is published at. */
    private boolean isPublishedVoucherHost(HttpExchange ex) {
        String base = config.voucherPublicUrl;
        if (base == null || base.isBlank()) base = voucherUrlFromFile();
        if (base == null || base.isBlank()) return false;

        String host = ex.getRequestHeaders().getFirst("Host");
        if (host == null || host.isBlank()) return false;
        try {
            String published = java.net.URI.create(base.replaceAll("/+$", "")).getHost();
            return published != null
                    && published.equalsIgnoreCase(host.split(":", 2)[0]);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** The scheme and host of the configured home ORK, which is where the enclave is served from. */
    private String enclaveOrigin() {
        try {
            java.net.URI u = java.net.URI.create(config.homeOrkUrl);
            int port = u.getPort();
            return u.getScheme() + "://" + u.getHost() + (port == -1 ? "" : ":" + port);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Where the enclave reaches the voucher endpoint, which need not be where the console is. */
    private String voucherBase() {
        String configured = config.voucherPublicUrl;
        if (configured == null || configured.isBlank()) {
            configured = voucherUrlFromFile();
        }
        return configured == null || configured.isBlank()
                ? publicBase()
                : configured.replaceAll("/+$", "");
    }

    /**
     * The address a tunnel published, if one has.
     *
     * <p>Read per call rather than cached, because the file appears seconds after this service
     * starts and may change if the tunnel reconnects. It is one small local read on a path this
     * service was configured with, not something a request can influence.
     */
    private String voucherUrlFromFile() {
        String path = config.voucherPublicUrlFile;
        if (path == null || path.isBlank()) return null;
        try {
            String value = java.nio.file.Files.readString(java.nio.file.Path.of(path)).trim();
            return value.isBlank() ? null : value;
        } catch (java.io.IOException e) {
            // No tunnel yet, or none at all. Both are ordinary.
            return null;
        }
    }

    private String publicBase() {
        return config.publicUrl == null || config.publicUrl.isBlank()
                ? "http://localhost:" + config.port
                : config.publicUrl.replaceAll("/+$", "");
    }

    private String consoleRedirectUri() {
        return publicBase() + "/console";
    }

    /** Any console asset, loaded from the jar. */
    private static String asset(String path) {
        try (java.io.InputStream in = ApiServer.class.getResourceAsStream(path)) {
            if (in == null) throw new Json.HttpError(500, "Missing from this build: " + path);
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            throw new Json.HttpError(500, "Could not read " + path + ": " + e.getMessage());
        }
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

        /* A published address serves the voucher endpoint and nothing else.
         *
         * When the voucher endpoint is reachable from the internet so the enclave can call it, the
         * console, the ops routes and the governance API must not come with it. They are recognised
         * by the host they arrived on rather than by a separate proxy, so there is one service to
         * run and one place the rule lives. */
        if (isPublishedVoucherHost(ex) && !"/tide/vouchers".equals(path)) {
            Json.sendError(ex, 404, "This address serves the voucher endpoint only");
            return;
        }

        // The enclave runs on the ORK's own origin and fetches vouchers from here, so that one
        // route needs CORS. Nothing else does: the console is served from this origin.
        if (applyEnclaveCors(ex, path) && "OPTIONS".equals(method)) {
            ex.sendResponseHeaders(204, -1);
            ex.close();
            return;
        }

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

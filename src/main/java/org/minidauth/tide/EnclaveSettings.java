package org.minidauth.tide;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * What the enclave is told about this vendor, and where it may redirect back to.
 *
 * <p>Every entry in {@code redirectUris} is signed individually by the settings ceremony: the
 * enclave refuses to return to a URI it has no signature for, so an attacker cannot point the
 * callback at their own origin.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class EnclaveSettings {
    /** Whether the enclave may self-register new users. */
    public boolean regOn;
    /** Whether key backup (Ragnarök offboarding) is enabled. */
    public boolean backupOn;
    public String logoUrl;
    public String imageUrl;
    /** Redirect URIs the enclave may return to. The first is the login callback. */
    public List<String> redirectUris = new ArrayList<>();

    /**
     * Origins allowed to hold a postMessage channel with the enclave.
     *
     * <p>Separate from {@link #redirectUris} because they authorise a different thing. A redirect
     * signature says "the enclave may navigate back here"; a client-origin signature says "this
     * origin may talk to the enclave in an embedded window". The enclave verifies the latter with
     * {@code verify(clientOriginAuth, vendorPublic, origin)} and refuses the channel outright if it
     * does not check out, which is what stops any page from framing the enclave and asking it to
     * decrypt.
     *
     * <p>Give the scheme, host and port only, e.g. {@code http://localhost:8090}.
     */
    public List<String> clientOrigins = new ArrayList<>();

    public EnclaveSettings() {}
}

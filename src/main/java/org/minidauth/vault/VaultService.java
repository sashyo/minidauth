package org.minidauth.vault;

import org.midgard.Midgard;
import org.minidauth.store.VendorKeyStore;

/**
 * Encrypt and decrypt through the ORK network.
 *
 * <p>The work happens across the cohort, not here. This service holds the VRK and passes it, along
 * with the caller's doken, to Midgard; the key that actually protects the data exists only as shares
 * spread across the ORKs, so no single node can read anything and neither can this process on its
 * own.
 *
 * <p>Both directions require a doken, which is the important part: there is no way to call these
 * without a real Tide sign-in behind you, and the roles the cohort put in that doken are what decide
 * whether the call is allowed. That check lives one layer up in the API, against the governed grant
 * record, so who can read is settled by the quorum rather than by whoever is holding a token.
 *
 * <p>Note what this is not. This is the vault flow, and it needs an identity at both ends. The
 * policy-enabled flow is the one that lets a stranger encrypt without any identity at all, and it
 * runs in the browser, not here.
 *
 * <h2>Signing is not here yet, and why</h2>
 *
 * The ORK supports policy-gated signing: a request named {@code BasicCustom<Name:Version>} goes
 * through the Policy flow, and because it is a custom request the contract's {@code ValidateData}
 * is handed the exact bytes before anything is signed. A policy can therefore refuse a payload it
 * does not recognise, which is what makes signing with a shared key safe.
 *
 * <p>It is not reachable from Java. {@code ModelRequest} exposes no way to set a name, version,
 * draft or auth flow, and there is no custom request class in the bindings; the concrete classes
 * each hard-code their own name. Reaching it needs either an addition to MidgardJava or building
 * the request transport by hand, which is the same wall that policy-enabled encryption runs into.
 */
public final class VaultService {

    private final VendorKeyStore store;

    public VaultService(VendorKeyStore store) {
        this.store = store;
    }

    /**
     * Encrypt with the vendor key.
     *
     * @param doken the caller's doken, already verified
     * @param data  plaintext
     * @return the ciphertext, opaque to everything but the ORK network
     */
    public String encrypt(String doken, String data) throws Exception {
        return Midgard.Encrypt(doken, data, requireVrk());
    }

    /**
     * Decrypt with the vendor key.
     *
     * @param doken     the caller's doken, already verified
     * @param encrypted ciphertext produced by {@link #encrypt}
     */
    public String decrypt(String doken, String encrypted) throws Exception {
        return Midgard.Decrypt(doken, encrypted, requireVrk());
    }

    private String requireVrk() {
        String vrk = store.getVRK();
        if (vrk == null || vrk.isBlank()) {
            throw new IllegalStateException("No active vendor key, so there is nothing to encrypt with");
        }
        return vrk;
    }
}

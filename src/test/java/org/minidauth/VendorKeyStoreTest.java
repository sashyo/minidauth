package org.minidauth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.minidauth.store.VendorKeyStore;
import org.minidauth.vrk.LicenseState;
import org.minidauth.vrk.VendorKeyState;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class VendorKeyStoreTest {

    @TempDir Path dir;

    private VendorKeyStore store() {
        return new VendorKeyStore(dir.resolve("vendor-key.json"), 3, 5);
    }

    @Test
    void aFreshStoreHasNoKeyAndNoLicense() {
        VendorKeyStore s = store();
        assertEquals(VendorKeyState.NotCreated, s.vendorKeyState());
        assertEquals(LicenseState.NotCreated, s.licenseState());
        assertNull(s.getVRK());
        assertNull(s.getPendingVRKInfo());
    }

    @Test
    void rollbackDiscardsUncommittedChanges() {
        VendorKeyStore s = store();
        s.setPendingVRKInfo("vrk-1", "GVRK1", "", "ytmp", "GVRK1", "obf");
        assertEquals(VendorKeyState.AwaitingPayment, s.vendorKeyState());

        s.rollback();
        assertEquals(VendorKeyState.NotCreated, s.vendorKeyState(),
                "an uncommitted mint must not survive a rollback");
    }

    @Test
    void commitSurvivesAReload() {
        VendorKeyStore s = store();
        s.setPendingVRKInfo("vrk-1", "GVRK1", "", "ytmp", "GVRK1", "obf");
        s.setVZK("vrk-1");
        s.commit();

        VendorKeyStore reloaded = store();
        assertEquals(VendorKeyState.AwaitingPayment, reloaded.vendorKeyState());
        assertEquals("vrk-1", reloaded.getVZK());
        assertEquals("GVRK1", reloaded.getPendingVRKInfo().pendingGVRK());
    }

    @Test
    void rollbackAfterACommitRestoresTheCommittedState() {
        VendorKeyStore s = store();
        s.setPendingVRKInfo("vrk-1", "GVRK1", "", "ytmp", "GVRK1", "obf");
        s.commit();

        s.setPendingGVRK("GVRK-SCRIBBLE");
        s.rollback();
        assertEquals("GVRK1", s.getPendingVRKInfo().pendingGVRK());
    }

    @Test
    void switchPromotesThePendingKeyAndClearsThePendingSlot() {
        VendorKeyStore s = store();
        s.setPendingVRKInfo("vrk-1", "GVRK1", "SIG1", "ytmp", "WALLET1", "obf");
        s.commit();

        s.switchPendingVRK();
        assertEquals("vrk-1", s.getVRK());
        assertEquals("GVRK1", s.get(VendorKeyStore.GVRK));
        assertEquals("SIG1", s.get(VendorKeyStore.GVRK_SIG));
        assertEquals("WALLET1", s.get(VendorKeyStore.WALLET_ID));
        assertNull(s.getPendingVRKInfo(), "the pending slot must be empty after a promotion");
    }

    @Test
    void switchingWithNothingPendingIsRefused() {
        VendorKeyStore s = store();
        assertThrows(IllegalStateException.class, s::switchPendingVRK);
    }

    @Test
    void finalizingProducesAnActiveLicense() {
        VendorKeyStore s = store();
        s.setPendingVRKInfo("vrk-1", "GVRK1", "", "ytmp", "WALLET1", "obf");
        s.commit();

        s.finalizeVendorInfo("vvk-id", "FIRSTADMIN", "FASIG", "GVRKSIG", "VVKPUB", "eVVK");
        s.commit();

        assertEquals(VendorKeyState.Created, s.vendorKeyState());
        assertEquals(LicenseState.Active, s.licenseState());
        assertEquals("GVRKSIG", s.get(VendorKeyStore.GVRK_SIG));
        assertEquals("VVKPUB", s.get(VendorKeyStore.OBF_GVVK));
        assertEquals("vvk-id", s.midgardSettings().VVKId);
    }

    @Test
    void aRotationErrorMarksTheLicenseAsNeedingAttentionAndIsDurable() {
        VendorKeyStore s = store();
        s.setPendingVRKInfo("vrk-1", "GVRK1", "", "ytmp", "WALLET1", "obf");
        s.commit();
        s.finalizeVendorInfo("vvk-id", "FA", "FASIG", "GVRKSIG", "VVKPUB", null);
        s.commit();

        // A half-written change plus a failure: the change is dropped, the error is kept.
        s.setPendingGVRK("HALF-WRITTEN");
        s.logRotationError("the cohort refused the pending key");

        assertEquals(LicenseState.Active_NeedsAttention, s.licenseState());
        assertNull(s.get(VendorKeyStore.PENDING_GVRK), "the half-written change must be rolled back");
        assertEquals("the cohort refused the pending key", store().get(VendorKeyStore.LATEST_ROTATION_ERROR));
    }

    @Test
    void thePrivateKeysAreNotExposedInTheConfigView() {
        VendorKeyStore s = store();
        s.setPendingVRKInfo("SUPER-SECRET-VRK", "GVRK1", "", "ytmp", "WALLET1", "obf");
        s.setVZK("SUPER-SECRET-VZK");
        s.commit();

        String rendered = String.valueOf(s.redactedView());
        assertFalse(rendered.contains("SUPER-SECRET-VRK"));
        assertFalse(rendered.contains("SUPER-SECRET-VZK"));
        assertTrue(rendered.contains("<redacted:"));
    }

    @Test
    void cohortThresholdsReachTheMidgardSettings() {
        VendorKeyStore s = store();
        assertEquals(3, s.midgardSettings().Threshold_T);
        assertEquals(5, s.midgardSettings().Threshold_N);
    }
}

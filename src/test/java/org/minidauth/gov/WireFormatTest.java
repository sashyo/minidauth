package org.minidauth.gov;

import org.junit.jupiter.api.Test;
import org.midgard.Serialization.Tools;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The two wire shapes the ORK reads back. Both were found the hard way against a live cohort, so
 * they are pinned here: a regression in either produces a failure inside the ORK, far from its
 * cause.
 */
class WireFormatTest {

    /**
     * Mirrors the ORK's read path exactly:
     * {@code CompilableContractTransport} takes {@code [0]=type, [1]=payload}, then
     * {@code ForsetiContract} reads {@code payload[1]} as the inner block and takes
     * {@code inner[0]}=source, {@code inner[1]}=entryType.
     */
    @Test
    void anUploadedContractUnwrapsTheWayTheOrkReadsIt() {
        String source = "public class Contract : IAccessPolicy { }";
        byte[] payload = GovernanceService.contractUploadPayload(source, "Contract");

        // AddContractToUpload wraps this again as [type, payload]; rebuild that envelope.
        byte[] envelope = Tools.CreateTideMemory("forseti".getBytes(StandardCharsets.UTF_8), payload);

        assertEquals("forseti", new String(Tools.GetValue(envelope, 0), StandardCharsets.UTF_8));
        byte[] transported = Tools.GetValue(envelope, 1);

        byte[] inner = Tools.GetValue(transported, 1);
        assertEquals(source, new String(Tools.GetValue(inner, 0), StandardCharsets.UTF_8));
        assertEquals("Contract", new String(Tools.GetValue(inner, 1), StandardCharsets.UTF_8));
    }

    @Test
    void anUploadedContractIsNotMistakenForACompiledDll() {
        // The ORK sniffs a pre-compiled DLL by the PE "MZ" header on the payload's first bytes.
        // A TideMemory block must never start with those, or source would be loaded as a DLL.
        byte[] payload = GovernanceService.contractUploadPayload("class C {}", "C");
        assertFalse(payload.length >= 2 && payload[0] == 0x4D && payload[1] == 0x5A,
                "payload must not begin with the MZ PE header");
    }

    @Test
    void thePublicPointIsReadOutOfAnAuthorizerPack() {
        // A real gVRK pack prefix, truncated after the point.
        String pack = "010000000500000056524B3A31370000000100000023000000200000"
                + "CACC0164771B30082F4F39B135C3858E0F00C5697E98849C14EC25AA66138F3A"
                + "08000000BB43D06A00000000";
        assertEquals("CACC0164771B30082F4F39B135C3858E0F00C5697E98849C14EC25AA66138F3A",
                GovernanceService.authorizerPackPublicPoint(pack));
    }

    @Test
    void anUnparseablePackYieldsNoPointRatherThanAWrongOne() {
        assertNull(GovernanceService.authorizerPackPublicPoint(null));
        assertNull(GovernanceService.authorizerPackPublicPoint("deadbeef"));
    }

    /**
     * Two packs minted against the same VRK carry the same point; a rotation changes it. This is
     * what the firstAdmin-pack guard keys off.
     */
    @Test
    void differentPacksOverTheSameKeyAgreeOnThePoint() {
        String point = "9F719B0189FC090C06388E4FB6DD6FE85CC951BF8C56C0A1D8798771AA1A532F";
        String gvrk = "010000000500000056524B3A3137000000010000002300000020000" + "0" + point + "AABB";
        String firstAdmin = "010000000500000056524B3A31370000000100000023000000200000" + point + "CCDD";
        assertEquals(GovernanceService.authorizerPackPublicPoint(gvrk),
                GovernanceService.authorizerPackPublicPoint(firstAdmin));
    }
}

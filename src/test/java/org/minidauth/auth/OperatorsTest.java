package org.minidauth.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class OperatorsTest {

    @TempDir Path dir;

    private Path roster(String json) throws IOException {
        Path f = dir.resolve("operators.json");
        Files.writeString(f, json);
        return f;
    }

    @Test
    void anAbsentRosterFileIsNotAnError() {
        Operators o = Operators.load(dir.resolve("missing.json"), null, null);
        assertEquals(0, o.approverCount());
        assertTrue(o.authenticate("anything").isEmpty());
    }

    @Test
    void theSingleAdminTokenGetsEveryRole() {
        Operators o = Operators.load(null, "tok", "admin");
        Operator admin = o.authenticate("tok").orElseThrow();
        assertEquals("admin", admin.name());
        assertTrue(admin.has(Role.VRK_ADMIN));
        assertTrue(admin.has(Role.APPROVER));
    }

    @Test
    void rosterEntriesAuthenticateWithTheirOwnRoles() throws IOException {
        Operators o = Operators.load(roster("""
                [{"name":"alice","token":"a","roles":["approver"]},
                 {"name":"ops","token":"b","roles":["vrk-admin"]}]"""), null, null);

        Operator alice = o.authenticate("a").orElseThrow();
        assertTrue(alice.has(Role.APPROVER));
        assertFalse(alice.has(Role.VRK_ADMIN));

        Operator ops = o.authenticate("b").orElseThrow();
        assertTrue(ops.has(Role.VRK_ADMIN));
        assertFalse(ops.has(Role.APPROVER));

        assertEquals(1, o.approverCount(), "only alice can approve");
    }

    @Test
    void anUnknownTokenAuthenticatesNobody() throws IOException {
        Operators o = Operators.load(roster("""
                [{"name":"alice","token":"a","roles":["approver"]}]"""), null, null);
        assertTrue(o.authenticate("wrong").isEmpty());
        assertTrue(o.authenticate("").isEmpty());
        assertTrue(o.authenticate(null).isEmpty());
    }

    /**
     * Two operators sharing a token would be indistinguishable in the approval record, which is
     * exactly what four-eyes counts on. Refuse at boot rather than mis-attribute an approval.
     */
    @Test
    void twoOperatorsSharingATokenIsRefusedAtBoot() throws IOException {
        Path f = roster("""
                [{"name":"alice","token":"same","roles":["approver"]},
                 {"name":"bob","token":"same","roles":["approver"]}]""");
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> Operators.load(f, null, null));
        assertTrue(e.getMessage().contains("share a token"));
    }

    @Test
    void aDuplicateNameIsRefusedAtBoot() throws IOException {
        Path f = roster("""
                [{"name":"alice","token":"a","roles":["approver"]},
                 {"name":"alice","token":"b","roles":["approver"]}]""");
        assertTrue(assertThrows(IllegalStateException.class, () -> Operators.load(f, null, null))
                .getMessage().contains("Duplicate operator name"));
    }

    @Test
    void anEntryMissingItsRolesOrTokenIsRefusedAtBoot() throws IOException {
        assertThrows(IllegalStateException.class, () -> Operators.load(
                roster("[{\"name\":\"alice\",\"token\":\"a\",\"roles\":[]}]"), null, null));
        assertThrows(IllegalStateException.class, () -> Operators.load(
                roster("[{\"name\":\"alice\",\"roles\":[\"approver\"]}]"), null, null));
    }

    @Test
    void anUnknownRoleNamesTheOnesThatExist() throws IOException {
        Path f = roster("[{\"name\":\"alice\",\"token\":\"a\",\"roles\":[\"superuser\"]}]");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Operators.load(f, null, null))
                .getMessage().contains("vrk-admin"));
    }

    @Test
    void roleWireNamesRoundTrip() {
        for (Role r : Role.values()) {
            assertEquals(r, Role.fromWire(r.wire()));
        }
        assertEquals(Role.VRK_ADMIN, Role.fromWire("VRK_ADMIN"));
    }
}

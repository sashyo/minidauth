package org.minidauth.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.function.LongSupplier;

import org.junit.jupiter.api.Test;

class SignInSessionsTest {

    /** A clock the test moves by hand. */
    private static final class Clock implements LongSupplier {
        long now = 1_000_000L;
        public long getAsLong() { return now; }
    }

    @Test
    void refusesASessionIdWithoutEnoughEntropy() {
        SignInSessions s = new SignInSessions(1000, 100, 5, 16, 100, new Clock());
        for (String weak : new String[] { null, "", "   ", "short", "0123456789" }) {
            Json.HttpError e = assertThrows(Json.HttpError.class, () -> s.remember(weak));
            assertEquals(400, e.status);
        }
        // A full-length random id is accepted.
        s.remember("app-123e4567-e89b-12d3-a456-426614174000");
    }

    @Test
    void aRememberedSessionIsLiveUntilItExpires() {
        Clock clock = new Clock();
        SignInSessions s = new SignInSessions(1000, 100, 5, 8, 100, clock);
        assertFalse(s.isLive("never-remembered"));
        s.remember("session-aaaaaa");
        assertTrue(s.isLive("session-aaaaaa"));
        clock.now += 1001; // past the TTL
        assertFalse(s.isLive("session-aaaaaa"));
    }

    @Test
    void eachSessionMaySpendOnlyItsVoucherBudget() {
        SignInSessions s = new SignInSessions(10_000, 100, 2, 8, 100, new Clock());
        s.remember("session-budget");
        assertTrue(s.claimVoucher("session-budget"));   // 1
        assertTrue(s.claimVoucher("session-budget"));   // 2
        assertFalse(s.claimVoucher("session-budget"));  // over the per-session budget
        // A session that was never started, or has expired, claims nothing.
        assertFalse(s.claimVoucher("session-unknown"));
    }

    @Test
    void aServiceWideCeilingCapsTheFloodAcrossSessions() {
        Clock clock = new Clock();
        SignInSessions s = new SignInSessions(10_000_000, 100, 100, 8, 3, clock);
        s.remember("session-one1");
        s.remember("session-two2");
        assertTrue(s.claimVoucher("session-one1"));   // 1
        assertTrue(s.claimVoucher("session-one1"));   // 2
        assertTrue(s.claimVoucher("session-two2"));   // 3
        assertFalse(s.claimVoucher("session-two2"));  // service ceiling for the minute
        clock.now += 60_000;                          // next minute
        assertTrue(s.claimVoucher("session-two2"));   // window reset
    }

    @Test
    void refusesToRememberMoreThanTheSessionCap() {
        SignInSessions s = new SignInSessions(10_000, 2, 5, 8, 100, new Clock());
        s.remember("session-one1");
        s.remember("session-two2");
        Json.HttpError e = assertThrows(Json.HttpError.class, () -> s.remember("session-three"));
        assertEquals(503, e.status);
    }
}

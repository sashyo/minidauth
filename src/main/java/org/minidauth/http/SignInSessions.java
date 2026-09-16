package org.minidauth.http;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;

/**
 * The sign-in sessions this service started, and the budget each one may spend on vouchers.
 *
 * <p>Issuing a voucher costs the VRK and draws on the licence's account quota, and the endpoint that
 * issues one is reachable without an operator credential: the enclave that fetches it runs in the
 * user's browser and has none to present. A live session id is the only thing between a caller and
 * paid quota, so this bounds what a session can cost:
 *
 * <ul>
 *   <li>a session id must carry real entropy to be remembered at all, so it cannot be guessed;</li>
 *   <li>each session may spend only a small, fixed number of vouchers, so observing one and replaying
 *       it burns a handful of quota, not thousands;</li>
 *   <li>the whole service has a per-minute voucher ceiling no flood of sessions can exceed.</li>
 * </ul>
 *
 * <p>A real sign-in needs a few vouchers; anything reaching these limits is abuse. In memory on
 * purpose: a session outliving a restart buys nothing, the sign-in it belongs to is long over.
 */
final class SignInSessions {

    private final long ttlMs;
    private final int maxSessions;
    private final int voucherBudget;       // per session
    private final int minSessionIdLength;  // entropy floor for a remembered id
    private final int perMinuteCeiling;    // whole-service voucher rate
    private final LongSupplier clock;

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private long windowStart;
    private int windowCount;

    private static final class Session {
        final long expiry;
        final AtomicInteger vouchers = new AtomicInteger();
        Session(long expiry) { this.expiry = expiry; }
    }

    SignInSessions() {
        this(10 * 60 * 1000L, 10_000, 50, 16, 300, System::currentTimeMillis);
    }

    SignInSessions(long ttlMs, int maxSessions, int voucherBudget, int minSessionIdLength,
                   int perMinuteCeiling, LongSupplier clock) {
        this.ttlMs = ttlMs;
        this.maxSessions = maxSessions;
        this.voucherBudget = voucherBudget;
        this.minSessionIdLength = minSessionIdLength;
        this.perMinuteCeiling = perMinuteCeiling;
        this.clock = clock;
    }

    /**
     * Remember a sign-in this service just started. Refuses a session id too short to be unguessable,
     * so a lazy or hostile caller cannot register one an attacker could reach the voucher endpoint
     * with by guessing.
     */
    void remember(String sessionId) {
        if (sessionId == null || sessionId.strip().length() < minSessionIdLength) {
            throw new Json.HttpError(400, "sessionId must be at least " + minSessionIdLength
                    + " characters of unguessable random");
        }
        long now = clock.getAsLong();
        sessions.values().removeIf(s -> s.expiry < now);
        // A cap rather than an eviction policy: this is a bound on memory, not a cache.
        if (sessions.size() >= maxSessions) {
            throw new Json.HttpError(503, "Too many sign-ins in flight; try again shortly");
        }
        sessions.put(sessionId, new Session(now + ttlMs));
    }

    /** Whether this session is one we started and has not expired. */
    boolean isLive(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) return false;
        Session s = sessions.get(sessionId);
        if (s == null) return false;
        if (s.expiry < clock.getAsLong()) { sessions.remove(sessionId); return false; }
        return true;
    }

    /**
     * Claim one voucher against a live session. Returns {@code false} — issue nothing — when the
     * session is not live, has spent its per-session budget, or the whole service is over its
     * per-minute ceiling. Only increments the counters when it returns {@code true}.
     */
    synchronized boolean claimVoucher(String sessionId) {
        if (!isLive(sessionId)) return false;
        Session s = sessions.get(sessionId);
        if (s == null) return false;
        if (s.vouchers.get() >= voucherBudget) return false;

        long now = clock.getAsLong();
        if (now - windowStart >= 60_000L) { windowStart = now; windowCount = 0; }
        if (windowCount >= perMinuteCeiling) return false;

        windowCount++;
        s.vouchers.incrementAndGet();
        return true;
    }

    /** Live session count, for tests and diagnostics. */
    int liveCount() {
        long now = clock.getAsLong();
        return (int) sessions.values().stream().filter(s -> s.expiry >= now).count();
    }
}

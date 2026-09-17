package org.minidauth.auth;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;

/**
 * A blocklist of revoked session ids (sid), so a logout takes effect at once instead of waiting for
 * tokens to expire. A reader token and the doken minted from it both carry a sid derived from the
 * caller's application session; when the app signs that session out it tells this service to revoke
 * the sid, and every voucher and doken-mint carrying it is refused from then on.
 *
 * <p>Eviction is by TIME, like the proof-of-possession cache: a sid only has to stay blocked until
 * every token that could bear it has expired (a doken's lifetime plus the reader token's), so a short
 * retention covers all in-flight tokens without the set growing without bound. Keyed on a
 * server-derived session id, never a value the client supplies, so it cannot be used to revoke
 * someone else's session.
 */
public final class Revocations {

    // sid -> the time after which it may be forgotten (all tokens bearing it are expired by then).
    private final Map<String, Long> until = new HashMap<>();
    private final long retentionSeconds;
    private final Clock clock;

    public Revocations(long retentionSeconds) {
        this(retentionSeconds, Clock.systemUTC());
    }

    Revocations(long retentionSeconds, Clock clock) {
        this.retentionSeconds = retentionSeconds;
        this.clock = clock;
    }

    /** Revoke a session id. Idempotent; no-op for a blank sid. */
    public synchronized void revoke(String sid) {
        if (sid == null || sid.isBlank()) return;
        long now = clock.instant().getEpochSecond();
        until.entrySet().removeIf(e -> e.getValue() <= now);
        until.put(sid, now + retentionSeconds);
    }

    /** True while the sid is revoked. A blank sid is never revoked (nothing to match). */
    public synchronized boolean isRevoked(String sid) {
        if (sid == null || sid.isBlank()) return false;
        Long u = until.get(sid);
        if (u == null) return false;
        if (u <= clock.instant().getEpochSecond()) { until.remove(sid); return false; }
        return true;
    }
}

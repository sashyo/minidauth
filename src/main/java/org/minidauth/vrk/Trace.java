package org.minidauth.vrk;

import java.security.SecureRandom;
import java.util.HexFormat;

/** W3C traceparent generation, so every ORK egress in one flow carries the same trace id. */
public final class Trace {
    private static final SecureRandom RNG = new SecureRandom();
    private static final ThreadLocal<String> CURRENT = new ThreadLocal<>();

    private Trace() {}

    /** Start a new trace for the current thread and return its traceparent. */
    public static String start() {
        byte[] traceId = new byte[16];
        byte[] spanId = new byte[8];
        RNG.nextBytes(traceId);
        RNG.nextBytes(spanId);
        String tp = "00-" + HexFormat.of().formatHex(traceId) + "-"
                + HexFormat.of().formatHex(spanId) + "-01";
        CURRENT.set(tp);
        return tp;
    }

    public static String current() {
        String tp = CURRENT.get();
        return tp != null ? tp : start();
    }

    public static void clear() {
        CURRENT.remove();
    }
}

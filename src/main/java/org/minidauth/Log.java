package org.minidauth;

import java.time.Instant;

/** Minimal stderr logger, the service deliberately carries no logging framework. */
public final class Log {
    private final String name;

    private Log(String name) { this.name = name; }

    public static Log of(Class<?> c) { return new Log(c.getSimpleName()); }

    public void info(String fmt, Object... args) { emit("INFO ", fmt, args, null); }
    public void warn(String fmt, Object... args) { emit("WARN ", fmt, args, null); }
    public void error(String fmt, Object... args) { emit("ERROR", fmt, args, null); }

    public void error(Throwable t, String fmt, Object... args) { emit("ERROR", fmt, args, t); }

    private void emit(String level, String fmt, Object[] args, Throwable t) {
        String msg = args.length == 0 ? fmt : String.format(fmt, args);
        System.err.println(Instant.now() + " " + level + " [" + name + "] " + msg);
        if (t != null) t.printStackTrace(System.err);
    }
}

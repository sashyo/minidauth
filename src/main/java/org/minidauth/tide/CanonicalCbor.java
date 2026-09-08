package org.minidauth.tide;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * A minimal CTAP2-canonical CBOR writer.
 *
 * <p>Hand-rolled rather than delegating to a CBOR library for the same reason {@link DokenBuilder}
 * is: these bytes are <b>attested</b>. The ORK re-encodes the unit and compares, so an
 * indefinite-length map, an unsorted key, or a non-minimal integer produces bytes that no longer
 * match the signature, and the failure surfaces as a signature mismatch far from its cause. Jackson's
 * CBOR writer defaults to indefinite-length containers and insertion order, neither of which is
 * canonical, so the encoding is done explicitly here.
 *
 * <p>The rules implemented, from RFC 8949 core-deterministic / CTAP2 canonical:
 * <ul>
 *   <li>Definite-length maps and arrays only.</li>
 *   <li>Integers in their shortest form.</li>
 *   <li>Map keys sorted by <b>length first, then bytewise</b>, not plain lexicographic, which is
 *       the easy mistake: {@code "attributes"} sorts before {@code "first_name"} on bytes, but both
 *       sort after {@code "last_name"} because it is shorter.</li>
 * </ul>
 */
public final class CanonicalCbor {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    /** Encode a value graph of String / Integer / Long / Boolean / null / List / Map. */
    public static byte[] encode(Object value) {
        CanonicalCbor w = new CanonicalCbor();
        w.write(value);
        return w.out.toByteArray();
    }

    private void write(Object value) {
        if (value == null) {
            out.write(0xF6); // null
        } else if (value instanceof String s) {
            byte[] utf8 = s.getBytes(StandardCharsets.UTF_8);
            head(3, utf8.length);
            out.writeBytes(utf8);
        } else if (value instanceof byte[] b) {
            head(2, b.length);
            out.writeBytes(b);
        } else if (value instanceof Boolean b) {
            out.write(b ? 0xF5 : 0xF4);
        } else if (value instanceof Integer || value instanceof Long) {
            long n = ((Number) value).longValue();
            if (n < 0) {
                head(1, -1 - n);
            } else {
                head(0, n);
            }
        } else if (value instanceof List<?> list) {
            head(4, list.size());
            for (Object item : list) {
                write(item);
            }
        } else if (value instanceof Map<?, ?> map) {
            writeMap(map);
        } else {
            throw new IllegalArgumentException(
                    "No canonical CBOR encoding defined for " + value.getClass().getName());
        }
    }

    /**
     * Write a map with CTAP2 key ordering.
     *
     * <p>Sorting happens here rather than being the caller's job, so a map built in any order still
     * encodes identically. Getting this wrong is silent: the bytes stay valid CBOR and only the
     * signature disagrees.
     */
    private void writeMap(Map<?, ?> map) {
        List<Map.Entry<String, Object>> entries = new ArrayList<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            if (!(e.getKey() instanceof String key)) {
                throw new IllegalArgumentException("Canonical CBOR map keys must be strings");
            }
            entries.add(Map.entry(key, wrapNull(e.getValue())));
        }
        entries.sort(Comparator
                .comparingInt((Map.Entry<String, Object> e) -> e.getKey().getBytes(StandardCharsets.UTF_8).length)
                .thenComparing(e -> e.getKey(), CanonicalCbor::compareBytewise));

        head(5, entries.size());
        for (Map.Entry<String, Object> e : entries) {
            write(e.getKey());
            write(unwrapNull(e.getValue()));
        }
    }

    /** Map.entry rejects nulls, so absent values are carried through a sentinel. */
    private static final Object NULL = new Object();

    private static Object wrapNull(Object v) {
        return v == null ? NULL : v;
    }

    private static Object unwrapNull(Object v) {
        return v == NULL ? null : v;
    }

    /** Unsigned byte comparison; Java's String.compareTo is UTF-16 code-unit order, not this. */
    static int compareBytewise(String a, String b) {
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < Math.min(x.length, y.length); i++) {
            int c = Integer.compare(x[i] & 0xFF, y[i] & 0xFF);
            if (c != 0) return c;
        }
        return Integer.compare(x.length, y.length);
    }

    /** Major type plus argument, in the shortest form that fits. */
    private void head(int majorType, long argument) {
        int mt = majorType << 5;
        if (argument < 24) {
            out.write(mt | (int) argument);
        } else if (argument <= 0xFF) {
            out.write(mt | 24);
            out.write((int) argument);
        } else if (argument <= 0xFFFF) {
            out.write(mt | 25);
            out.write((int) (argument >> 8));
            out.write((int) (argument & 0xFF));
        } else if (argument <= 0xFFFFFFFFL) {
            out.write(mt | 26);
            for (int shift = 24; shift >= 0; shift -= 8) {
                out.write((int) ((argument >> shift) & 0xFF));
            }
        } else {
            out.write(mt | 27);
            for (int shift = 56; shift >= 0; shift -= 8) {
                out.write((int) ((argument >> shift) & 0xFF));
            }
        }
    }
}

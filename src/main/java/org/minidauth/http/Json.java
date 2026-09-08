package org.minidauth.http;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Json {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Json() {}

    public static ObjectMapper mapper() { return MAPPER; }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            byte[] raw = in.readAllBytes();
            if (raw.length == 0) return new LinkedHashMap<>();
            return MAPPER.readValue(raw, LinkedHashMap.class);
        } catch (com.fasterxml.jackson.core.JacksonException e) {
            throw new HttpError(400, "Malformed JSON body: " + e.getOriginalMessage());
        }
    }

    public static void send(HttpExchange ex, int status, Object body) throws IOException {
        byte[] out = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(body);
        ex.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, out.length);
        ex.getResponseBody().write(out);
        ex.close();
    }

    public static void sendError(HttpExchange ex, int status, String message) throws IOException {
        send(ex, status, Map.of("error", message, "status", status));
    }

    /**
     * Send a body exactly as given, with no JSON wrapping.
     *
     * <p>Needed for proxying: the enclave parses some responses itself and a wrapper object turns
     * a valid payload into an undefined field on the far side.
     */
    public static void sendRaw(HttpExchange ex, int status, String body, String contentType) throws IOException {
        byte[] out = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", contentType);
        ex.sendResponseHeaders(status, out.length);
        ex.getResponseBody().write(out);
        ex.close();
    }

    public static void sendNoContent(HttpExchange ex) throws IOException {
        ex.sendResponseHeaders(204, -1);
        ex.close();
    }

    public static String string(Map<String, Object> body, String key) {
        Object v = body.get(key);
        if (v == null) return null;
        String s = String.valueOf(v);
        return s.isBlank() ? null : s;
    }

    public static String requireString(Map<String, Object> body, String key) {
        String v = string(body, key);
        if (v == null) throw new HttpError(400, key + " is required");
        return v;
    }

    /** An error carrying the HTTP status to answer with. */
    public static final class HttpError extends RuntimeException {
        public final int status;

        public HttpError(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    public static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }
}

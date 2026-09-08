package org.minidauth.http;

import com.sun.net.httpserver.HttpExchange;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Path-template routing over the JDK HTTP server. */
public final class Router {

    private final List<Route> routes = new ArrayList<>();

    public interface Handler {
        void handle(HttpExchange ex, Map<String, String> pathParams) throws Exception;
    }

    public Router get(String pattern, Handler h) { return add("GET", pattern, h); }
    public Router post(String pattern, Handler h) { return add("POST", pattern, h); }
    public Router delete(String pattern, Handler h) { return add("DELETE", pattern, h); }

    private Router add(String method, String pattern, Handler h) {
        routes.add(new Route(method, split(pattern), h));
        return this;
    }

    /** @return the matched route, or null. Sets {@code out} to the extracted path params. */
    public Handler match(String method, String path, Map<String, String> out) {
        String[] parts = split(path);
        boolean pathMatchedSomeMethod = false;

        for (Route r : routes) {
            if (r.parts.length != parts.length) continue;
            Map<String, String> params = new LinkedHashMap<>();
            boolean ok = true;
            for (int i = 0; i < parts.length; i++) {
                String p = r.parts[i];
                if (p.startsWith("{") && p.endsWith("}")) {
                    params.put(p.substring(1, p.length() - 1),
                            URLDecoder.decode(parts[i], StandardCharsets.UTF_8));
                } else if (!p.equals(parts[i])) {
                    ok = false;
                    break;
                }
            }
            if (!ok) continue;
            pathMatchedSomeMethod = true;
            if (r.method.equals(method)) {
                out.putAll(params);
                return r.handler;
            }
        }
        if (pathMatchedSomeMethod) throw new Json.HttpError(405, "Method " + method + " not allowed on " + path);
        return null;
    }

    private static String[] split(String path) {
        String trimmed = path;
        int q = trimmed.indexOf('?');
        if (q >= 0) trimmed = trimmed.substring(0, q);
        while (trimmed.endsWith("/") && trimmed.length() > 1) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        if (trimmed.startsWith("/")) trimmed = trimmed.substring(1);
        if (trimmed.isEmpty()) return new String[0];
        return trimmed.split("/");
    }

    /** Parse a query string into a flat map, last value wins. */
    public static Map<String, String> query(HttpExchange ex) {
        Map<String, String> out = new LinkedHashMap<>();
        String raw = ex.getRequestURI().getRawQuery();
        if (raw == null || raw.isBlank()) return out;
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) {
                out.put(URLDecoder.decode(pair, StandardCharsets.UTF_8), "");
            } else {
                out.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        return out;
    }

    private record Route(String method, String[] parts, Handler handler) {}
}

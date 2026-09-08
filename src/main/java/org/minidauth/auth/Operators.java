package org.minidauth.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.minidauth.Log;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The operator roster, read from configuration at boot and never mutated at runtime.
 *
 * <p>This is deliberately <b>not</b> an identity store. There is no enrolment, no token issuance and
 * no API to change it, operators are declared by whoever deploys the service, the same way the ORK
 * URL is. Tokens are compared by digest so a token is never held in memory in the clear beyond the
 * request that presents it.
 */
public final class Operators {
    private static final Log log = Log.of(Operators.class);

    /** tokenDigest -> operator */
    private final Map<String, Operator> byTokenDigest = new LinkedHashMap<>();

    private Operators() {}

    /**
     * @param file  optional JSON array of {@code {name, token, roles[]}}; ignored when absent
     * @param adminToken optional single all-roles operator, for a one-operator deployment
     */
    public static Operators load(Path file, String adminToken, String adminName) {
        Operators operators = new Operators();

        if (adminToken != null && !adminToken.isBlank()) {
            operators.add(adminName, adminToken, EnumSet.allOf(Role.class));
        }

        if (file != null && Files.exists(file)) {
            for (Entry e : readFile(file)) {
                if (e.name == null || e.name.isBlank()) {
                    throw new IllegalStateException("Operator entry in " + file + " has no name");
                }
                if (e.token == null || e.token.isBlank()) {
                    throw new IllegalStateException("Operator '" + e.name + "' in " + file + " has no token");
                }
                Set<Role> roles = EnumSet.noneOf(Role.class);
                for (String r : e.roles) roles.add(Role.fromWire(r));
                if (roles.isEmpty()) {
                    throw new IllegalStateException("Operator '" + e.name + "' in " + file + " has no roles");
                }
                operators.add(e.name, e.token, roles);
            }
            log.info("Loaded operators from %s", file);
        }

        if (operators.byTokenDigest.isEmpty()) {
            log.warn("No operators configured. Set MC_ADMIN_TOKEN or provide an operators file, "
                    + "or nothing will be able to authenticate.");
        }
        return operators;
    }

    private void add(String name, String token, Set<Role> roles) {
        String digest = digest(token);
        Operator existing = byTokenDigest.get(digest);
        if (existing != null && !existing.name().equals(name)) {
            throw new IllegalStateException("Operators '" + existing.name() + "' and '" + name
                    + "' share a token; approvals could not be told apart");
        }
        if (byTokenDigest.values().stream().anyMatch(o -> o.name().equalsIgnoreCase(name))) {
            throw new IllegalStateException("Duplicate operator name '" + name + "'");
        }
        byTokenDigest.put(digest, new Operator(name, roles));
    }

    public Optional<Operator> authenticate(String token) {
        if (token == null || token.isBlank()) return Optional.empty();
        return Optional.ofNullable(byTokenDigest.get(digest(token)));
    }

    public List<Operator> all() {
        return new ArrayList<>(byTokenDigest.values());
    }

    /**
     * How many operators can approve. The quorum threshold is derived from this, so the roster the
     * deployment declares is what sets the bar.
     */
    public int approverCount() {
        return (int) byTokenDigest.values().stream().filter(o -> o.has(Role.APPROVER)).count();
    }

    private static List<Entry> readFile(Path file) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.readValue(Files.readString(file, StandardCharsets.UTF_8),
                    mapper.getTypeFactory().constructCollectionType(List.class, Entry.class));
        } catch (IOException e) {
            throw new IllegalStateException("Could not read the operators file at " + file, e);
        }
    }

    private static String digest(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return java.util.Base64.getEncoder()
                    .encodeToString(md.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class Entry {
        public String name;
        public String token;
        public List<String> roles = List.of();
    }
}

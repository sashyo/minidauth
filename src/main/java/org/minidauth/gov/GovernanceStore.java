package org.minidauth.gov;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** JSON-file persistence for contracts, deployed policies and change requests. */
public final class GovernanceStore {

    private final ObjectMapper mapper = new ObjectMapper();
    private final Path file;
    private State state;

    public GovernanceStore(Path file) {
        this.file = file;
        this.state = load();
    }

    private State load() {
        if (!Files.exists(file)) return new State();
        try {
            String json = Files.readString(file, StandardCharsets.UTF_8);
            if (json.isBlank()) return new State();
            return mapper.readValue(json, State.class);
        } catch (IOException e) {
            throw new IllegalStateException("Could not read governance store at " + file, e);
        }
    }

    public synchronized void persist() {
        try {
            Files.createDirectories(file.getParent());
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.writeString(tmp, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(state),
                    StandardCharsets.UTF_8);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new IllegalStateException("Could not persist governance store to " + file, e);
        }
    }

    // ------------------------------------------------------------- contracts

    public synchronized Optional<Contract> contract(String contractId) {
        return Optional.ofNullable(state.contracts.get(contractId));
    }

    public synchronized List<Contract> contracts() {
        return new ArrayList<>(state.contracts.values());
    }

    public synchronized void putContract(Contract c) {
        state.contracts.put(c.contractId, c);
    }

    public synchronized boolean deleteContract(String contractId) {
        return state.contracts.remove(contractId) != null;
    }

    // -------------------------------------------------------------- policies

    public synchronized Optional<DeployedPolicy> policy(String policyId) {
        return Optional.ofNullable(state.policies.get(policyId));
    }

    public synchronized List<DeployedPolicy> policies() {
        return new ArrayList<>(state.policies.values());
    }

    public synchronized void putPolicy(DeployedPolicy p) {
        state.policies.put(p.policyId, p);
    }

    public synchronized boolean deletePolicy(String policyId) {
        return state.policies.remove(policyId) != null;
    }

    // ---------------------------------------------------------------- grants

    /** The roles a Tide identity currently holds, or an empty record. */
    public synchronized RoleGrant grant(String vuid) {
        RoleGrant g = state.grants.get(vuid);
        return g != null ? g : new RoleGrant(vuid);
    }

    public synchronized List<RoleGrant> grants() {
        return new ArrayList<>(state.grants.values());
    }

    public synchronized void putGrant(RoleGrant grant) {
        if (grant.roles.isEmpty()) {
            // Keep no empty rows: "has no roles" and "has no record" are the same thing, and one
            // representation means the doken builder cannot disagree with the audit view.
            state.grants.remove(grant.vuid);
        } else {
            state.grants.put(grant.vuid, grant);
        }
    }

    // -------------------------------------------------------- change requests

    public synchronized Optional<ChangeRequest> changeRequest(String id) {
        return Optional.ofNullable(state.changeRequests.get(id));
    }

    public synchronized List<ChangeRequest> changeRequests(Status filter) {
        List<ChangeRequest> out = new ArrayList<>();
        for (ChangeRequest cr : state.changeRequests.values()) {
            if (filter == null || cr.status == filter) out.add(cr);
        }
        return out;
    }

    public synchronized void putChangeRequest(ChangeRequest cr) {
        state.changeRequests.put(cr.id, cr);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class State {
        public Map<String, Contract> contracts = new LinkedHashMap<>();
        public Map<String, DeployedPolicy> policies = new LinkedHashMap<>();
        public Map<String, ChangeRequest> changeRequests = new LinkedHashMap<>();
        public Map<String, RoleGrant> grants = new LinkedHashMap<>();
    }
}

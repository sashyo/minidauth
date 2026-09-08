package org.minidauth.gov;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A registered contract source.
 *
 * <p>{@code contractId} is SHA-512 of the exact source, UPPERCASE hex. The ORKs compare it as a
 * case-sensitive string, so any edit to the source, a comment included, produces a different
 * contract and invalidates every policy that referenced the old one.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class Contract {
    public String contractId;
    public String name;
    /** Wire value of {@code PolicySignRequest.ContractType}; only {@code forseti} exists today. */
    public String type = "forseti";
    public String source;
    public String registeredBy;
    public String registeredAt;
    /** The change request that authorised this registration. */
    public String changeRequestId;

    public Contract() {}
}

package org.minidauth.gov;

/** A governance rule refusal, carrying the HTTP status the IGA surface uses for it. */
public final class GovernanceException extends RuntimeException {
    public final int status;

    public GovernanceException(int status, String message) {
        super(message);
        this.status = status;
    }

    public static GovernanceException badRequest(String m) { return new GovernanceException(400, m); }
    public static GovernanceException forbidden(String m) { return new GovernanceException(403, m); }
    public static GovernanceException notFound(String m) { return new GovernanceException(404, m); }
    /** Not PENDING, already signed, or otherwise in the wrong state. */
    public static GovernanceException conflict(String m) { return new GovernanceException(409, m); }
    /** Under threshold. */
    public static GovernanceException preconditionFailed(String m) { return new GovernanceException(412, m); }
}

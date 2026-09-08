package org.minidauth.tide;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The ORK builds its own copy of the doken and signs that, returning only a signature. So these
 * tests are really one assertion repeated: the bytes this builder produces must be exactly the bytes
 * {@code Cryptide/Models/Doken.cs GetDataToSign()} produces. A single space or reordered field yields
 * a token that fails to verify, and the ORK reports it only as "Doken signature failed".
 */
class DokenBuilderTest {

    private static String decodeSegment( String jws, int index ) {
        return new String( Base64.getUrlDecoder().decode( jws.split( "\\." )[ index ] ),
                StandardCharsets.UTF_8 );
    }

    private DokenBuilder full() {
        return new DokenBuilder()
                .sessionKey( "SESSIONKEY" )
                .userKey( "USERKEY" )
                .vuid( "VUID" )
                .homeOrk( "http://localhost:1001" )
                .issuedAt( 1788880000L )
                .expiresAt( 1788888888L )
                .audience( "vvk-id" )
                .sessionId( "sess-1" )
                .realmRoles( List.of( "tide-vault-reader" ) );
    }

    @Test
    void theHeaderIsExactlyWhatTheOrkWrites() {
        assertEquals( "{\"alg\":\"EdDSA\",\"typ\":\"doken\"}", decodeSegment( full().dataToSign(), 0 ) );
    }

    @Test
    void thePayloadMatchesTheOrkFieldOrderAndSpacing() {
        assertEquals(
                "{\"t.ssk\":\"SESSIONKEY\","
                        + "\"tideuserkey\":\"USERKEY\","
                        + "\"vuid\":\"VUID\","
                        + "\"t.uho\":\"http://localhost:1001\","
                        + "\"exp\":1788888888,"
                        + "\"aud\":\"vvk-id\","
                        + "\"realm_access\":{\"roles\":[\"tide-vault-reader\"]},"
                        + "\"resource_access\":{}}",
                decodeSegment( full().dataToSign(), 1 ) );
    }

    /**
     * The bug the C# source documents: the signer omitted an absent access claim while the
     * delivered token carried {@code {}}, so the signatures could never agree.
     */
    @Test
    void theAccessClaimsAreAlwaysEmittedEvenWhenEmpty() {
        String payload = decodeSegment(
                new DokenBuilder().userKey( "U" ).vuid( "V" ).expiresAt( 1 ).audience( "A" ).dataToSign(), 1 );
        assertTrue( payload.contains( "\"realm_access\":{}" ), payload );
        assertTrue( payload.contains( "\"resource_access\":{}" ), payload );
        assertTrue( payload.endsWith( ",\"resource_access\":{}}" ), "resource_access must come last" );
    }

    /** These two are omitted entirely when absent, rather than emitted as null. */
    @Test
    void theOptionalClaimsAreOmittedNotNulled() {
        String payload = decodeSegment(
                new DokenBuilder().userKey( "U" ).vuid( "V" ).expiresAt( 1 ).audience( "A" ).dataToSign(), 1 );
        assertFalse( payload.contains( "t.ssk" ) );
        assertFalse( payload.contains( "t.uho" ) );
        assertFalse( payload.contains( "null" ) );
        assertTrue( payload.startsWith( "{\"tideuserkey\":" ) );
    }

    @Test
    void expiryIsANumberNotAString() {
        assertTrue( decodeSegment( full().dataToSign(), 1 ).contains( "\"exp\":1788888888," ) );
    }

    @Test
    void emptyRolesRenderAsTheEmptyObjectNotAnEmptyArray() {
        assertEquals( "{}", DokenBuilder.rolesJson( Set.of() ) );
        assertEquals( "{}", DokenBuilder.rolesJson( null ) );
        assertEquals( "{\"roles\":[\"a\"]}", DokenBuilder.rolesJson( List.of( "a" ) ) );
        assertEquals( "{\"roles\":[\"a\",\"b\"]}", DokenBuilder.rolesJson( List.of( "a", "b" ) ) );
    }

    /**
     * The ORK reads realm_access off the access token with {@code GetRawText()} and signs that
     * text, so the access token and the local copy must carry the identical rendering.
     */
    @Test
    void theAccessTokenCarriesTheSameAccessClaimsAsTheSignedCopy() {
        DokenBuilder b = full();
        String accessPayload = decodeSegment( b.accessTokenJws(), 1 );
        String signedPayload = decodeSegment( b.dataToSign(), 1 );

        String roles = "\"realm_access\":{\"roles\":[\"tide-vault-reader\"]}";
        assertTrue( accessPayload.contains( roles ), accessPayload );
        assertTrue( signedPayload.contains( roles ), signedPayload );
    }

    /**
     * On the access surface {@code realm_access} is mapper-derived, so an empty one asserted with
     * no role mapper attested behind it is an unbacked claim and the engine refuses the request.
     * Omitting it is safe precisely because the ORK's own copy defaults an absent access claim to
     * {@code {}}, which is what the signed bytes carry unconditionally.
     */
    @Test
    void emptyAccessClaimsAreOmittedFromTheAccessTokenButStillSigned() {
        DokenBuilder b = new DokenBuilder().userKey( "U" ).vuid( "V" ).expiresAt( 1 ).audience( "A" );
        String accessPayload = decodeSegment( b.accessTokenJws(), 1 );
        assertFalse( accessPayload.contains( "realm_access" ), accessPayload );
        assertFalse( accessPayload.contains( "resource_access" ), accessPayload );
        assertTrue( decodeSegment( b.dataToSign(), 1 ).endsWith(
                "\"realm_access\":{},\"resource_access\":{}}" ) );
    }

    /** A granted role has to reach the access token, or the ORK's copy defaults it away. */
    @Test
    void grantedRolesDoReachTheAccessToken() {
        assertTrue( decodeSegment( full().accessTokenJws(), 1 )
                .contains( "\"realm_access\":{\"roles\":[\"tide-vault-reader\"]}" ) );
    }

    /**
     * The ORK refuses the sign request with "iat missing from token" without this, and it belongs
     * only on the access token, the doken's own signed payload has no iat.
     */
    @Test
    void theAccessTokenCarriesIatButTheSignedDokenDoesNot() {
        assertTrue( decodeSegment( full().accessTokenJws(), 1 ).contains( "\"iat\":1788880000," ) );
        assertFalse( decodeSegment( full().dataToSign(), 1 ).contains( "iat" ) );
    }

    /**
     * The ORK matches {@code sid} against the blind-signed auth request before signing, so it has
     * to reach the access token, but the doken's own signed payload has no sid at all, and adding
     * one would make the two copies disagree.
     */
    @Test
    void theAccessTokenCarriesTheSessionIdButTheSignedDokenDoesNot() {
        assertTrue( decodeSegment( full().accessTokenJws(), 1 ).contains( "\"sid\":\"sess-1\"" ) );
        assertFalse( decodeSegment( full().dataToSign(), 1 ).contains( "sid" ) );
    }

    /** The ORK's ToParseableJws appends the signature segment itself, so two segments is correct. */
    @Test
    void theAccessTokenHasTwoSegments() {
        assertEquals( 2, full().accessTokenJws().split( "\\." ).length );
        assertFalse( full().accessTokenJws().endsWith( "." ) );
    }

    /** The access token must not carry t.ssk, the ORK takes the session key from the auth data. */
    @Test
    void theAccessTokenDoesNotCarryTheSessionKey() {
        assertFalse( decodeSegment( full().accessTokenJws(), 1 ).contains( "t.ssk" ) );
    }

    @Test
    void theFinishedTokenIsThreeSegmentsOverTheSignedBytes() {
        DokenBuilder b = full();
        String token = b.build( "abc+def/ghi==" );
        assertEquals( 3, token.split( "\\." ).length );
        assertTrue( token.startsWith( b.dataToSign() + "." ),
                "the signature must be appended to the exact signed bytes" );
    }

    /** The cohort returns standard base64; a JWT segment needs base64url with no padding. */
    @Test
    void theSignatureIsConvertedToBase64Url() {
        assertEquals( "abc-def_ghi", DokenBuilder.toBase64Url( "abc+def/ghi==" ) );
        assertEquals( "plain", DokenBuilder.toBase64Url( "plain" ) );
    }

    @Test
    void aTokenCannotBeAssembledWithoutASignature() {
        assertThrows( IllegalArgumentException.class, () -> full().build( null ) );
        assertThrows( IllegalArgumentException.class, () -> full().build( "  " ) );
    }

    /**
     * End to end: sign the builder's own bytes with a stand-in VVK and confirm {@link Doken}
     * verifies the assembled token and reads the identity back out.
     */
    @Test
    void anAssembledTokenVerifiesAndCarriesItsIdentity() throws Exception {
        var kp = java.security.KeyPairGenerator.getInstance( "Ed25519" ).generateKeyPair();

        DokenBuilder b = full();
        var signer = java.security.Signature.getInstance( "Ed25519" );
        signer.initSign( kp.getPrivate() );
        signer.update( b.dataToSign().getBytes( StandardCharsets.UTF_8 ) );
        String signature = Base64.getEncoder().encodeToString( signer.sign() );

        String token = b.build( signature );
        Doken parsed = Doken.verify( token, DokenTestKeys.encodePoint( kp.getPublic() ) );

        assertEquals( "VUID", parsed.vuid );
        assertEquals( "vvk-id", parsed.audience );
        assertEquals( 1788888888L, parsed.expiresAt );
        assertEquals( "tide-vault-reader",
                parsed.payload.get( "realm_access" ).get( "roles" ).get( 0 ).asText(),
                "the granted role must survive into the verified token" );
    }
}

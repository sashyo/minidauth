package org.minidauth.tide;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.EdECPublicKey;
import java.util.HexFormat;

/**
 * Test-only stand-in for the cohort's VVK.
 *
 * <p>{@link #encodePoint} is the inverse of {@code Doken.publicKeyFromHex}: 32-byte little-endian y
 * with the x-coordinate's sign in the top bit. Keeping the two in one place means a change to the
 * wire encoding breaks the round-trip tests rather than silently passing on both sides.
 */
public final class DokenTestKeys {

    private DokenTestKeys() {}

    static KeyPair generate() throws Exception {
        return KeyPairGenerator.getInstance( "Ed25519" ).generateKeyPair();
    }

    /** Encode an Ed25519 public key the way a gVVK/authorizer pack carries it: 32 bytes, hex. */
    public static String encodePoint( PublicKey key ) {
        EdECPublicKey ed = (EdECPublicKey) key;
        BigInteger y = ed.getPoint().getY();
        byte[] be = y.toByteArray();
        byte[] le = new byte[ 32 ];
        int copy = Math.min( be.length, 32 );
        for ( int i = 0; i < copy; i++ ) {
            le[ i ] = be[ be.length - 1 - i ];
        }
        if ( ed.getPoint().isXOdd() ) {
            le[ 31 ] |= (byte) 0x80;
        }
        return HexFormat.of().formatHex( le );
    }
}

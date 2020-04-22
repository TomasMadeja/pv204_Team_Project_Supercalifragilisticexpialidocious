/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.muni.fi.pv204.host;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;
/**
 * Primitives needed for a J-PAKE exchange.
 * Based on J-PAKEUtil by bouncycastle and the EC J-PAKE demo by Hao Feng
 * @author minh
 */
public class Util 
{
    static final BigInteger ZERO = BigInteger.valueOf(0);
    static final BigInteger ONE = BigInteger.valueOf(1);
    
        /**
     * Return a value that can be used as x1 or x3 during round 1.
     * <p>
     * The returned value is a random value in the range <tt>[0, q-1]</tt>.
     */
    public static BigInteger generateX1(
        BigInteger q,
        SecureRandom random)
    {
        BigInteger min = ZERO;
        BigInteger max = q.subtract(ONE);
        return BigIntegers.createRandomInRange(min, max, random);
    }

    /**
     * Return a value that can be used as x2 or x4 during round 1.
     * <p>
     * The returned value is a random value in the range <tt>[1, q-1]</tt>.
     */
    public static BigInteger generateX2(
        BigInteger q,
        SecureRandom random)
    {
        BigInteger min = ONE;
        BigInteger max = q.subtract(ONE);
        return BigIntegers.createRandomInRange(min, max, random);
    }
    
    /**
     * Converts the given password to a {@link BigInteger}
     * for use in arithmetic calculations.
     */
    public static BigInteger calculateS(char[] password)
    {
        return new BigInteger(Strings.toUTF8ByteArray(password));
    }
    
    /**
     * Calculate g^x mod p as done in round 1.
     * TODO make this EC
     */
    public static ECPoint calculateGx(
        ECPoint G,
        BigInteger x)
    {
        return G.multiply(x);
    }
    
    /**
     * Calculate ga as done in round 2.
     * TODO make this EC
     */
    public static ECPoint calculateGA(
        ECPoint Gx1,
        ECPoint Gx3,
        ECPoint Gx4)
    {
        // ga = g^(x1+x3+x4) = g^x1 * g^x3 * g^x4 
        return Gx1.add(Gx3.add(Gx4));
    }
    
    /**
     * Calculate x2 * s as done in round 2.TODO make this EC
     * @param q
     * @param x2
     * @param s
     * @return
     */
    public static BigInteger calculateX2s(
        BigInteger q,
        BigInteger x2,
        BigInteger s)
    {
        return x2.multiply(s).mod(q);
    }
    
       /**
     * Calculate A as done in round 2.
     */
    public static ECPoint calculateA(
        BigInteger q,
        ECPoint GA,
        BigInteger x2s)
    {
        // A = ga^(x*s)
        return GA.multiply(x2s);
    }
    
    /**
     * Calculate a zero knowledge proof of x using Schnorr's signature.
     * The returned array has two elements {g^v, r = v-x*h} for x.
     */
    
    /*
    public static BigInteger[] calculateZeroKnowledgeProof(
        BigInteger p,
        BigInteger q,
        BigInteger g,
        BigInteger gx,
        BigInteger x,
        String participantId,
        Digest digest,
        SecureRandom random)
    {
        BigInteger[] zeroKnowledgeProof = new BigInteger[2];

        // Generate a random v, and compute g^v
        BigInteger vMin = ZERO;
        BigInteger vMax = q.subtract(ONE);
        BigInteger v = BigIntegers.createRandomInRange(vMin, vMax, random);

        BigInteger gv = g.modPow(v, p);
        BigInteger h = calculateHashForZeroKnowledgeProof(g, gv, gx, participantId, digest); // h

        zeroKnowledgeProof[0] = gv;
        zeroKnowledgeProof[1] = v.subtract(x.multiply(h)).mod(q); // r = v-x*h

        return zeroKnowledgeProof;
    }
    */
/*
    private static BigInteger calculateHashForZeroKnowledgeProof(
        BigInteger g,
        BigInteger gr,
        BigInteger gx,
        String participantId,
        Digest digest)
    {
        digest.reset();

        updateDigestIncludingSize(digest, g);

        updateDigestIncludingSize(digest, gr);

        updateDigestIncludingSize(digest, gx);

        updateDigestIncludingSize(digest, participantId);

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return new BigInteger(output);
    }
*/
    /**
     * Validates that g^x4 is not 1.
     *
     * @throws CryptoException if g^x4 is 1
     */
    public static void validateGx4(ECPoint Gx4)
        throws CryptoException
    {
        if (Gx4.isInfinity())
        {
            throw new CryptoException("g^x validation failed.  g^x should not be infinity.");
        }
    }

    /**
     * Validates that ga is not 1.
     * <p>
     * As described by Feng Hao...
     * <p>
     * <blockquote>
     * Alice could simply check ga != 1 to ensure it is a generator.
     * In fact, as we will explain in Section 3, (x1 + x3 + x4 ) is random over Zq even in the face of active attacks.
     * Hence, the probability for ga = 1 is extremely small - on the order of 2^160 for 160-bit q.
     * </blockquote>
     *
     * @throws CryptoException if ga is 1
     */
    public static void validateGa(ECPoint Ga)
        throws CryptoException
    {
        if (Ga.isInfinity())
        {
            throw new CryptoException("ga is equal to infinity.  It should not be.  The chances of this happening are on the order of 2^160 for a 160-bit q.  Try again.");
        }
    }



    public static BigInteger getSHA256(ECPoint generator, ECPoint V, ECPoint X, String userID) {

    	MessageDigest sha256 = null;

    	try {
    		sha256 = MessageDigest.getInstance("SHA-256");
    		
    		byte [] GBytes = generator.getEncoded(false);
    		byte [] VBytes = V.getEncoded(false);
    		byte [] XBytes = X.getEncoded(false);
    		byte [] userIDBytes = userID.getBytes();
    		
    		// It's good practice to prepend each item with a 4-byte length
    		sha256.update(ByteBuffer.allocate(4).putInt(GBytes.length).array());
    		sha256.update(GBytes);

    		sha256.update(ByteBuffer.allocate(4).putInt(VBytes.length).array());
    		sha256.update(VBytes);

    		sha256.update(ByteBuffer.allocate(4).putInt(XBytes.length).array());
    		sha256.update(XBytes);
    		
    		sha256.update(ByteBuffer.allocate(4).putInt(userIDBytes.length).array());
    		sha256.update(userIDBytes);    	
   		
    	} catch (Exception e) {
    		e.printStackTrace();
    	}

    	return new BigInteger(sha256.digest());
    }
    
    public static BigInteger getSHA256(BigInteger K) {

    	MessageDigest sha256 = null;

    	try {
    		sha256 = MessageDigest.getInstance("SHA-256");
    		sha256.update(K.toByteArray());
    	} catch (Exception e) {
    		e.printStackTrace();
    	}

    	return new BigInteger(1, sha256.digest()); // 1 for positive int
    }
    /**
     * Calculates the keying material, which can be done after round 2 has completed.
     * A session key must be derived from this key material using a secure key derivation function (KDF).
     * The KDF used to derive the key is handled externally (i.e. not by {@link JPAKEParticipant}).
     * <pre>
     * KeyingMaterial = (B/g^{x2*x4*s})^x2
     * </pre>
     */
    public static ECPoint calculateKeyingMaterial(
        ECPoint Gx4,
        BigInteger x2,
        BigInteger s,
        ECPoint B)
    {
        //return gx4.modPow(x2.multiply(s).negate().mod(q), p).multiply(B).modPow(x2, p);
        return (B.subtract(Gx4.multiply(x2).multiply(s))).multiply(x2);
    }

    /**
     * Validates that the given participant ids are not equal.
     * (For the J-PAKE exchange, each participant must use a unique id.)
     *
     * @throws CryptoException if the participantId strings are equal.
     */
    public static void validateParticipantIdsDiffer(String participantId1, String participantId2)
        throws CryptoException
    {
        if (participantId1.equals(participantId2))
        {
            throw new CryptoException(
                "Both participants are using the same participantId ("
                    + participantId1
                    + "). This is not allowed. "
                    + "Each participant must use a unique participantId.");
        }
    }

    /**
     * Validates that the given participant ids are equal.
     * This is used to ensure that the payloads received from
     * each round all come from the same participant.
     *
     * @throws CryptoException if the participantId strings are equal.
     */
    public static void validateParticipantIdsEqual(String expectedParticipantId, String actualParticipantId)
        throws CryptoException
    {
        if (!expectedParticipantId.equals(actualParticipantId))
        {
            throw new CryptoException(
                "Received payload from incorrect partner ("
                    + actualParticipantId
                    + "). Expected to receive payload from "
                    + expectedParticipantId
                    + ".");
        }
    }

    /**
     * Validates that the given object is not null.
     *
     *  @param object object in question
     * @param description name of the object (to be used in exception message)
     * @throws NullPointerException if the object is null.
     */
    public static void validateNotNull(Object object, String description)
    {
        if (object == null)
        {
            throw new NullPointerException(description + " must not be null");
        }
    }

    /**
     * Calculates the MacTag (to be used for key confirmation), as defined by
     * <a href="http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf">NIST SP 800-56A Revision 1</a>,
     * Section 8.2 Unilateral Key Confirmation for Key Agreement Schemes.
     * <pre>
     * MacTag = HMAC(MacKey, MacLen, MacData)
     *
     * MacKey = H(K || "JPAKE_KC")
     *
     * MacData = "KC_1_U" || participantId || partnerParticipantId || gx1 || gx2 || gx3 || gx4
     *
     * Note that both participants use "KC_1_U" because the sender of the round 3 message
     * is always the initiator for key confirmation.
     *
     * HMAC = {@link HMac} used with the given {@link Digest}
     * H = The given {@link Digest}
     * MacLen = length of MacTag
     * </pre>
     * 
     * TODO udelat pro EC
     */
    public static BigInteger calculateMacTag(
        String participantId,
        String partnerParticipantId,
        ECPoint Gx1,
        ECPoint Gx2,
        ECPoint Gx3,
        ECPoint Gx4,
        BigInteger keyingMaterial,
        Digest digest)
    {
        byte[] macKey = calculateMacKey(
            keyingMaterial,
            digest);

        HMac mac = new HMac(digest);
        byte[] macOutput = new byte[mac.getMacSize()];
        mac.init(new KeyParameter(macKey));

        /*
         * MacData = "KC_1_U" || participantId_Alice || participantId_Bob || gx1 || gx2 || gx3 || gx4.
         */
        updateMac(mac, "KC_1_U");
        updateMac(mac, participantId);
        updateMac(mac, partnerParticipantId);
//        updateMac(mac, gx1);
//        updateMac(mac, gx2);
//        updateMac(mac, gx3);
//        updateMac(mac, gx4);

        mac.doFinal(macOutput, 0);

        Arrays.fill(macKey, (byte)0);

        return new BigInteger(macOutput);

    }

    /**
     * Calculates the MacKey (i.e. the key to use when calculating the MagTag for key confirmation).
     * <pre>
     * MacKey = H(K || "JPAKE_KC")
     * </pre>
     * 
     * TODO udelat pro EC
     */
    private static byte[] calculateMacKey(BigInteger keyingMaterial, Digest digest)
    {
        digest.reset();

        updateDigest(digest, keyingMaterial);
        /*
         * This constant is used to ensure that the macKey is NOT the same as the derived key.
         */
        updateDigest(digest, "JPAKE_KC");

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return output;
    }

    /**
     * Validates the MacTag received from the partner participant.
     *
     * @param partnerMacTag the MacTag received from the partner.
     * @throws CryptoException if the participantId strings are equal
     * 
     * TODO udelat pro EC.
     */
    public static void validateMacTag(
        String participantId,
        String partnerParticipantId,
        BigInteger gx1,
        BigInteger gx2,
        BigInteger gx3,
        BigInteger gx4,
        BigInteger keyingMaterial,
        Digest digest,
        BigInteger partnerMacTag)
        throws CryptoException
    {
        /*
         * Calculate the expected MacTag using the parameters as the partner
         * would have used when the partner called calculateMacTag.
         * 
         * i.e. basically all the parameters are reversed.
         * participantId <-> partnerParticipantId
         *            x1 <-> x3
         *            x2 <-> x4
         */
//        BigInteger expectedMacTag = calculateMacTag(
//            partnerParticipantId,
//            participantId,
//            gx3,
//            gx4,
//            gx1,
//            gx2,
//            keyingMaterial,
//            digest);
//
//        if (!expectedMacTag.equals(partnerMacTag))
//        {
//            throw new CryptoException(
//                "Partner MacTag validation failed. "
//                    + "Therefore, the password, MAC, or digest algorithm of each participant does not match.");
//        }
    }

    private static void updateDigest(Digest digest, BigInteger bigInteger)
    {
        byte[] byteArray = BigIntegers.asUnsignedByteArray(bigInteger);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateDigestIncludingSize(Digest digest, BigInteger bigInteger)
    {
        byte[] byteArray = BigIntegers.asUnsignedByteArray(bigInteger);
        digest.update(intToByteArray(byteArray.length), 0, 4);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateDigest(Digest digest, String string)
    {
        byte[] byteArray = Strings.toUTF8ByteArray(string);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateDigestIncludingSize(Digest digest, String string)
    {
        byte[] byteArray = Strings.toUTF8ByteArray(string);
        digest.update(intToByteArray(byteArray.length), 0, 4);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateMac(Mac mac, BigInteger bigInteger)
    {
        byte[] byteArray = BigIntegers.asUnsignedByteArray(bigInteger);
        mac.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateMac(Mac mac, String string)
    {
        byte[] byteArray = Strings.toUTF8ByteArray(string);
        mac.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static byte[] intToByteArray(int value)
    {
        return new byte[]{
            (byte)(value >>> 24),
            (byte)(value >>> 16),
            (byte)(value >>> 8),
            (byte)value
        };
    }
    
        
    

}

    


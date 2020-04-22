/*  
 * @author: Feng Hao, haofeng66@gmail.com
 * 
 * This is a simple demo program written in Java, just to show how J-PAKE can be implemented using
 * the Elliptic Curve group setting (the same setting as that of ECDSA or ECDH). 
 * 
 * The implementation of J-PAKE in the DSA-like group setting has been included into Bouncycastle (v1.48 and above). 
 * Details can be found at:
 * http://www.bouncycastle.org/viewcvs/viewcvs.cgi/java/crypto/src/org/bouncycastle/crypto/examples/JPAKEExample.java?revision=1.1&view=markup
 * 
 * License of the code: none. The code is free to use and modify without any restrictions.
 *
 * Dependence: BouncyCastle library (https://www.bouncycastle.org/java.html) 
 *  
 * Publications:    
 *  - The initial workshop paper (SPW'08): http://grouper.ieee.org/groups/1363/Research/contributions/hao-ryan-2008.pdf
 *  - The extended journal version (Springer Transactions'10): http://eprint.iacr.org/2010/190.pdf
 * 
 * Acknowledgment: the author would like to thank Dylan Clarke for useful comments on the demo code. 
 * 
 * Date: 29 December 2013.
 *  
 */

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class EllipticCurveJPAKEDemo {

	/*
	 * See [1] for public domain parameters for NIST standard curves
	 * P-224, P-256, P-384, P-521. This demo code only uses P-256 as an example. One can also
	 * use other curves that are suitable for Elliptic Curve Cryptography (ECDSA/ECDH), e.g., Curve25519.
	 *  
	 * [1] D. Johnson, A. Menezes, S. Vanstone, "The Elliptic Curve Digital Signature Algorithm (ECDSA)",
	 *     International Journal of Information Security, 2001. Available at
	 *     http://cs.ucsb.edu/~koc/ccs130h/notes/ecdsa-cert.pdf 
	 *  
	 */
	
	private ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
	
	// Domain parameters 
	private ECCurve.Fp ecCurve = (ECCurve.Fp)ecSpec.getCurve();	
	private BigInteger a = ecCurve.getA().toBigInteger();
	private BigInteger b = ecCurve.getB().toBigInteger();
	private BigInteger q = ecCurve.getQ();
	private BigInteger coFactor = ecSpec.getH(); // Not using the symbol "h" here to avoid confusion as h will be used later in SchnorrZKP. 
	private BigInteger n = ecSpec.getN();
	private ECPoint G = ecSpec.getG();
	
	/* 
	 * Shared passwords for Alice and Bob 
	 * Try changing them to different values? 
	 */
	
	private String s1Str = "deadbeef";
	private String s2Str = "deadbeef";

	/* 
	 * UserIDs for Alice and Bob.
	 */
	
	private String AliceID = "Alice";
	private String BobID = "Bob";

    public static void main(String args[]) {

    	EllipticCurveJPAKEDemo test = new EllipticCurveJPAKEDemo();
    	test.run();
    }

    private void run () {
	
    	System.out.println("************ Public elliptic curve domain parameters ************\n");
    	System.out.println("Curve param a (" + a.bitLength() + " bits): "+ a.toString(16));
    	System.out.println("Curve param b (" + b.bitLength() + " bits): "+ b.toString(16));    	    	
    	System.out.println("Co-factor h (" + coFactor.bitLength() + " bits): " + coFactor.toString(16));
    	System.out.println("Base point G (" + G.getEncoded(false).length + " bytes): " + new BigInteger(G.getEncoded(false)).toString(16));
    	System.out.println("X coord of G (" + G.getXCoord().toBigInteger().bitLength() + " bits): " + G.getXCoord().toBigInteger().toString(16));
    	System.out.println("y coord of G (" + G.getYCoord().toBigInteger().bitLength() + " bits): " + G.getYCoord().toBigInteger().toString(16));
    	System.out.println("Order of the base point n (" + n.bitLength() + " bits): "+ n.toString(16));
    	System.out.println("Prime field q (" + q.bitLength() + " bits): "+ q.toString(16));
    	
    	System.out.println("");
    	
    	System.out.println("(Secret passwords used by Alice and Bob: "+
    			"\""+s1Str+"\" and \""+s2Str+"\")\n");
    	
    	BigInteger s1 = new BigInteger(s1Str.getBytes());
    	BigInteger s2 = new BigInteger(s2Str.getBytes());

    	/* Step 1:  
    	 * 
    	 * Alice chooses x1 randomly from [1, n-1], x2 from [1, n-1]
    	 * Similarly, Bob chooses x3 randomly from [1, n-1] and x4 from [1, n-1]
    	 * 
    	 * Alice -> Bob: G*x1, G*x2 and ZKP{x1}, ZKP{X2}
    	 * Bob -> Alice: G*x3, G*x4 and ZKP{x3}, ZKP{X4}   
    	 * 
    	 * Note: in the DSA setting, x1, x3 are chosen from [0, q-1] and x2, x4 from [1, q-1]
    	 * However, in the ECDSA setting, the zero element is naturally excluded.
    	 */
    	    	
    	BigInteger x1 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
    	BigInteger x2 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
    	BigInteger x3 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
    	BigInteger x4 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
    	
    	ECPoint X1 = G.multiply(x1);
    	SchnorrZKP zkpX1 = new SchnorrZKP();
    	zkpX1.generateZKP(G, n, x1, X1, AliceID);
    	
    	ECPoint X2 = G.multiply(x2);
    	SchnorrZKP zkpX2 = new SchnorrZKP();
    	zkpX2.generateZKP(G, n, x2, X2, AliceID);
    	
    	ECPoint X3 = G.multiply(x3);
    	SchnorrZKP zkpX3 = new SchnorrZKP();
    	zkpX3.generateZKP(G, n, x3, X3, BobID);
    	
    	ECPoint X4 = G.multiply(x4);
    	SchnorrZKP zkpX4 = new SchnorrZKP();
    	zkpX4.generateZKP(G, n, x4, X4, BobID);
    	
    	System.out.println("************Step 1**************\n");
    	System.out.println("Alice sends to Bob: ");
    	System.out.println("G*x1="+new BigInteger(X1.getEncoded(false)).toString(16));
    	System.out.println("G*x2="+new BigInteger(X2.getEncoded(false)).toString(16));
    	System.out.println("KP{x1}: {V="+new BigInteger(zkpX1.getV().getEncoded(false)).toString(16)+"; r="+zkpX1.getr().toString(16)+"}");
    	System.out.println("KP{x2}: {V="+new BigInteger(zkpX2.getV().getEncoded(false)).toString(16)+"; r="+zkpX2.getr().toString(16)+"}");
    	System.out.println("");

    	System.out.println("Bob sends to Alice: ");
    	System.out.println("G*x3="+new BigInteger(X3.getEncoded(false)).toString(16));
    	System.out.println("G*x4="+new BigInteger(X4.getEncoded(false)).toString(16));
    	System.out.println("KP{x3}: {V="+new BigInteger(zkpX3.getV().getEncoded(false)).toString(16)+"; r="+zkpX3.getr().toString(16)+"}");
    	System.out.println("KP{x4}: {V="+new BigInteger(zkpX4.getV().getEncoded(false)).toString(16)+"; r="+zkpX4.getr().toString(16)+"}");
    	System.out.println("");
    	
    	/*
    	 * Alice checks 1) BobID is a valid identity (omitted in this demo code) and 2) is different from her own
    	 */
    	if (AliceID.equals(BobID)) {
    		System.out.println("ERROR: AliceID and BobID must be different.");
    		System.exit(0);
    	}
    	    	
    	/* 
    	 * Alice verifies Bob's ZKPs.
    	 * 
    	 * Note: in the DSA setting, Alice needs to check g^{x4} != 1 (i.e., not an identity element). 
    	 * In the ECDSA setting, checking the infinity point (i.e., identity element) has been covered in the public key validation step, 
    	 * as part the Schnorr ZKP verification routine.
    	 */
    	
    	if (verifyZKP(G, X3, zkpX3.getV(), zkpX3.getr(), BobID) && verifyZKP(G, X4, zkpX4.getV(), zkpX4.getr(), BobID)) {
    		System.out.println("Alice checks KP{x3}: OK");
    		System.out.println("Alice checks KP{x4}: OK");
    		System.out.println("");
    	}else {
    		System.out.println("ERROR: invalid KP{x3, x4}.");
    		System.exit(0);
    	}
		
    	/*
    	 * Symmetrically, Bob checks Alice's UserID and her KPs on {x1} and {x2}
    	 */
    	
    	if (BobID.equals(AliceID)) {
    		System.out.println("ERROR: AliceID and BobID must be different.");
    		System.exit(0);
    	}
    	    	
    	if (verifyZKP(G, X1, zkpX1.getV(), zkpX1.getr(), AliceID) && verifyZKP(G, X2, zkpX2.getV(), zkpX2.getr(), AliceID)) {
    		System.out.println("Bob checks KP{x1}: OK");
    		System.out.println("Bob checks KP{x2}: OK");
    		System.out.println("");
    	}else {
    		System.out.println("ERROR: invalid KP{x1, x2}.");
    		System.exit(0);
    	}
    	
    	/*
    	 * Step 2:
    	 * 
    	 * Alice -> Bob: A and KP{x2s}
    	 * Bob -> Alice: B and KP{x4s}
    	 */

    	ECPoint GA = X1.add(X3).add(X4); 
    	ECPoint A = GA.multiply(x2.multiply(s1).mod(n));
				
    	SchnorrZKP zkpX2s = new SchnorrZKP();
    	zkpX2s.generateZKP(GA, n, x2.multiply(s1).mod(n), A, AliceID);
		
    	ECPoint GB = X1.add(X2).add(X3); 
    	ECPoint B = GB.multiply(x4.multiply(s2).mod(n));
				
    	SchnorrZKP zkpX4s = new SchnorrZKP();
    	zkpX4s.generateZKP(GB, n, x4.multiply(s2).mod(n), B, BobID);
    	
    	System.out.println("************Step 2**************\n");
    	System.out.println("Alice sends to Bob:");
    	System.out.println("A="+new BigInteger(A.getEncoded(false)).toString(16));
    	System.out.println("KP{x2*s}: {V="+new BigInteger(zkpX2s.getV().getEncoded(false)).toString(16)+", r="+zkpX2s.getr().toString(16)+"}");
    	System.out.println("");

    	System.out.println("Bob sends to Alice:");
    	System.out.println("B="+new BigInteger(B.getEncoded(false)).toString(16));
    	System.out.println("KP{x4*s}: {V="+new BigInteger(zkpX4s.getV().getEncoded(false)).toString(16)+", r="+zkpX4s.getr().toString(16)+"}");
    	System.out.println("");		
    	
    	/* Alice verifies Bob's ZKP */
    	if (verifyZKP(GB, B, zkpX4s.getV(), zkpX4s.getr(), BobID)) {
    		System.out.println("Alice checks KP{x4*s}: OK");
    	} else {
    		System.out.println("ERROR: invalid KP{x4*s}.");
    		System.exit(0);
    	}
    	
    	/*
    	 * Symmetrically, Bob checks Alice's KP on {x1*s}
    	 */
    	if (verifyZKP(GA, A, zkpX2s.getV(), zkpX2s.getr(), AliceID)) {
    		System.out.println("Bob checks KP{x2*s}: OK");
    		System.out.println("");
    	}else {
    		System.out.println("ERROR: invalid KP{x2*s}.");
    		System.exit(0);
    	}
    	
    	/* After step 2, compute the common key based on hashing the x coordinate of the derived EC point */    	
    	BigInteger Ka = getSHA256( B.subtract(X4.multiply(x2.multiply(s1).mod(n))).multiply(x2).getXCoord().toBigInteger());
    	BigInteger Kb = getSHA256( A.subtract(X2.multiply(x4.multiply(s2).mod(n))).multiply(x4).getXCoord().toBigInteger());
		
    	System.out.println("************After step 2**************\n");
    	System.out.println("Alice computes a session key \t K="+Ka.toString(16));
    	System.out.println("Bob computes a session key \t K="+Kb.toString(16));
    	    	
    	/* 
    	 * It is recommended that both parties perform an explicit key confirmation
    	 * before using the session key. This provides explicit assurance that the 
    	 * two parties have actually obtained the same session key. The key confirmation
    	 * method is the same regardless of the group setting (DSA or ECDSA). See the 
    	 * existing J-PAKE key confirmation implementation in Bouncycastle for details. 
    	 * 
    	 * http://www.bouncycastle.org/viewcvs/viewcvs.cgi/java/crypto/src/org/bouncycastle/crypto/agreement/jpake/JPAKEUtil.java?revision=1.3&view=markup
    	 */
    }

    public boolean verifyZKP(ECPoint generator, ECPoint X, ECPoint V, BigInteger r, String userID) {
    	
    	/* ZKP: {V=G*v, r} */    	    	
    	BigInteger h = getSHA256(generator, V, X, userID);
    	
    	// Public key validation based on p. 25
    	// http://cs.ucsb.edu/~koc/ccs130h/notes/ecdsa-cert.pdf
    	
    	// 1. X != infinity
    	if (X.isInfinity()){
    		return false;
    	}
    	
    	// 2. Check x and y coordinates are in Fq, i.e., x, y in [0, q-1]
    	if (X.getXCoord().toBigInteger().compareTo(BigInteger.ZERO) == -1 ||
    			X.getXCoord().toBigInteger().compareTo(q.subtract(BigInteger.ONE)) == 1 ||
    			X.getYCoord().toBigInteger().compareTo(BigInteger.ZERO) == -1 ||
    			X.getYCoord().toBigInteger().compareTo(q.subtract(BigInteger.ONE)) == 1) {
    		return false;
    	}
    				
    	// 3. Check X lies on the curve
    	try {
    		ecCurve.decodePoint(X.getEncoded(false));
    	}
    	catch(Exception e){
    		e.printStackTrace();
    		return false;
    	}
    	
    	// 4. Check that nX = infinity.
    	// It is equivalent - but more more efficient - to check the coFactor*X is not infinity
    	if (X.multiply(coFactor).isInfinity()) { 
    		return false;
    	}
    	
    	// Now check if V = G*r + X*h. 
    	// Given that {G, X} are valid points on curve, the equality implies that V is also a point on curve.
    	if (V.equals(generator.multiply(r).add(X.multiply(h.mod(n))))) {
    		return true;
    	}
    	else {
    		return false;
    	}
    }

    public BigInteger getSHA256(ECPoint generator, ECPoint V, ECPoint X, String userID) {

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

    public BigInteger getSHA256(BigInteger K) {

    	MessageDigest sha256 = null;

    	try {
    		sha256 = MessageDigest.getInstance("SHA-256");
    		sha256.update(K.toByteArray());
    	} catch (Exception e) {
    		e.printStackTrace();
    	}

    	return new BigInteger(1, sha256.digest()); // 1 for positive int
    }
    
    private class SchnorrZKP {
    	
    	private ECPoint V = null;
    	private BigInteger r = null;
    			
    	private SchnorrZKP () {
    		// constructor
    	}
    	
    	private void generateZKP (ECPoint generator, BigInteger n, BigInteger x, ECPoint X, String userID) {

        	/* Generate a random v from [1, n-1], and compute V = G*v */
        	BigInteger v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
        			n.subtract(BigInteger.ONE), new SecureRandom());
        	V = generator.multiply(v);
        	
        	BigInteger h = getSHA256(generator, V, X, userID); // h

        	r = v.subtract(x.multiply(h)).mod(n); // r = v-x*h mod n   	
        }
    	
    	private ECPoint getV() {
    		return V;
    	}
    	
    	private BigInteger getr() {
    		return r;
    	}
    	
    }
}

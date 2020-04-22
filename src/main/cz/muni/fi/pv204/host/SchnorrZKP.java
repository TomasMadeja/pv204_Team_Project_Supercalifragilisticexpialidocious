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
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;

//import cz.muni.fi.pv204.host.Util;

/**
 *
 * @author minh
 */
public class SchnorrZKP {
    	
    	private ECPoint V = null;
    	private BigInteger r = null;
    			
    	public SchnorrZKP () {
    		// constructor
    	}

		public SchnorrZKP (ECPoint V, BigInteger r) {
			this.V = V;
			this.r = r;
		}
    	
    	public void generateZKP (ECPoint generator, BigInteger n, BigInteger x, ECPoint X, String userID) {

        	/* Generate a random v from [1, n-1], and compute V = G*v */
        	BigInteger v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
        			n.subtract(BigInteger.ONE), new SecureRandom());
        	V = generator.multiply(v);
        	
        	BigInteger h = Util.getSHA256(generator, V, X, userID); // h

        	r = v.subtract(x.multiply(h)).mod(n); // r = v-x*h mod n   	
        }
    	
    	public ECPoint getV() {
    		return V;
    	}
    	
    	public BigInteger getr() {
    		return r;
    	}
       
            /**
     * Validates the zero knowledge proof 
     *
     * @throws CryptoException if the zero knowledge proof is not correct
     */
    //public boolean verifyZKP(ECParameterSpec ecSpec, ECPoint generator, ECPoint X, ECPoint V, BigInteger r, BigInteger q, String userID) {
    public boolean verifyZKP(ECParameterSpec ecSpec, ECPoint generator, ECPoint X, BigInteger q, String userID) {	
    	/* ZKP: {V=G*v, r} */    	    	
    	BigInteger h = Util.getSHA256(generator, V, X, userID);
        ECCurve.Fp ecCurve = (ECCurve.Fp)ecSpec.getCurve();
    	BigInteger coFactor = ecSpec.getH();
        BigInteger n = ecSpec.getN();
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
        
    	
    }


package cz.muni.fi.pv204.javacard.jpake;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import javacard.security.MessageDigest;


public class JPakeECParam {


    public ECPoint addPoints(ECPoint a, ECPoint b)
    {
        X9ECParameters curve = ECNamedCurveTable.getByName("P-256");
        ECDomainParameters ecparams = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH(), curve.getSeed());
        ECPoint result;
        result= a.add(b);
        return result;
    }
    public ECPoint mulPoints(ECPoint a, BigInteger scalar)
    {
        X9ECParameters curve = ECNamedCurveTable.getByName("P-256");
        ECDomainParameters ecparams = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH(), curve.getSeed());
        ECPoint result;
        result= a.multiply(scalar);
        return result;
    }

    public ECPoint getGenCard(ECPoint P1, ECPoint P2, ECPoint P3, BigInteger x2S)
    {
//Alice -> Bob: A = (G1 + G3 + G4) x [x2*s] and a ZKP for x2*s

        ECPoint temp,temp2;
        ECPoint result;
        temp= addPoints(P1,P2);
        temp2 = addPoints(temp,P3);
        result = mulPoints(temp2,x2S);
        return result;
    }
    public ECPoint getSharedKey(ECPoint host, ECPoint P4, BigInteger x2S, BigInteger x2 )
    {
//Alice computes Ka = (B - (G4 x [x2*s])) x [x2]

        ECPoint temp, temp1,result;
        temp = mulPoints(P4,x2S);
        temp.negate();
        temp1 = addPoints(host,temp);
        result= mulPoints(temp1,x2);
        return result;

    }

public BigInteger byteArrayToBigint(byte[] input)
{
        BigInteger result = new BigInteger(input);
        return result;
}

public static ECPoint byteArrayToECPoint(byte[] input)
{
    X9ECParameters curve = ECNamedCurveTable.getByName("P-256");
    ECDomainParameters ecparams = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH(), curve.getSeed());

    ECPoint result = (ecparams.getCurve().decodePoint(input));
    return result;
}

public static BigInteger getSHA256(ECPoint generator, ECPoint V, ECPoint X, String userID) {

    	MessageDigest sha256 = null;
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256,false);
    		
    		byte [] GBytes = generator.getEncoded(false);
    		byte [] VBytes = V.getEncoded(false);
    		byte [] XBytes = X.getEncoded(false);
    		byte [] userIDBytes = userID.getBytes();
                byte [] result = new byte[sha256.getLength()];
    	try {
    		
    		// It's good practice to prepend each item with a 4-byte length
    		sha256.update(ByteBuffer.allocate(4).putInt(GBytes.length).array(), (short) 0 , (short)4);
    		sha256.update(GBytes, (short) 0 , (short) GBytes.length);

    		sha256.update(ByteBuffer.allocate(4).putInt(VBytes.length).array(), (short) 0,  (short)4);
    		sha256.update(VBytes, (short) 0, (short) VBytes.length);

    		sha256.update(ByteBuffer.allocate(4).putInt(XBytes.length).array(), (short) 0, (short) 4 );
    		sha256.update(XBytes, (short) 0, (short) XBytes.length);
    		
    		sha256.update(ByteBuffer.allocate(4).putInt(userIDBytes.length).array(), (short) 0, (short) 4);
    		sha256.doFinal(userIDBytes, (short) 0, (short) userIDBytes.length, result, (short) 0);    	
   		
    	} catch (Exception e) {
    		e.printStackTrace();
    	}

    	return new BigInteger(result);
    }





}

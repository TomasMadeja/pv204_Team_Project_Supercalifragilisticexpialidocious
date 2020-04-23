package cz.muni.fi.pv204.javacard.jpake;

import cz.muni.fi.pv204.host.cardTools.Util;
import javacard.security.MessageDigest;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;


public class JPakeECParam {

    public final ECParameterSpec ecSpec;
    public final SecP256R1Curve curve;
    private MessageDigest sha;

    public JPakeECParam() {
        this.ecSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("P-256");
        this.curve = (SecP256R1Curve) ecSpec.getCurve();
        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    }


//     group.generateZKPr(
//            G,
//            x1, Gx1,
//            zkpX1V, v,
//            this.participantID
//        );
    public BigInteger generateZKPr(
            ECPoint generator,
            BigInteger x, ECPoint X,
            ECPoint V, BigInteger v,
            byte[] userID
    ){
        BigInteger h = getSHA256(generator, V, X, userID);
        BigInteger r = v.subtract(x.multiply(h));
        return r;
    }

    public boolean verifyZKP(ECPoint generator, ECPoint X, ECPoint V, BigInteger r, byte[] userID) {
        /* ZKP: {V=G*v, r} */
        BigInteger h = getSHA256(generator, V, X, userID);
        BigInteger coFactor = ecSpec.getH();
        BigInteger q = curve.getQ();
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
            curve.decodePoint(X.getEncoded(false));
        }
        catch(Exception e){
            return false;
        }

        // 4. Check that nX = infinity.
        // It is equivalent - but more more efficient - to check the coFactor*X is not infinity
        if (X.multiply(coFactor).isInfinity()) {
            return false;
        }

        // Now check if V = G*r + X*h.
        // Given that {G, X} are valid points on curve, the equality implies that V is also a point on curve.
        return V.equals(
                generator
                        .multiply(r)
                        .add(
                                X.multiply(h)
                        )
        );
    }

    private  BigInteger getSHA256(ECPoint generator, ECPoint V, ECPoint X, byte[] userID) {
        byte [] GBytes = generator.getEncoded(false);
        byte [] VBytes = V.getEncoded(false);
        byte [] XBytes = X.getEncoded(false);
        byte [] result = new byte[sha.getLength()];

        sha.reset();
        sha.update(GBytes, (short) 0, (short) GBytes.length);
        sha.update(VBytes, (short) 0, (short) VBytes.length);
        sha.update(XBytes, (short) 0, (short) XBytes.length);
        sha.doFinal(
                userID, (short) 0, (short) userID.length,
                result, (short) 0
        );
        return new BigInteger(result);
    }
}

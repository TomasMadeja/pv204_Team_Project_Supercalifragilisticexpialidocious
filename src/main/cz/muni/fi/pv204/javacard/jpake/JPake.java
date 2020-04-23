package cz.muni.fi.pv204.javacard.jpake;


//import org.bouncycastle.asn1.x9.ECNamedCurveTable;

import javacard.framework.Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;


public class JPake {

    public final JPakeECParam group; // TODO set some default
    public final ECParameterSpec ecSpec;
    public final ECCurve curve;
    //private BigInteger a = curve.getA().toBigInteger();
    //private BigInteger b = curve.getB().toBigInteger();
    //private BigInteger q = curve.getQ();
    //private BigInteger coFactor = ecSpec.getH(); // Not using the symbol "h" here to avoid confusion as h will be used later in SchnorrZKP. 
    private BigInteger n;
    private ECPoint G;
    public final short sizeOfGx;
    public final short sizeOfAB;
    public final short sizeOfZKP;
    public final short sizeOfID;

    private byte[] participantID;
    private JPakePassword password; //TODO getnout cosi blabla

    /**
     * Alice's x1 or Bob's x3.
     */
    private BigInteger x1;
    /**
     * Alice's x2 or Bob's x4.
     */
    private BigInteger x2;
    /**
     * Alice's g^x1 or Bob's g^x3.
     */
    private ECPoint Gx1;
    /**
     * Alice's g^x2 or Bob's g^x4.
     */
    private ECPoint Gx2;
    /**
     * Alice's g^x3 or Bob's g^x1.
     */
    private ECPoint Gx3;
    /**
     * Alice's g^x4 or Bob's g^x2.
     */
    private ECPoint Gx4;
    /**
     * Alice's B or Bob's A.
     */
    private ECPoint B;


    public JPake(
            byte[] participantID,
            JPakePassword password,
            JPakeECParam group
    ) {
        // TODO add proper sizes
        sizeOfGx = 1;
        sizeOfAB = 1;
        sizeOfZKP = 1;
        sizeOfID = 1;
        this.participantID = participantID;
        this.password = password;
        this.ecSpec = ECNamedCurveTable.getParameterSpec("P-256");
        this.group = group;
        this.curve = ecSpec.getCurve();
        this.n = ecSpec.getN();
        this.G = ecSpec.getG();

    }

  
    public BigInteger[] createRound2PayloadToSend(
            byte[] Gx3,
            byte[] Gx4,
            byte[] B,
            byte[] knowledgeProofForX3V,
            BigInteger knowledgeProofForX3r, //ignored
            byte[] knowledgeProofForX4V,
            BigInteger knowledgeProofForX4r, //ignored
            byte[] knowledgeProofForX4sV,
            BigInteger knowledgeProofForX4sr, //ignored
            byte[] participantId
    ) {
        BigInteger[] result = new BigInteger[3];

        this.x1 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
                n.subtract(BigInteger.ONE), new SecureRandom());
        this.x2 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
                n.subtract(BigInteger.ONE), new SecureRandom());

        // Gx1 (actually Gx3) and ZKP
        this.Gx1 = G.multiply(x1);
        BigInteger v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
        			n.subtract(BigInteger.ONE), new SecureRandom());
        ECPoint zkpX1V = G.multiply(v);
        result[0] = group.generateZKPr(
                G,
                x1, Gx1,
                zkpX1V, v,
                this.participantID
        );

        // Gx2 (actually Gx4) and ZKP
        this.Gx2 = G.multiply(x2);
        v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
        			n.subtract(BigInteger.ONE), new SecureRandom());
        ECPoint zkpX2V = G.multiply(v);
        result[1] = group.generateZKPr(
                G,
                x2, Gx2,
                zkpX2V, v,
                this.participantID
        );

        // B (actually B) and ZKP
        ECPoint GB = Gx1.add(this.Gx3).add(this.Gx4);
        byte[] pass = password.getPassword();
        BigInteger x2s = x2.multiply(new BigInteger(password.getPassword()));
    	ECPoint Bpoint = GB.multiply(x2s);
        
        v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
        			n.subtract(BigInteger.ONE), new SecureRandom());
        ECPoint zkpX2sV = GB.multiply(v);
        result[2] = group.generateZKPr(
                GB,
                x2s, Bpoint,
                zkpX2sV, v,
                this.participantID
        );

        // FILL

        byte[] point;
        point = this.Gx1.getEncoded(false); // Gx3
        Util.arrayCopy(
                point, (short) 0,
                Gx3, (short) 0,
                (short) point.length
        );
        point = this.Gx2.getEncoded(false); // Gx4
        Util.arrayCopy(
                point, (short) 0,
                Gx4, (short) 0,
                (short) point.length
        );
        point = Bpoint.getEncoded(false); // B
        Util.arrayCopy(
                point, (short) 0,
                B, (short) 0,
                (short) point.length
        );
        point = zkpX1V.getEncoded(false); // ZKP x3
        Util.arrayCopy(
                point, (short) 0,
                knowledgeProofForX3V, (short) 0,
                (short) point.length
        );
        point = zkpX2V.getEncoded(false); // ZKP x4
        Util.arrayCopy(
                point, (short) 0,
                knowledgeProofForX4V, (short) 0,
                (short) point.length
        );
        point = zkpX2sV.getEncoded(false); // ZKP x4
        Util.arrayCopy(
                point, (short) 0,
                knowledgeProofForX4sV, (short) 0,
                (short) point.length
        );
        return result;
    }


    public boolean validateRound1PayloadReceived(
            byte[] Gx1,
            byte[] Gx2,
            byte[] knowledgeProofForX1V,
            BigInteger knowledgeProofForX1r,
            byte[] knowledgeProofForX2V,
            BigInteger knowledgeProofForX2r,
            byte[] participantID
    ) {
        try {

            ECPoint zkpX1V = curve.decodePoint(knowledgeProofForX1V);
            this.Gx3 = group.curve.decodePoint(Gx1);

            if (!group.verifyZKP(
                    G, this.Gx3,
                    zkpX1V, knowledgeProofForX1r,
                    participantID
            )) {
                return false;
            }

            ECPoint zkpX2V = curve.decodePoint(knowledgeProofForX2V);
            this.Gx4 = curve.decodePoint(Gx2);
            if (!group.verifyZKP(
                    G, Gx4,
                    zkpX2V, knowledgeProofForX2r,
                    participantID
            )) {
                return false;
            }


        } catch (Exception e) {
            return false;
        }

        return true;

    }


    public boolean validateRound3PayloadReceived(
            byte[] A,
            byte[] knowledgeProofForX2sV,
            BigInteger knowledgeProofForX2sr,
            byte[] participantId
    ) {
        try {
            // B (actually A)
            this.B = curve.decodePoint(A);

            ECPoint GA = this.Gx3.add(this.Gx1).add(this.Gx2);
            ECPoint zkpX2sV = curve.decodePoint(knowledgeProofForX2sV);
            if (!group.verifyZKP(
                    GA, this.B,
                    zkpX2sV, knowledgeProofForX2sr,
                    participantId
            )) {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
        return  true;
    }


    public byte[] calculateKeyingMaterial()
    {
        BigInteger s = new BigInteger(password.getPassword());
        ECPoint keyingMaterial = (B.subtract(
                Gx4.multiply(
                        x2
                ).multiply(s)
        )).multiply(x2);
        return keyingMaterial.getEncoded(false);
    }

}
package cz.muni.fi.pv204.javacard.jpake;

//import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;

import java.io.InvalidObjectException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;



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
    
    private char[] participantID;
    private byte[] participantID_byte;
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
    private byte digest;


    private BigInteger knowledgeProofForX1r;
    private BigInteger knowledgeProofForX2r;
    private BigInteger knowledgeProofForX3r;
    private BigInteger knowledgeProofForX4r;
    
    private ECPoint knowledgeProofForX1V;
    private ECPoint knowledgeProofForX2V;
    private ECPoint knowledgeProofForX3V;
    private ECPoint knowledgeProofForX4V;


    private BigInteger knowledgeProofForX2sr;
    private BigInteger knowledgeProofForX4sr;
    private ECPoint knowledgeProofForX2sV;
    private ECPoint knowledgeProofForX4sV;





/*
    public JPake(
            char[] participantID,
            JPakePassword password
    ) {
        // TODO add proper sizes
        sizeOfGx = 1;
        sizeOfAB = 1;
        sizeOfZKP = 1;
        sizeOfID = 1;

        this.password=password;
        this.participantID=participantID;


    }
*/

    public JPake(
            char[] participantID,
            JPakePassword password,
            JPakeECParam group,
            byte digest
    ) {
        // TODO add proper sizes
        sizeOfGx = 1;
        sizeOfAB = 1;
        sizeOfZKP = 1;
        sizeOfID = 1;
        this.participantID=participantID; // add byte[] equivalents?
        this.password=password;
        this.ecSpec = ECNamedCurveTable.getParameterSpec("P-256");  
        this.group = group;
        this.curve = ecSpec.getCurve();
        this.digest = digest;
        this.n = ecSpec.getN();
        this.G = ecSpec.getG();

    }

/*
    public void createRound1PayloadToSend(
            byte[] Gx1,
            byte[] Gx2,
            byte[] knowledgeProofForX1,
            byte[] knowdledgeProofForX2s,
            byte[] participantId
    ) {
        this.Gx1=Gx1;
        this.Gx2= Gx2;
        this.knowledgeProofForX1=knowledgeProofForX1;
        this.knowledgeProofForX2s=knowdledgeProofForX2s;
        this.participantID_byte=participantId;
    }
*/

    public BigInteger[] createRound2PayloadToSend(
            byte[] Gx3,
            byte[] Gx4,
            byte[] B,
            byte[] knowledgeProofForX3V,
            BigInteger knowledgeProofForX3r, //ignored
            byte[] knowdledgeProofForX4V,
            BigInteger knowledgeProofForX4r, //ignored
            byte[] knowdledgeProofForX4sV,
            BigInteger knowledgeProofForX4sr, //ignored
            byte[] participantId
    ) { 
        this.x1 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
        this.x2 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
        
        this.Gx1 = G.multiply(x1);
        this.Gx2 = G.multiply(x2);
        //TODO fill this into byte[] x3, x4
        
        BigInteger v1 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
        			n.subtract(BigInteger.ONE), new SecureRandom());
        this.knowledgeProofForX1V = G.multiply(v1);
        this.knowledgeProofForX1r = JPakeECParam.generateZKPr(G, n, x1, Gx1, knowledgeProofForX1V, v1, Arrays.toString(participantID));
        //TODO copy this ??
        
        BigInteger v2 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
        			n.subtract(BigInteger.ONE), new SecureRandom());
        this.knowledgeProofForX2V = G.multiply(v2);
        this.knowledgeProofForX2r = JPakeECParam.generateZKPr(G, n, x2, Gx2, knowledgeProofForX1V, v2, Arrays.toString(participantID));
        //TODO fill this into zkproofs x3, x4
        
        ECPoint GB = Gx1.add(Gx2).add(this.Gx3); //is this correct?
        BigInteger s2 = new BigInteger("1234".getBytes());
    	ECPoint BtoSend = GB.multiply(x2.multiply(s2).mod(n)); 
        //todo fill the above into byte[] B
        
        BigInteger v2s = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
        			n.subtract(BigInteger.ONE), new SecureRandom());
        this.knowledgeProofForX2sV = G.multiply(v2s);
        this.knowledgeProofForX2sr = JPakeECParam.generateZKPr(G, n, x2.multiply(s2).mod(n), BtoSend, knowledgeProofForX1V, v2s, Arrays.toString(participantID));
        //TODO fill the above into byte[] knowdledgeProofForX4sV, and BigInteger knowledgeProofForX4sr
        
        return new BigInteger[0];
    }

/*
    public void createRound3PayloadToSend(
            byte[] A,
            byte[] knowdledgeProofForX2s,
            byte[] participantId
    ) {
        this.A=A;
        this.knowledgeProofForX2s=knowdledgeProofForX2s;
        this.participantID_byte=participantId;
    }

*/
    public boolean validateRound1PayloadReceived(
            byte[] Gx1,
            byte[] Gx2,
            byte[] knowledgeProofForX1V,
            BigInteger knowledgeProofForX1r,
            byte[] knowledgeProofForX2V,
            BigInteger knowledgeProofForX2r,
            byte[] participantId
    ) { 
        try {
            //X9ECParameters curve = ECNamedCurveTable.getByName("P-256");
            //ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-256");
            //ECCurve curve = ecSpec.getCurve();
            ECDomainParameters ecparams = new ECDomainParameters(ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN(), ecSpec.getH(), ecSpec.getSeed());
            // check if Gx1,Gx2 are infinity

            if (( JPakeECParam.byteArrayToECPoint(Gx1)).isInfinity() ||
                    (JPakeECParam.byteArrayToECPoint(Gx2)).isInfinity())
             throw new Exception("infnity point ");

            // check if points are valid for the given curve
            ecparams.getCurve().decodePoint((JPakeECParam.byteArrayToECPoint(Gx1)).getEncoded(false));
            ecparams.getCurve().decodePoint((JPakeECParam.byteArrayToECPoint(Gx2)).getEncoded(false));

            //beginning of checking the proof
            ECPoint V1 = JPakeECParam.byteArrayToECPoint(knowledgeProofForX1V);
            BigInteger r1 = knowledgeProofForX1r;
            ECPoint Gx1Point = JPakeECParam.byteArrayToECPoint(Gx1);
            
            //BigInteger h = JPakeECParam.getSHA256(ecSpec.getG(), V, Gx1Point, Arrays.toString(participantID));
            //verifyZKP(ECParameterSpec ecSpec, ECPoint generator, ECPoint X, ECPoint V, BigInteger r, BigInteger q, String userID) {	
            if (!JPakeECParam.verifyZKP(ecSpec, ecSpec.getG(), Gx1Point, V1, r1, ecSpec.getN(), Arrays.toString(participantID)) ) {
                return false;
            }
            ECPoint V2 = JPakeECParam.byteArrayToECPoint(knowledgeProofForX2V);
            BigInteger r2 = knowledgeProofForX2r;
            ECPoint Gx2Point = JPakeECParam.byteArrayToECPoint(Gx2);
            if (!JPakeECParam.verifyZKP(ecSpec, ecSpec.getG(), Gx2Point, V2, r2, ecSpec.getN(), Arrays.toString(participantID)) ) {
                return false;
            }

            }
        catch(Exception e)
        {
            //System.out.println("exception in JPake");
            //e.printStackTrace();
            return false;
        }

        return true;

    }

/*
    public void validateRound2PayloadReceived(
            byte[] Gx3,
            byte[] Gx4,
            byte[] B,
            byte[] knowledgeProofForX3,
            byte[] knowledgeProofForX4,
            byte[] knowledgeProofForX4s,
            byte[] participantId
    ) {
    
    
    }
*/

    public void validateRound3PayloadReceived(
            byte[] A,
            BigInteger knowledgeProofForX2s,
            byte[] participantId
    ) { }


    public void calculateKeyingMaterial(
            byte[] keyingMaterial
    ) { 
    BigInteger s2 = new BigInteger("1234".getBytes());
    BigInteger Kb = JPakeECParam.getSHA256( B.subtract(Gx4.multiply(x2.multiply(s2).mod(n))).multiply(x2).getXCoord().toBigInteger());
    //TODO save Kb into byte[] keyingMaterial
    
    }

}
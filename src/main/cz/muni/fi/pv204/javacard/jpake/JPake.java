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



    private JPakeECParam group; // TODO set some default
    public final short sizeOfGx;
    public final short sizeOfAB;
    public final short sizeOfZKP;
    public final short sizeOfID;
    private char[] participantID;
    private byte[] participantID_byte;
    private JPakePassword password;
    private byte digest;
    private byte []Gx1;
    private byte []Gx2;
    private byte []Gx3;
    private byte []Gx4;

    private byte[] knowledgeProofForX1;
    private byte[] knowledgeProofForX2;
    private byte[] knowledgeProofForX3;
    private byte[] knowledgeProofForX4;

    private byte[] knowledgeProofForX1s;
    private byte[] knowledgeProofForX2s;
    private byte[] knowledgeProofForX3s;
    private byte[] knowledgeProofForX4s;

    private byte[]A;
    private byte[]B;





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
        this.participantID=participantID;
        this.password=password;
        this.group = group;
        this.digest = digest;

    }


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


    public void createRound2PayloadToSend(
            byte[] Gx3,
            byte[] Gx4,
            byte[] B,
            byte[] knowledgeProofForX3,
            byte[] knowdledgeProofForX4,
            byte[] knowdledgeProofForX4s,
            byte[] participantId
    ) {
        this.Gx3=Gx3;
        this.Gx4= Gx4;
        this.B=B;
        this.knowledgeProofForX3=knowledgeProofForX3;
        this.knowledgeProofForX4=knowdledgeProofForX4;
        this.knowledgeProofForX4s=knowdledgeProofForX4s;
        this.participantID_byte=participantId;
    }


    public void createRound3PayloadToSend(
            byte[] A,
            byte[] knowdledgeProofForX2s,
            byte[] participantId
    ) {
        this.A=A;
        this.knowledgeProofForX2s=knowdledgeProofForX2s;
        this.participantID_byte=participantId;
    }


    public void validateRound1PayloadReceived(
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
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-256");
            ECCurve curve = ecSpec.getCurve();
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
                throw new Exception("The ZKP proof for x1 failed.");
            }
            ECPoint V2 = JPakeECParam.byteArrayToECPoint(knowledgeProofForX2V);
            BigInteger r2 = knowledgeProofForX2r;
            ECPoint Gx2Point = JPakeECParam.byteArrayToECPoint(Gx2);
            if (!JPakeECParam.verifyZKP(ecSpec, ecSpec.getG(), Gx2Point, V2, r2, ecSpec.getN(), Arrays.toString(participantID)) ) {
                throw new Exception("The ZKP proof for x1 failed.");
            }

            }
        catch(Exception e)
        {
            System.out.println("exception in JPake");
            e.printStackTrace();
        }



    }


    public void validateRound2PayloadReceived(
            byte[] Gx3,
            byte[] Gx4,
            byte[] B,
            byte[] knowledgeProofForX3,
            byte[] knowledgeProofForX4,
            byte[] knowledgeProofForX4s,
            byte[] participantId
    ) { }


    public void validateRound3PayloadReceived(
            byte[] A,
            byte[] knowledgeProofForX2s,
            byte[] participantId
    ) { }


    public void calculateKeyingMaterial(
            byte[] keyingMaterial
    ) { }

}
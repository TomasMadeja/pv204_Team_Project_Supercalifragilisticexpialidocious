package cz.muni.fi.pv204.javacard.jpake;

import java.math.BigInteger;

public class JPake {



    private JPakeECParam group; // TODO set some default
    public final short sizeOfGx;
    public final short sizeOfAB;
    public final short sizeOfZKP;
    public final short sizeOfID;

    public JPake(
            char[] participantID,
            JPakePassword password
    ) {
        // TODO add proper sizes
        sizeOfGx = 1;
        sizeOfAB = 1;
        sizeOfZKP = 1;
        sizeOfID = 1;
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
    }


    public void createRound1PayloadToSend(
           byte[] Gx1,
           byte[] Gx2,
           byte[] knowledgeProofForX1V,
           BigInteger knowledgeProofForX1r,
           byte[] knowdledgeProofForX2sV,
           BigInteger knowledgeProofForX2r,
           byte[] participantId
    ) { }


    public BigInteger[] createRound2PayloadToSend(
            byte[] Gx3,
            byte[] Gx4,
            byte[] B,
            byte[] knowledgeProofForX3V,
            BigInteger knowledgeProofForX3r,
            byte[] knowdledgeProofForX4V,
            BigInteger knowledgeProofForX4r,
            byte[] knowdledgeProofForX4sV,
            BigInteger knowledgeProofForX4sr,
            byte[] participantId
    ) {
        return new BigInteger[0];
    }


    public void createRound3PayloadToSend(
            byte[] A,
            byte[] knowdledgeProofForX2sV,
            BigInteger knowledgeProofForX2sr,
            byte[] participantId
    ) { }


    public void validateRound1PayloadReceived(
            byte[] Gx1,
            byte[] Gx2,
            byte[] knowledgeProofForX1V,
            BigInteger knowledgeProofForX1r,
            byte[] knowledgeProofForX2V,
            BigInteger knowledgeProofForX2r,
            byte[] participantId
    ) { }


    public void validateRound2PayloadReceived(
            byte[] Gx3,
            byte[] Gx4,
            byte[] B,
            byte[] knowledgeProofForX3V,
            BigInteger knowledgeProofForX3r,
            byte[] knowledgeProofForX4V,
            BigInteger knowledgeProofForX4r,
            byte[] knowledgeProofForX4sV,
            BigInteger knowledgeProofForX4sr,
            byte[] participantId
    ) { }


    public void validateRound3PayloadReceived(
            byte[] A,
            byte[] knowledgeProofForX2sV,
            BigInteger knowledgeProofForX2sr,
            byte[] participantId
    ) { }


    public void calculateKeyingMaterial(
            byte[] keyingMaterial
    ) { }

}

package cz.muni.fi.pv204.javacard.jpake;

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
           byte[] knowledgeProofForX1,
           byte[] knowdledgeProofForX2s,
           byte[] participantId
    ) { }


    public void createRound2PayloadToSend(
            byte[] Gx3,
            byte[] Gx4,
            byte[] B,
            byte[] knowledgeProofForX3,
            byte[] knowdledgeProofForX4,
            byte[] knowdledgeProofForX4s,
            byte[] participantId
    ) { }


    public void createRound3PayloadToSend(
            byte[] A,
            byte[] knowdledgeProofForX2s,
            byte[] participantId
    ) { }


    public void validateRound1PayloadReceived(
            byte[] Gx1,
            byte[] Gx2,
            byte[] knowledgeProofForX1,
            byte[] knowledgeProofForX2,
            byte[] participantId
    ) { }


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

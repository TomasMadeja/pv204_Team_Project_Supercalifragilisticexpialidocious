package cz.muni.fi.pv204.javacard.jpake;

public class JPake {

    private JPakeECParam group; // TODO set some default

    public JPake(
            char[] participantID,
            JPakePassword[] password
    ) { }


    public JPake(
            char[] participantID,
            byte[] password,
            JPakeECParam group,
            byte digest
    ) { }


    public void createRound1PayloadToSend(
           byte[] Gx1,
           byte[] Gx2,
           byte[] knowledgeProofForX1,
           byte[] knowdledgeProofForX2,
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
            byte[] knowdledgeProofForX2s
    ) { }


    public void validateRound1PayloadReceived(
            byte[] Gx1,
            byte[] Gx2,
            byte[] knowledgeProofForX1,
            byte[] knowdledgeProofForX2,
            byte[] participantId
    ) { }


    public void validateRound2PayloadReceived(
            byte[] Gx3,
            byte[] Gx4,
            byte[] B,
            byte[] knowledgeProofForX3,
            byte[] knowdledgeProofForX4,
            byte[] knowdledgeProofForX4s,
            byte[] participantId
    ) { }


    public void validateRound3PayloadReceived(
            byte[] A,
            byte[] knowdledgeProofForX2ss
    ) { }


    public void calculateKeyingMaterial(
            byte[] keyingMaterial
    ) { }

}

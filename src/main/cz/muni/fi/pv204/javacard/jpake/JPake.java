package cz.muni.fi.pv204.javacard.jpake;

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
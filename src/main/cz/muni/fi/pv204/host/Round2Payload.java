/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.muni.fi.pv204.host;

/**
 *
 * @author minh
 */
//package org.bouncycastle.crypto.agreement.jpake;

//import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;
//import org.bouncycastle.util.Arrays;

/**
 * The payload sent/received during the second round of a J-PAKE exchange.
 * <p>
 * Each {@link JPAKEParticipant} creates and sends an instance
 * of this payload to the other {@link JPAKEParticipant}.
 * The payload to send should be created via
 * {@link JPAKEParticipant#createRound2PayloadToSend()}
 * <p>
 * Each {@link JPAKEParticipant} must also validate the payload
 * received from the other {@link JPAKEParticipant}.
 * The received payload should be validated via
 * {@link JPAKEParticipant#validateRound2PayloadReceived(JPAKERound2Payload)}
 */
public class Round2Payload
{
    /**
     * The id of the {@link JPAKEParticipant} who created/sent this payload.
     */
    private final String participantId;

    /**
     * The value of Gx3, as computed for the 2nd pass.
     */
    private final ECPoint Gx3;
    /**
     * The value of Gx4, as computed for the 2nd pass.
     */
    private final ECPoint Gx4;
    /**
     * The value of B, as computed for the 2nd pass.
     */
    private final ECPoint B;

    /**
     * The zero knowledge proof for x3.
     */
    private final SchnorrZKP knowledgeProofForX3;
    /**
     * The zero knowledge proof for x4.
     */
    private final SchnorrZKP knowledgeProofForX4;
    /**
     * The zero knowledge proof for x4 * s.
     */
    private final SchnorrZKP knowledgeProofForX4s;

    public Round2Payload(
        String participantId,
        ECPoint Gx3,
        ECPoint Gx4,
        ECPoint B,
        SchnorrZKP knowledgeProofForX3,
        SchnorrZKP knowledgeProofForX4,
        SchnorrZKP knowledgeProofForX4s)
    {
        Util.validateNotNull(participantId, "participantId");
        Util.validateNotNull(Gx3, "Gx3");
        Util.validateNotNull(Gx4, "Gx4");
        Util.validateNotNull(B, "B");
        Util.validateNotNull(knowledgeProofForX3, "knowledgeProofForX3");
        Util.validateNotNull(knowledgeProofForX4, "knowledgeProofForX4");
        Util.validateNotNull(knowledgeProofForX4s, "knowledgeProofForX4s");

        this.participantId = participantId;
        this.B = B;
        this.Gx3 = Gx3;
        this.Gx4 = Gx4;
        this.knowledgeProofForX3 = knowledgeProofForX3;
        this.knowledgeProofForX4 = knowledgeProofForX4;
        this.knowledgeProofForX4s = knowledgeProofForX4s;
    }

    public String getParticipantId()
    {
        return participantId;
    }

    public ECPoint getB()
    {
        return B;
    }
    public ECPoint getGx3()
    {
        return Gx3;
    }
    public ECPoint getGx4()
    {
        return Gx4;
    }

    public SchnorrZKP getKnowledgeProofForX4s()
    {
        return knowledgeProofForX4s;
    }
    public SchnorrZKP getKnowledgeProofForX3()
    {
        return knowledgeProofForX3;
    }
    public SchnorrZKP getKnowledgeProofForX4()
    {
        return knowledgeProofForX4;
    }

}

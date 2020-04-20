/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.muni.fi.pv204.host;

/**
 * Class for creation of the first round of J-PAKE protocol
 * based on bouncycastle J-PAKE library and ECC J-PAKE demo
 * by Hao Feng
 * @author minh
 */
//package org.bouncycastle.crypto.agreement.jpake;

//import java.math.BigInteger;

//import org.bouncycastle.util.Arrays;
//import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * The payload sent/received during the first round of a J-PAKE exchange.
 * <p>
 * Each {@link JPAKEParticipant} creates and sends an instance
 * of this payload to the other {@link JPAKEParticipant}.
 * The payload to send should be created via
 * {@link JPAKEParticipant#createRound1PayloadToSend()}.
 * <p>
 * Each {@link JPAKEParticipant} must also validate the payload
 * received from the other {@link JPAKEParticipant}.
 * The received payload should be validated via
 * {@link JPAKEParticipant#validateRound1PayloadReceived(JPAKERound1Payload)}.
 */
public class Round1Payload
{
    /**
     * The id of the {@link JPAKEParticipant} who created/sent this payload.
     */
    private final String participantId;

    /**
     * The value of g^x1
     */
    private final ECPoint Gx1;

    /**
     * The value of g^x2
     */
    private final ECPoint Gx2;

    /**
     * The zero knowledge proof for x1.
     * <p>
     * This is a class, containing {g^v, r} for x1.
     * </p>
     */
    private final SchnorrZKP knowledgeProofForX1;

    /**
     * The zero knowledge proof for x2.
     * <p>
     * This is a class, containing {g^v, r} for x2.
     * </p>
     */
    private final SchnorrZKP knowledgeProofForX2;

    public Round1Payload(
        String participantId,
        ECPoint Gx1,
        ECPoint Gx2,
        SchnorrZKP knowledgeProofForX1,
        SchnorrZKP knowledgeProofForX2)
    {
        Util.validateNotNull(participantId, "participantId");
        Util.validateNotNull(Gx1, "Gx1");
        Util.validateNotNull(Gx2, "Gx2");
        Util.validateNotNull(knowledgeProofForX1, "knowledgeProofForX1");
        Util.validateNotNull(knowledgeProofForX2, "knowledgeProofForX2");

        this.participantId = participantId;
        this.Gx1 = Gx1;
        this.Gx2 = Gx2;
        this.knowledgeProofForX1 = knowledgeProofForX1;
         //       = Arrays.copyOf(knowledgeProofForX1, knowledgeProofForX1.length);
        this.knowledgeProofForX2 = knowledgeProofForX2;
    }

    public String getParticipantId()
    {
        return participantId;
    }

    public ECPoint getGx1()
    {
        return Gx1;
    }

    public ECPoint getGx2()
    {
        return Gx2;
    }

    public SchnorrZKP getKnowledgeProofForX1()
    {
        return knowledgeProofForX1;
    }

    public SchnorrZKP getKnowledgeProofForX2()
    {
        return knowledgeProofForX2;
    }

}

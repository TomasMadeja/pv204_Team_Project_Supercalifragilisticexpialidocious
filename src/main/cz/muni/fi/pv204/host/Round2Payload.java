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
     * The value of A, as computed during round 2.
     */
    private final ECPoint A;

    /**
     * The zero knowledge proof for x2 * s.
     * <p>
     * This is a two element array, containing {g^v, r} for x2 * s.
     * </p>
     */
    private final SchnorrZKP knowledgeProofForX2s;

    public Round2Payload(
        String participantId,
        ECPoint A,
        SchnorrZKP knowledgeProofForX2s)
    {
        Util.validateNotNull(participantId, "participantId");
        Util.validateNotNull(A, "A");
        Util.validateNotNull(knowledgeProofForX2s, "knowledgeProofForX2s");

        this.participantId = participantId;
        this.A = A;
        this.knowledgeProofForX2s = knowledgeProofForX2s;
    }

    public String getParticipantId()
    {
        return participantId;
    }

    public ECPoint getA()
    {
        return A;
    }

    public SchnorrZKP getKnowledgeProofForX2s()
    {
        return knowledgeProofForX2s;
    }

}

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.muni.fi.pv204.host;

/**
 * TODO!!!
 * Finish the MAC tags!!!
 * @author minh
 */
//package org.bouncycastle.crypto.agreement.jpake;
import org.bouncycastle.math.ec.ECPoint;
import java.math.BigInteger;

/**
 * The payload sent/received during the optional third round of a J-PAKE exchange,
 * which is for explicit key confirmation.
 * <p>
 * Each {@link JPAKEParticipant} creates and sends an instance
 * of this payload to the other {@link JPAKEParticipant}.
 * The payload to send should be created via
 * {@link JPAKEParticipant#createRound3PayloadToSend(BigInteger)}
 * <p>
 * Each {@link JPAKEParticipant} must also validate the payload
 * received from the other {@link JPAKEParticipant}.
 * The received payload should be validated via
 * {@link JPAKEParticipant#validateRound3PayloadReceived(JPAKERound3Payload, BigInteger)}
 */
public class Round3Payload
{
    /**
     * The id of the {@link JPAKEParticipant} who created/sent this payload.
     */
    private final String participantId;

    /**
     * The value of MacTag, as computed by round 3.
     *
     * @see JPAKEUtil#calculateMacTag(String, String, BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, org.bouncycastle.crypto.Digest)
     */
    private final BigInteger macTag;

    public Round3Payload(String participantId, BigInteger magTag)
    {
        this.participantId = participantId;
        this.macTag = magTag;
    }

    public String getParticipantId()
    {
        return participantId;
    }

    public BigInteger getMacTag()
    {
        return macTag;
    }

}

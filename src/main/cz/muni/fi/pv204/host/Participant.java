/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.muni.fi.pv204.host;

/**
 * Class for the participant, host, of J-PAKE exchange
 * based on bouncycastle J-PAKE library
 * @author minh
 */
//package org.bouncycastle.crypto.agreement.jpake;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * A participant in a Password Authenticated Key Exchange by Juggling (J-PAKE) exchange.
 * <p>
 * The J-PAKE exchange is defined by Feng Hao and Peter Ryan in the paper
 * <a href="http://grouper.ieee.org/groups/1363/Research/contributions/hao-ryan-2008.pdf">
 * "Password Authenticated Key Exchange by Juggling, 2008."</a>
 * <p>
 * The J-PAKE protocol is symmetric.
 * There is no notion of a <i>client</i> or <i>server</i>, but rather just two <i>participants</i>.
 * An instance of {@link JPAKEParticipant} represents one participant, and
 * is the primary interface for executing the exchange.
 * <p>
 * To execute an exchange, construct a {@link JPAKEParticipant} on each end,
 * and call the following 7 methods
 * (once and only once, in the given order, for each participant, sending messages between them as described):
 * <ol>
 * <li>{@link #createRound1PayloadToSend()} - and send the payload to the other participant</li>
 * <li>{@link #validateRound1PayloadReceived(JPAKERound1Payload)} - use the payload received from the other participant</li>
 * <li>{@link #createRound2PayloadToSend()} - and send the payload to the other participant</li>
 * <li>{@link #validateRound2PayloadReceived(JPAKERound2Payload)} - use the payload received from the other participant</li>
 * <li>{@link #calculateKeyingMaterial()}</li>
 * <li>{@link #createRound3PayloadToSend(BigInteger)} - and send the payload to the other participant</li>
 * <li>{@link #validateRound3PayloadReceived(JPAKERound3Payload, BigInteger)} - use the payload received from the other participant</li>
 * </ol>
 * <p>
 * Each side should derive a session key from the keying material returned by {@link #calculateKeyingMaterial()}.
 * The caller is responsible for deriving the session key using a secure key derivation function (KDF).
 * <p>
 * Round 3 is an optional key confirmation process.
 * If you do not execute round 3, then there is no assurance that both participants are using the same key.
 * (i.e. if the participants used different passwords, then their session keys will differ.)
 * <p>
 * If the round 3 validation succeeds, then the keys are guaranteed to be the same on both sides.
 * <p>
 * The symmetric design can easily support the asymmetric cases when one party initiates the communication.
 * e.g. Sometimes the round1 payload and round2 payload may be sent in one pass.
 * Also, in some cases, the key confirmation payload can be sent together with the round2 payload.
 * These are the trivial techniques to optimize the communication.
 * <p>
 * The key confirmation process is implemented as specified in
 * <a href="http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf">NIST SP 800-56A Revision 1</a>,
 * Section 8.2 Unilateral Key Confirmation for Key Agreement Schemes.
 * <p>
 * This class is stateful and NOT threadsafe.
 * Each instance should only be used for ONE complete J-PAKE exchange
 * (i.e. a new {@link JPAKEParticipant} should be constructed for each new J-PAKE exchange).
 * <p>
 */
public class Participant
{
    /*
     * Possible internal states.  Used for state checking.
     */

    public static final int STATE_INITIALIZED = 0;
    public static final int STATE_ROUND_1_CREATED = 10;
    public static final int STATE_ROUND_1_VALIDATED = 20;
    public static final int STATE_ROUND_2_CREATED = 30;
    public static final int STATE_ROUND_2_VALIDATED = 40;
    public static final int STATE_ROUND_3_CREATED = 60;
    public static final int STATE_ROUND_3_VALIDATED = 70;
    public static final int STATE_KEY_CALCULATED = 80;

    /**
     * Unique identifier of this participant.
     * The two participants in the exchange must NOT share the same id.
     */
    private final byte[] participantId;

    /**
     * Shared secret.  This only contains the secret between construction
     * and the call to {@link #calculateKeyingMaterial()}.
     * <p>
     * i.e. When {@link #calculateKeyingMaterial()} is called, this buffer overwritten with 0's,
     * and the field is set to null.
     * </p>
     */
    private byte[] password;

    /**
     * Digest to use during calculations.
     */
    private final Digest digest;

    /**
     * Source of secure random data.
     */
    
    private final SecureRandom random;
    
    public final ECParameterSpec ecSpec;
    public final SecP256R1Curve ecCurve;
    private final BigInteger q;
    private final BigInteger coFactor; // Not using the symbol "h" here to avoid confusion as h will be used later in SchnorrZKP. 
    private final BigInteger n;
    private final ECPoint G;

    /**
     * The participantId of the other participant in this exchange.
     */
    private byte[] partnerParticipantId;

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

    /**
     * The current state.
     * See the <tt>STATE_*</tt> constants for possible values.
     */
    private int state;

    /**
     * Convenience constructor that uses the prime256v1 EC
     *
     * After construction, the {@link #getState() state} will be  {@link #STATE_INITIALIZED}.
     *
     * @param participantId unique identifier of this participant.
     *                      The two participants in the exchange must NOT share the same id.
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @throws NullPointerException if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public Participant(
        byte[] participantId,
        byte[] password)
    {
        this(
            participantId,
            password,
            ECNamedCurveTable.getParameterSpec("P-256"));  //TODO vybrat krivku
    }


    /**
     * Convenience constructor for a new PArticipant that uses
     * a SHA-256 digest and a default SecureRandom implementation.
     *
     * @param participantId unique identifier of this participant.
     *                      The two participants in the exchange must NOT share the same id.
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @param ecSpec
     * @throws NullPointerException if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public Participant(
        byte[] participantId,
        byte[] password,
        ECParameterSpec ecSpec)
    {
        this(
            participantId,
            password,
            ecSpec,
            new SHA256Digest(),
            CryptoServicesRegistrar.getSecureRandom());
    }


    /**
     * Construct a new Participant.
     * The most flexible constructor
     * <p>
     * After construction, the {@link #getState() state} will be  {@link #STATE_INITIALIZED}.
     *
     * @param participantId unique identifier of this participant.
     *                      The two participants in the exchange must NOT share the same id.
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @param ecSpec
     * @param digest        digest to use during zero knowledge proofs and key confirmation (SHA-256 or stronger preferred)
     * @param random        source of secure random data for x1 and x2, and for the zero knowledge proofs
     * @throws NullPointerException if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public Participant(
        byte[] participantId,
        byte[] password,
        ECParameterSpec ecSpec,
        Digest digest,
        SecureRandom random)
    {
        Util.validateNotNull(participantId, "participantId");
        Util.validateNotNull(password, "password");
        Util.validateNotNull(ecSpec, "E");
        Util.validateNotNull(digest, "digest");
        Util.validateNotNull(random, "random");
        if (password.length == 0)
        {
            throw new IllegalArgumentException("Password must not be empty.");
        }

        this.participantId = participantId;
        
        /*
         * Create a defensive copy so as to fully encapsulate the password.
         * 
         * This array will contain the password for the lifetime of this
         * participant BEFORE {@link #calculateKeyingMaterial()} is called.
         * 
         * i.e. When {@link #calculateKeyingMaterial()} is called, the array will be cleared
         * in order to remove the password from memory.
         * 
         * The caller is responsible for clearing the original password array
         * given as input to this constructor.
         */
        this.password = password;
        this.ecSpec = ecSpec;
        this.ecCurve = (SecP256R1Curve) ecSpec.getCurve();  //TODO group.getP(); come up with a compatible solution with the guys
        this.q = ecCurve.getQ();
        this.G = ecSpec.getG();
        this.coFactor = ecSpec.getH();
        this.n = ecSpec.getN();
        this.digest = digest;
        this.random = random;

        this.state = STATE_INITIALIZED;
    }

    /**
     * Gets the current state of this participant.
     * See the <tt>STATE_*</tt> constants for possible values.
     */
    public int getState()
    {
        return this.state;
    }

    /**
     * Creates and returns the payload to send to the other participant during pass 1
     * Only Alice, the one who initialize the communication should use this
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_1_CREATED}.
     * @return Round1Payload containing a point on EC and a Schnorr ZKP of the scalar522222222222u
     */
    public Round1Payload createRound1PayloadToSend()
    {
        if (this.state >= STATE_ROUND_1_CREATED)
        {
            throw new IllegalStateException("Round1 payload already created for " + participantId);
        }

        this.x1 = Util.generateX1(q, random);
        this.x2 = Util.generateX2(q, random);

        this.Gx1 = Util.calculateGx(G, x1);
        this.Gx2 = Util.calculateGx(G, x2);
        SchnorrZKP knowledgeProofForX1 = new SchnorrZKP();
        knowledgeProofForX1.generateZKP(G, n, x1, Gx1, participantId);  //TODO n
        SchnorrZKP knowledgeProofForX2 = new SchnorrZKP();
        knowledgeProofForX2.generateZKP(G, n, x2, Gx2, participantId);

        this.state = STATE_ROUND_1_CREATED;

        return new Round1Payload(participantId, Gx1, Gx2, knowledgeProofForX1, knowledgeProofForX2);
    }

    /**
     * Validates the payload received from the other participant during round 1.
     * <p>
     * Must be called prior to {@link #createRound2PayloadToSend()}.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_1_VALIDATED}.
     *
     * @throws CryptoException if validation fails.
     * @throws IllegalStateException if called multiple times.
     */
    public void validateRound1PayloadReceived(Round1Payload round1PayloadReceived)
        throws CryptoException
    {
        if (this.state >= STATE_ROUND_1_VALIDATED)
        {
            throw new IllegalStateException("Validation already attempted for round1 payload for" + participantId);
        }
        this.partnerParticipantId = round1PayloadReceived.getParticipantId();
        this.Gx3 = round1PayloadReceived.getGx1();
        this.Gx4 = round1PayloadReceived.getGx2();

        SchnorrZKP knowledgeProofForX3 = round1PayloadReceived.getKnowledgeProofForX1();
        SchnorrZKP knowledgeProofForX4 = round1PayloadReceived.getKnowledgeProofForX2();

        Util.validateGx4(Gx4);
        if(!knowledgeProofForX3.verifyZKP(ecSpec, G, Gx3, q, round1PayloadReceived.getParticipantId()) || //TODO
           !knowledgeProofForX4.verifyZKP(ecSpec, G, Gx4, q, round1PayloadReceived.getParticipantId()) ){
         throw new CryptoException("Zero knowledge of the 1st pass (from Alice) carried out by Bob failed.");
        } //TODO
//verifyZKP(ECParameterSpec ecSpec, ECPoint generator, ECPoint X, BigInteger q, String userID)
        this.state = STATE_ROUND_1_VALIDATED;
    }

    /**
     * Creates and returns the payload to send to the other participant during pass 2.
     * Only "Bob", the one who did NOT initialize the communication should use this method
     * <p>
     * {@link #validateRound1PayloadReceived(JPAKERound1Payload)} must be called prior to this method.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_2_CREATED}.
     *
     * @throws IllegalStateException if called prior to {@link #validateRound1PayloadReceived(JPAKERound1Payload)}, or multiple times
     */
    public Round2Payload createRound2PayloadToSend()
    {
        if (this.state >= STATE_ROUND_2_CREATED)
        {
            throw new IllegalStateException("Round2 payload already created for " + this.participantId);
        }
        if (this.state < STATE_ROUND_1_VALIDATED)
        {
            throw new IllegalStateException("Round1 payload must be validated prior to creating Round2 payload for " + this.participantId);
        }
        
        
        //from Bob's point of view
        //Bob's this.x1 is acutally x3 etc. 
        this.x1 = Util.generateX1(q, random);
        this.x2 = Util.generateX2(q, random);

        this.Gx1 = Util.calculateGx(G, x1);
        this.Gx2 = Util.calculateGx(G, x2);
        SchnorrZKP knowledgeProofForX3 = new SchnorrZKP();
        knowledgeProofForX3.generateZKP(G, n, x1, Gx1, participantId);  //TODO n
        SchnorrZKP knowledgeProofForX4 = new SchnorrZKP();
        knowledgeProofForX4.generateZKP(G, n, x2, Gx2, participantId);
        
        //Bob's this.Gx3  is the actual Gx1 etc.
        ECPoint GB = Util.calculateGA(Gx3, Gx4, Gx1);
        BigInteger s = Util.calculateS(password);
        //Bob's  this.x2 is the actual x4 etc.
        BigInteger x4s = Util.calculateX2s(q, x2, s);
        ECPoint B = Util.calculateA(q, GB, x4s);
        SchnorrZKP knowledgeProofForX4s = new SchnorrZKP();
        knowledgeProofForX4s.generateZKP(GB, n, x4s, B, participantId); //TODO n
        //zkpX2s.generateZKP(GA, n, x2.multiply(s1).mod(n), A, AliceID);
        //generateZKP (ECPoint generator, BigInteger n, BigInteger x, ECPoint X, String userID)

        this.state = STATE_ROUND_2_CREATED;

        return new Round2Payload(participantId,
        Gx1,
        Gx2,
        B,
        knowledgeProofForX3,
        knowledgeProofForX4,
        knowledgeProofForX4s);
    }

    /**
     * Validates the payload received from the other participant during pass 2.
     * This step is made by Alice.
     * <p>
     * Note that this DOES NOT detect a non-common password.
     * The only indication of a non-common password is through derivation
     * of different keys (which can be detected explicitly by executing round 3 and round 4)
     * <p>
     * Must be called prior to {@link #calculateKeyingMaterial()}.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_2_VALIDATED}.
     *
     * @throws CryptoException if validation fails.
     * @throws IllegalStateException if called prior to {@link #validateRound1PayloadReceived(JPAKERound1Payload)}, or multiple times
     */
    public void validateRound2PayloadReceived(Round2Payload round2PayloadReceived)
        throws CryptoException
    {
        if (this.state >= STATE_ROUND_2_VALIDATED)
        {
            throw new IllegalStateException("Validation already attempted for round2 payload for" + participantId);
        }
        this.B = round2PayloadReceived.getB();
        this.Gx3 = round2PayloadReceived.getGx3();
        this.Gx4 = round2PayloadReceived.getGx4();
        ECPoint Gb = Util.calculateGA(Gx3, Gx1, Gx2);
        
        SchnorrZKP knowledgeProofForX4s = round2PayloadReceived.getKnowledgeProofForX4s();
        SchnorrZKP knowledgeProofForX3 = round2PayloadReceived.getKnowledgeProofForX3();
        SchnorrZKP knowledgeProofForX4 = round2PayloadReceived.getKnowledgeProofForX4();
        
        //these throw exceptions
        Util.validateGa(Gb);
        //Util.validateZeroKnowledgeProof(p, q, gB, b, knowledgeProofForX4s, round2PayloadReceived.getParticipantId(), digest);
        
        //
        if (
        !knowledgeProofForX4s.verifyZKP(ecSpec, Gb, B, q, round2PayloadReceived.getParticipantId()) ||
        !knowledgeProofForX3.verifyZKP(ecSpec, G, Gx3, q, round2PayloadReceived.getParticipantId()) ||
        !knowledgeProofForX4.verifyZKP(ecSpec, G, Gx4, q, round2PayloadReceived.getParticipantId()) ){
        
            throw new CryptoException("Zero knowledge proofs of the 2nd pass (from Bob) carried out by Alice failed");
        }
        
        this.state = STATE_ROUND_2_VALIDATED;
        
        
    }


    /**
     * Creates and returns the payload to send to the other participant during the 3rd pass.
     * This is made by Alice
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_3_CREATED}.
     *
     * @return The payload sent by Alice during the 3rd pass of J-PAKE.
     * @throws IllegalStateException if called prior to {@link #calculateKeyingMaterial()}, or multiple times
     */
    public Round3Payload createRound3PayloadToSend()
    {
        if (this.state >= STATE_ROUND_3_CREATED)
        {
            throw new IllegalStateException("Round3 payload already created for " + this.participantId);
        }
        //if (this.state < STATE_KEY_CALCULATED)
        //{
        //    throw new IllegalStateException("Keying material must be calculated prior to creating Round3 payload for " + this.participantId);
        //}

        ECPoint GA = Util.calculateGA(Gx1, Gx3, Gx4);
        BigInteger s = Util.calculateS(password);
        BigInteger x2s = Util.calculateX2s(q, x2, s);
        ECPoint A = Util.calculateA(q, GA, x2s);
        SchnorrZKP knowledgeProofForX2s = new SchnorrZKP();
        knowledgeProofForX2s.generateZKP(GA, n, x2s, A, participantId);
        return new Round3Payload(participantId, A, knowledgeProofForX2s);
    }

    /**
     * Validates the payload received from the "Alice" participant during the 3rd pass.
     * This is carried out from bob's point of view
     * <p>
     * See {@link JPAKEParticipant} for more details on round 3.
     * <p>
     * After execution, the {@link #getState() state} will be {@link #STATE_ROUND_3_VALIDATED}.
     *
     * @param round3PayloadReceived The round 3 payload received from the other participant.
     * @throws CryptoException if validation fails.
     * @throws IllegalStateException if called prior to {@link #calculateKeyingMaterial()}, or multiple times
     */
    public void validateRound3PayloadReceived(Round3Payload round3PayloadReceived)
        throws CryptoException
    {   //These might be redundant
        if (this.state >= STATE_ROUND_3_VALIDATED)
        {
            throw new IllegalStateException("Validation already attempted for round3 payload for" + participantId);
        }
        
        ECPoint A = round3PayloadReceived.getA();
        Util.validateGa(A); //nevím, co se tu má testovat
        
        ECPoint Ga = Util.calculateGA(Gx3, Gx1, Gx2);
        Util.validateGa(A);
        SchnorrZKP knowledgeProofForX2s =round3PayloadReceived.getKnowledgeProofForX2s();
        if (knowledgeProofForX2s.verifyZKP(ecSpec, G, Ga, q, participantId)){
            throw new CryptoException("Zero knowledge proofs of the 3nd pass (from Alice) carried out by Bob failed");
        }
        /*
         * Clear the rest of the fields.
         */
        this.B = A;
        this.state = STATE_ROUND_3_VALIDATED;
    }

    /**
     * Calculates and returns the key material.
     * From the point of view od Alice
     *
     * A session key must be derived from this key material using a secure key derivation function (KDF).
     * The KDF used to derive the key is handled externally (i.e. not by {@link JPAKEParticipant}).
     * <p>
     * The keying material will be identical for each participant if and only if
     * each participant's password is the same.  i.e. If the participants do not
     * share the same password, then each participant will derive a different key.
     * Therefore, if you immediately start using a key derived from
     * the keying material, then you must handle detection of incorrect keys.
     * If you want to handle this detection explicitly, you can optionally perform
     * rounds 3 and 4.  See {@link JPAKEParticipant} for details on how to execute
     * rounds 3 and 4.
     * <p>
     * The keying material will be in the range <tt>[0, p-1]</tt>.
     * <p>
     * {@link #validateRound2PayloadReceived(JPAKERound2Payload)} must be called prior to this method.
     * <p>
     * As a side effect, the internal {@link #password} array is cleared, since it is no longer needed.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_KEY_CALCULATED}.
     *
     * @throws IllegalStateException if called prior to {@link #validateRound2PayloadReceived(JPAKERound2Payload)},
     * or if called multiple times.
     */
    public ECPoint calculateKeyingMaterial()
    {
        if (this.state >= STATE_KEY_CALCULATED)
        {
            throw new IllegalStateException("Key already calculated for " + participantId);
        }
        if (this.state < STATE_ROUND_2_VALIDATED)
        {
            throw new IllegalStateException("Round2 payload must be validated prior to creating key for " + participantId);
        }
        BigInteger s = Util.calculateS(password);

        /*
         * Clear the password array from memory, since we don't need it anymore.
         *
         * Also set the field to null as a flag to indicate that the key has already been calculated.
         */
        ECPoint keyingMaterial = Util.calculateKeyingMaterial(Gx4, x2, s, B);

        /*
         * Clear the ephemeral private key fields as well.
         * Note that we're relying on the garbage collector to do its job to clean these up.
         * The old objects will hang around in memory until the garbage collector destroys them.
         *
         * If the ephemeral private keys x1 and x2 are leaked,
         * the attacker might be able to brute-force the password.
         */

        /*
         * Do not clear gx* yet, since those are needed by round 3.
         */

        this.state = STATE_KEY_CALCULATED;

        return keyingMaterial;
    }

    public void clear() {
        for (int i = 0; i < password.length; i++) {
            password[i] = 0x00;
        }
        this.x1 = null;
        this.x2 = null;
        this.B = null;
        this.Gx1 = null;
        this.Gx2 = null;
        this.Gx3 = null;
        this.Gx4 = null;
        this.password = null;
        System.gc();
    }

}

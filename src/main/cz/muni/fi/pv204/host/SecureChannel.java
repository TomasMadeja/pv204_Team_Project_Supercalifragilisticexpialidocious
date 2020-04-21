package cz.muni.fi.pv204.host;


import org.apache.groovy.json.internal.ArrayUtils;
import org.bouncycastle.crypto.CryptoException;
import sun.security.util.ArrayUtil;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.SecureRandom;
import java.security.spec.ECPoint;

public class SecureChannel {

    public static final short CHALLANGE_LENGTH = 32;
    public static final int PASS_LEN = 4;

    private JCardSymInterface channel;
    private MagicAes aes;
    private SecureRandom rand;
    private Participant participant;

    public SecureChannel(
            JCardSymInterface channel,
            String participantId,
            char[] password
    ) throws Exception {
        if (password.length != PASS_LEN) throw new Exception();
        for (char c : password) {
            if (! Character.isDigit(c)) throw new Exception();
        }

        this.channel = channel;

        rand = SecureRandom.getInstanceStrong();
        aes = new MagicAes();
        participant = new Participant(participantId, password);
    }

    public void establishSC() throws Exception {
        ResponseAPDU r;
        r = establishmentRound1();
        r = establishmentRound3(r);
        establishmentHello(r);
    }

    public void wrap() { }
    public void unwrap() {}

    private ResponseAPDU establishmentRound1() throws CardException {

        Round1Payload round1 = participant.createRound1PayloadToSend();
        byte[] Gx1 = round1.getGx1().getEncoded(false);
        byte[] Gx2 = round1.getGx2().getEncoded(false);
        byte[] zkp1 = combine(
                round1.getKnowledgeProofForX1().getV().getEncoded(false),
                round1.getKnowledgeProofForX1().getr().toByteArray()
        );
        byte[] zkp2 = combine(
                round1.getKnowledgeProofForX2().getV().getEncoded(false),
                round1.getKnowledgeProofForX2().getr().toByteArray()
        );
        byte[] participantIDA = round1.getParticipantId().getBytes();

        short sizeOfGx = (short) Gx1.length;
        short sizeOfZKP = (short) zkp1.length;
        short sizeOfID = (short) participantIDA.length;
        // Obtained from generate round 1

        // TODO call round 1 generation

        int outgoingLength = 2*sizeOfGx + 2*sizeOfZKP + sizeOfID;
        byte[] outgoing = new byte[
                outgoingLength
                ];
        short outgoingOffset = 0;

        short offset = outgoingOffset; // Gx1
        System.arraycopy(
                Gx1, (short) 0,
                outgoing, offset,
                sizeOfGx
        );
        offset += sizeOfGx; // Gx2
        System.arraycopy(
                Gx2, (short) 0,
                outgoing, offset,
                sizeOfGx
        );
        offset += sizeOfGx; // ZKP x1
        System.arraycopy(
                zkp1, (short) 0,
                outgoing, offset,
                sizeOfZKP
        );
        offset += sizeOfZKP; // ZKP x2
        System.arraycopy(
                zkp2, (short) 0,
                outgoing, offset,
                sizeOfZKP
        );
        offset += sizeOfZKP; // ID
        System.arraycopy(
                participantIDA, (short) 0,
                outgoing, offset,
                sizeOfID
        );
        return channel.transmit(
                new CommandAPDU(outgoing)
        );
    }

    private ResponseAPDU establishmentRound3(
            ResponseAPDU response
    ) throws CardException, CryptoException {
        short sizeOfGx = 1;
        short sizeOfZKP = 1;
        short sizeOfAB = 1;
        short sizeOfID = 1;

        byte[] Gx3 = new byte[0];
        byte[] Gx4 = new byte[0];
        byte[] B = new byte[0];
        byte[] zkp1 = new byte[0];
        byte[] zkp2 = new byte[0];
        byte[] zkp3 = new byte[0];
        byte[] participantIDB = new byte[0];

        // Validation
        byte[] incoming = response.getData();

        short offset = 0;
        System.arraycopy(
                incoming, offset,
                Gx3, (short) 0,
                sizeOfGx
        );
        offset += sizeOfGx; // Gx2
        System.arraycopy(
                incoming, offset,
                Gx4, (short) 0,
                sizeOfGx
        );
        offset += sizeOfGx; // B
        System.arraycopy(
                incoming, offset,
                B, (short) 0,
                sizeOfAB
        );
        offset += sizeOfAB; // ZKP X3
        System.arraycopy(
                incoming, offset,
                zkp1, (short) 0,
                sizeOfZKP
        );
        offset += sizeOfZKP; // ZKP X4
        System.arraycopy(
                incoming, offset,
                zkp2, (short) 0,
                sizeOfZKP
        );
        offset += sizeOfZKP; // ZKP X4s
        System.arraycopy(
                incoming, offset,
                zkp3, (short) 0,
                sizeOfZKP
        );
        offset += sizeOfZKP; // ID
        System.arraycopy(
                incoming, offset,
                participantIDB, (short) 0,
                sizeOfID
        );


        participant.validateRound2PayloadReceived(
                new Round2Payload(
                        new String(participantIDB),
                        participant.ecCurve.decodePoint(Gx3),
                        participant.ecCurve.decodePoint(Gx4),
                        participant.ecCurve.decodePoint(B),
                        new SchnorrZKP(),
                        new SchnorrZKP(),
                        new SchnorrZKP()
            )
        );

        // Response
        // Obtained from generate round 3
        Round3Payload round3 = participant.createRound3PayloadToSend();
        byte[] A = round3.getA().getEncoded(false);
        zkp1 = combine(
                round3.getKnowledgeProofForX2s().getV().getEncoded(false),
                round3.getKnowledgeProofForX2s().getr().toByteArray()
        );
        byte[] participantIDA = round3.getParticipantId().getBytes();

        int outgoingLength = 2*sizeOfGx + 2*sizeOfZKP + sizeOfID;
        byte[] outgoing = new byte[
                outgoingLength
                ];
        short outgoingOffset = 0;

        offset = outgoingOffset; // Gx1
        System.arraycopy(
                A, (short) 0,
                outgoing, offset,
                sizeOfAB
        );
        offset += sizeOfAB; // ZKP X2s
        System.arraycopy(
                zkp1, (short) 0,
                outgoing, offset,
                sizeOfZKP
        );
        offset += sizeOfZKP; // ID
        System.arraycopy(
                participantIDA, (short) 0,
                outgoing, offset,
                sizeOfID
        );
        return channel.transmit(
                new CommandAPDU(outgoing)
        );
    }


    private void establishmentHello(
            ResponseAPDU response
    ) throws Exception {
        byte[] challenge = response.getData();
        if (challenge.length != CHALLANGE_LENGTH) {
            throw new Exception(); // TODO add specific range
        }

        // TODO add call for keying material
        byte[] keyingMaterial = participant.calculateKeyingMaterial().getEncoded(false);

        aes.generateKey(keyingMaterial, challenge);

        byte[] r = new byte[CHALLANGE_LENGTH];
        rand.nextBytes(r);

        byte[] outgoing = new byte[2*CHALLANGE_LENGTH];
        System.arraycopy(challenge, 0, outgoing, 0, CHALLANGE_LENGTH);

        for (short i = 0; i < CHALLANGE_LENGTH; i++) {
            outgoing[i] =  (byte) (
                    r[i] ^ outgoing[i]
            );
            outgoing[CHALLANGE_LENGTH+i] = r[i];
        }
        aes.encrypt(
                outgoing, (short) 0, (short) outgoing.length,
                outgoing, (short) 0, (short) outgoing.length
        );
        ResponseAPDU apdu = channel.transmit(new CommandAPDU(outgoing));
        // handle response
        byte[] incoming = apdu.getData();
        aes.decrypt(
                incoming, (short) 0, (short) incoming.length,
                incoming, (short) 0, (short) incoming.length
        );

        if (incoming.length != 2*CHALLANGE_LENGTH) {
            throw new Exception(); // TODO add specific range
        }
        for (short i = 0; i < CHALLANGE_LENGTH; i++) {
            if ( incoming[CHALLANGE_LENGTH+i] != (byte) (challenge[i] ^ r[i]) ) {
                throw new Exception(); // TODO throw something
            }
        }
    }

    private byte[] combine(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

}

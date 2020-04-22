package cz.muni.fi.pv204.host;


import cz.muni.fi.pv204.host.cardTools.Util;
import org.apache.groovy.json.internal.ArrayUtils;
import org.bouncycastle.crypto.CryptoException;
import sun.security.util.ArrayUtil;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.spec.ECPoint;

public class SecureChannel {

    public static final short CHALLANGE_LENGTH = 32;
    public static final int PASS_LEN = 4;

    public static final byte[] INS_R1_ID = Util.hexStringToByteArray("08110000" + "0A");
    public static final byte[] INS_R1_GX = Util.hexStringToByteArray("08120000" + "C3");
    public static final byte[] INS_R1_ZKP1 = Util.hexStringToByteArray("08130000");
    public static final byte[] INS_R1_ZKP2 = Util.hexStringToByteArray("08140000");

    public static final byte[] INS_R2_GX = Util.hexStringToByteArray("08110000");
    public static final byte[] INS_R2_B = Util.hexStringToByteArray("08120000");
    public static final byte[] INS_R2_ZKP1 = Util.hexStringToByteArray("08130000");
    public static final byte[] INS_R2_ZKP2 = Util.hexStringToByteArray("08140000");
    public static final byte[] INS_R2_ZKP3 = Util.hexStringToByteArray("08150000");

    public static final byte[] INS_R3_A = Util.hexStringToByteArray("08310000");
    public static final byte[] INS_R3_ZKP1 = Util.hexStringToByteArray("08320000");

    public static final byte[] INS_HELLO = Util.hexStringToByteArray("08420000");

    public static final int SIZE_ECPOINT = 65;
    public static final byte SIZE_ECPOINT_BYTE = 0x41;
    public static final int SIZE_ID = 10;


    private JCardSymInterface channel;
    private MagicAes aes;
    private SecureRandom rand;
    private Participant participant;
    private byte[] participantIDB = new byte[SIZE_ID];


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
        validationRound2(r);
        r = establishmentRound3();
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

        byte[] outgoing;
        short offset = 0;
        byte[] len = new byte[1];

        outgoing = participantIDA;
        ResponseAPDU response = channel.transmit(
                new CommandAPDU(combine(INS_R1_ID, outgoing))
        );
        checkResponseAccept(response);

        outgoing = new byte[Gx1.length + Gx2.length];
        offset = 0;
        System.arraycopy(
                Gx1, (short) 0,
                outgoing, offset,
                Gx1.length
        );
        offset += Gx1.length; // Gx2
        System.arraycopy(
                Gx2, (short) 0,
                outgoing, offset,
                Gx2.length
        );
        response = channel.transmit(
                new CommandAPDU(combine(INS_R1_GX, outgoing))
        );
        checkResponseAccept(response);

        outgoing = zkp1;
        len[0] = (byte) (
                SIZE_ECPOINT_BYTE +
                        getLSB(round1.getKnowledgeProofForX1().getr().toByteArray().length)
        );
        response = channel.transmit(
                new CommandAPDU(combine(INS_R1_ZKP1, combine(len, outgoing)))
        );
        checkResponseAccept(response);


        outgoing = zkp2;
        len[0] = (byte) (
                SIZE_ECPOINT_BYTE +
                        getLSB(round1.getKnowledgeProofForX1().getr().toByteArray().length)
        );
        response = channel.transmit(
                new CommandAPDU(combine(INS_R1_ZKP2, combine(len, outgoing)))
        );
        checkResponseAccept(response);

        return response;
    }

    private void validationRound2(
            ResponseAPDU response
    ) throws CardException, CryptoException {
        short sizeOfGx = SIZE_ECPOINT;

        byte[] Gx3 = new byte[sizeOfGx];
        byte[] Gx4 = new byte[sizeOfGx];
        byte[] B = new byte[sizeOfGx];
        byte[] zkp1;
        byte[] zkp2;
        byte[] zkp3;

        // Validation
        byte[] incoming;
        short offset;

        incoming = response.getData();
        offset = 0;
        System.arraycopy(
                incoming, offset,
                participantIDB, (short) 0,
                SIZE_ID
        );
        response = channel.transmit(
                new CommandAPDU(INS_R2_GX)
        );
        checkResponseAccept(response);

        incoming = response.getData();
        offset = 0;
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
        response = channel.transmit(
                new CommandAPDU(INS_R2_B)
        );
        checkResponseAccept(response);

        incoming = response.getData();
        offset = 0; // B
        System.arraycopy(
                incoming, offset,
                B, (short) 0,
                SIZE_ECPOINT
        );
        response = channel.transmit(
                new CommandAPDU(INS_R2_ZKP1)
        );
        checkResponseAccept(response);

        incoming = response.getData();
        offset = 0; // ZKP X3
        zkp1 = split(incoming, offset, incoming.length);
        response = channel.transmit(
                new CommandAPDU(INS_R2_ZKP2)
        );
        checkResponseAccept(response);

        incoming = response.getData();
        offset = 0; // ZKP X4
        zkp2 = split(incoming, offset, incoming.length);
        response = channel.transmit(
                new CommandAPDU(INS_R2_ZKP3)
        );
        checkResponseAccept(response);

        incoming = response.getData();
        offset = 0; // ZKP X4s
        zkp3 = split(incoming, offset, incoming.length);


        participant.validateRound2PayloadReceived(
                new Round2Payload(
                        new String(participantIDB),
                        participant.ecCurve.decodePoint(Gx3),
                        participant.ecCurve.decodePoint(Gx4),
                        participant.ecCurve.decodePoint(B),
                        decodeZKP(zkp1, 0, zkp1.length),
                        decodeZKP(zkp2, 0, zkp2.length),
                        decodeZKP(zkp3, 0, zkp3.length)
            )
        );
    }

    private ResponseAPDU establishmentRound3() throws CardException {
        short sizeOfGx = SIZE_ECPOINT;
        byte[] A = new byte[sizeOfGx];
        byte[] zkp1;

        Round3Payload round3 = participant.createRound3PayloadToSend();
        A = round3.getA().getEncoded(false);
        zkp1 = combine(
                round3.getKnowledgeProofForX2s().getV().getEncoded(false),
                round3.getKnowledgeProofForX2s().getr().toByteArray()
        );

        byte[] outgoing;
        short offset ;
        ResponseAPDU response;
        byte[] len = new byte[1];

        outgoing = A;
        response = channel.transmit(
                new CommandAPDU(combine(INS_R3_A, outgoing))
        );
        checkResponseAccept(response);

        outgoing = zkp1;
        len[0] = (byte) (
                SIZE_ECPOINT_BYTE +
                        getLSB(round3.getKnowledgeProofForX2s().getr().toByteArray().length)
        );
        response = channel.transmit(
                new CommandAPDU(combine(INS_R1_ZKP1, combine(len, outgoing)))
        );
        checkResponseAccept(response);

        return response;
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

    private void checkResponseAccept(ResponseAPDU response) {

    }

    private byte getLSB(int length) {
        // only works n positive values
        return (byte) (length & 0xff);
    }

    private byte[] combine(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    private byte[] split(byte[] buffer, int offset, int length) {
        byte[] r = new byte[length];
        System.arraycopy(buffer, offset, r, 0, length);
        return r;
    }

    private SchnorrZKP decodeZKP(byte[] buffer, int offset, int length) {
        byte[] V = new byte[SIZE_ECPOINT];
        byte[] r;
        System.arraycopy(
                buffer, offset,
                V, (short) 0,
                SIZE_ECPOINT
        );
        r = split(buffer, offset+SIZE_ECPOINT, length-SIZE_ECPOINT);
        return new SchnorrZKP(
                participant.ecCurve.decodePoint(V),
                new BigInteger(r)
        );
    }

}

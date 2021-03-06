package cz.muni.fi.pv204.host;


import cz.muni.fi.pv204.host.cardTools.Util;
import javacard.framework.ISO7816;
import org.bouncycastle.crypto.CryptoException;
import sun.plugin.dom.exception.InvalidStateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

public class SecureChannel {

    public static final short CHALLANGE_LENGTH = 32;
    public static final int PASS_LEN = 4;
    public static final short ROUNDS_PER_KEY = 50;


    public static final byte[] INS_R1_ID = Util.hexStringToByteArray("08110000" + "0A");
    public static final byte[] INS_R1_GX = Util.hexStringToByteArray("08120000" + "82");
    public static final byte[] INS_R1_ZKP1 = Util.hexStringToByteArray("08130000");
    public static final byte[] INS_R1_ZKP2 = Util.hexStringToByteArray("08140000");

    public static final byte[] INS_R2_GX = Util.hexStringToByteArray("08210000");
    public static final byte[] INS_R2_B = Util.hexStringToByteArray("08220000");
    public static final byte[] INS_R2_ZKP1 = Util.hexStringToByteArray("08230000");
    public static final byte[] INS_R2_ZKP2 = Util.hexStringToByteArray("08240000");
    public static final byte[] INS_R2_ZKP3 = Util.hexStringToByteArray("08250000");

    public static final byte[] INS_R3_A = Util.hexStringToByteArray("08310000" + "41");
    public static final byte[] INS_R3_ZKP1 = Util.hexStringToByteArray("08320000");

    public static final byte[] INS_HELLO = Util.hexStringToByteArray("08410000");
    public static final byte[] INS_RESET = Util.hexStringToByteArray("08420000");

    public static final int SIZE_ECPOINT = 65;
    public static final byte SIZE_ECPOINT_BYTE = 0x41;
    public static final int SIZE_ID = 10;

    public static final short SW_NO_ERROR = (short) 0x9000;


    public static class ErrorResponseException extends Exception {
        private short errorCode;

        public ErrorResponseException(short errorCode) {
            this.errorCode = errorCode;
        }

        public short getErrorCode() {
            return errorCode;
        }
    }

    public static class ResponseFormatException extends Exception {

        public ResponseFormatException() {
            super();
        }

    }

    public static class IncorrectPasswordException extends Exception {

        public IncorrectPasswordException() {
            super();
        }

    }

    private JCardSymInterface channel;
    private MagicAes aes;
    private SecureRandom rand;
    private Participant participant;
    private byte[] participantIDB = new byte[SIZE_ID];
    private short counter;
    private boolean established;

    public SecureChannel(
            JCardSymInterface channel,
            byte[] participantId,
            char[] password
    ) throws Exception {
        if (participantId.length != SIZE_ID) throw new Exception();
        if (password.length != PASS_LEN) throw new Exception();
        byte[] p = new byte[PASS_LEN];
        for (int i=0; i < PASS_LEN; i++) {
            if (! Character.isDigit(password[i])) throw new Exception();
            p[i] = (byte) (password[i] - '0');
        }

        this.channel = channel;

        rand = SecureRandom.getInstanceStrong();
        aes = new MagicAes();
        participant = new Participant(participantId, p);
        counter = 0;
        established = false;
    }

    public void establishSC() throws CardException, ErrorResponseException,
            CryptoException, ResponseFormatException, BadPaddingException,
            InvalidKeyException, IllegalBlockSizeException, ShortBufferException,
            IncorrectPasswordException, InvalidAlgorithmParameterException,
            DigestException {
        ResponseAPDU r;
        r = establishmentRound1();
        validationRound2(r);
        r = establishmentRound3();
        establishmentHello(r);
        counter = 0;
        established = true;
    }

    public void clear() {
        participant.clear();
    }

    public boolean isEstablished() {
        return established;
    }

    public void reset() throws CardException {
        if (established) {
            channel.transmit(new CommandAPDU(INS_RESET));
        }
    }

    public ResponseAPDU send(byte[] buffer)
            throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException,
            ShortBufferException, InvalidAlgorithmParameterException, DigestException, CardException, InterruptedException {
        if (!established) throw new InvalidStateException("No connection");
        if (counter >= ROUNDS_PER_KEY) {
            established = false;
            throw new InterruptedException("Counter ran out. COnnection closed");
        }
        short l = 0;
        if (buffer.length < 5) {
            aes.nextIV();
            return channel.transmit(new CommandAPDU(buffer));
        } else {
            l = (short) (aes.padding.padLength((short) (buffer.length - ISO7816.OFFSET_CDATA)) + buffer.length);
        }
        if (l > 256) {
            throw new InvalidParameterException();
        }
        byte[] outBuffer = new byte[l];
        System.arraycopy(buffer, 0, outBuffer, 0, buffer.length);
        try {
            aes.padding.pad(
                    outBuffer,
                    (short) ISO7816.OFFSET_CDATA,
                    (short) (buffer.length - ISO7816.OFFSET_CDATA),
                    (short) (outBuffer.length - ISO7816.OFFSET_CDATA)
            );
        } catch (Exception e) { }
        l = (short) aes.encrypt(
                outBuffer, (short) ISO7816.OFFSET_CDATA, (short) (outBuffer.length - ISO7816.OFFSET_CDATA),
                outBuffer, (short) ISO7816.OFFSET_CDATA, (short) (outBuffer.length - ISO7816.OFFSET_CDATA)
        );
        outBuffer[ISO7816.OFFSET_LC] = getLSB(l);
        if (l > 255) {
            outBuffer[ISO7816.OFFSET_LC] = 0x00;
        }
        counter++;
        ResponseAPDU response = channel.transmit(new CommandAPDU(outBuffer));
        Arrays.fill(buffer, (byte) 0x00);
        return  response;
    }

    public short decryptDataBuffer(byte[] buffer) throws
            InvalidAlgorithmParameterException, ShortBufferException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, DigestException {
        if (buffer.length == 0) {
            aes.nextIV();
            return  0;
        }
        aes.decrypt(
                buffer, (short) 0, (short) buffer.length,
                buffer, (short) 0, (short) buffer.length
        );
        return aes.padding.unpad(buffer, (short) 0, (short) buffer.length);
    }

    private ResponseAPDU establishmentRound1(
    ) throws CardException, ErrorResponseException {

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
        byte[] participantIDA = round1.getParticipantId();
        byte[] b = round1.getKnowledgeProofForX2().getr().toByteArray();

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
        len[0] = (byte) (getLSB(outgoing.length)
        );
        response = channel.transmit(
                new CommandAPDU(combine(INS_R1_ZKP1, combine(len, outgoing)))
        );
        checkResponseAccept(response);


        outgoing = zkp2;
        len[0] = (byte) (getLSB(outgoing.length)
        );
        response = channel.transmit(
                new CommandAPDU(combine(INS_R1_ZKP2, combine(len, outgoing)))
        );
        checkResponseAccept(response);

        return response;
    }


    private void validationRound2(
            ResponseAPDU response
    ) throws CardException, CryptoException, ErrorResponseException,
            ResponseFormatException {
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

        checkResponseLength(response, SIZE_ID, SIZE_ID);

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

        checkResponseLength(response, 2*SIZE_ECPOINT, 2*SIZE_ECPOINT);
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

        checkResponseLength(response, SIZE_ECPOINT, SIZE_ECPOINT);
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

        checkResponseLength(response, SIZE_ECPOINT+1, 255);
        incoming = response.getData();
        offset = 0; // ZKP X3
        zkp1 = split(incoming, offset, incoming.length);
        response = channel.transmit(
                new CommandAPDU(INS_R2_ZKP2)
        );
        checkResponseAccept(response);

        checkResponseLength(response, SIZE_ECPOINT+1, 255);
        incoming = response.getData();
        offset = 0; // ZKP X4
        zkp2 = split(incoming, offset, incoming.length);
        response = channel.transmit(
                new CommandAPDU(INS_R2_ZKP3)
        );
        checkResponseAccept(response);

        checkResponseLength(response, SIZE_ECPOINT+1, 255);
        incoming = response.getData();
        offset = 0; // ZKP X4s
        zkp3 = split(incoming, offset, incoming.length);

        participant.validateRound2PayloadReceived(
                new Round2Payload(
                        participantIDB,
                        participant.ecCurve.decodePoint(Gx3),
                        participant.ecCurve.decodePoint(Gx4),
                        participant.ecCurve.decodePoint(B),
                        decodeZKP(zkp1, 0, zkp1.length),
                        decodeZKP(zkp2, 0, zkp2.length),
                        decodeZKP(zkp3, 0, zkp3.length)
            )
        );
    }

    private ResponseAPDU establishmentRound3(
    ) throws CardException, ErrorResponseException {
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
        len[0] = (byte) (getLSB(outgoing.length));
        response = channel.transmit(
                new CommandAPDU(combine(INS_R3_ZKP1, combine(len, outgoing)))
        );
        checkResponseAccept(response);

        return response;
    }

    private void establishmentHello(
            ResponseAPDU response
    ) throws ResponseFormatException, CardException, ErrorResponseException,
            IncorrectPasswordException, InvalidAlgorithmParameterException,
            ShortBufferException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, DigestException {
        byte[] challenge = response.getData();

        checkResponseLength(response, CHALLANGE_LENGTH, CHALLANGE_LENGTH);
        aes.generateKey(participant.calculateKeyingMaterial().getEncoded(false), challenge);

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
        byte[] len = {(byte) (CHALLANGE_LENGTH*2)};
        response = channel.transmit(new CommandAPDU(combine(INS_HELLO, combine(len, outgoing))));
        checkResponseAccept(response);
        checkResponseLength(response, 2*CHALLANGE_LENGTH, 2*CHALLANGE_LENGTH);
        // handle response
        byte[] incoming = response.getData();
        aes.decrypt(
                incoming, (short) 0, (short) incoming.length,
                incoming, (short) 0, (short) incoming.length
        );

        for (short i = 0; i < CHALLANGE_LENGTH; i++) {
            if ( incoming[CHALLANGE_LENGTH+i] != (byte) (challenge[i] ^ incoming[i]) ) {
                throw new IncorrectPasswordException();
            }
        }
    }

    private void checkResponseAccept(ResponseAPDU response) throws ErrorResponseException {
        if ((short) response.getSW() != SW_NO_ERROR ) {
            throw new ErrorResponseException((short) response.getSW());
        }
    }

    private ResponseAPDU checkResponseLength(
            ResponseAPDU response,
            int lower,
            int upper
    ) throws ResponseFormatException {
        int l = response.getData().length;
        if (lower > l || l > upper) {
            throw new ResponseFormatException();
        }
        return response;
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

package cz.muni.fi.pv204.javacard;

import cz.muni.fi.pv204.javacard.crypto.MagicAes;
import cz.muni.fi.pv204.javacard.crypto.PKCS5Padding;
import cz.muni.fi.pv204.javacard.jpake.JPake;
import cz.muni.fi.pv204.javacard.jpake.JPakeECParam;
import cz.muni.fi.pv204.javacard.jpake.JPakePassword;
import javacard.framework.*;
import javacard.security.RandomData;

import java.math.BigInteger;
import java.security.InvalidParameterException;


public class SecureChannel {

    public static final short PIN_SIZE = 4;
    public static final short PIN_TRIES = 3;
    public static final short ROUNDS_PER_KEY = 50;

    public static final short SIZE_CHALLENGE = 32; // sha 256 - 128 for AES IV
    public static final short SIZE_ID = 10;
    public static final short SIZE_EC_POINT = 65;

    public static final byte ROUND_1_ID = 0x11;
    public static final byte ROUND_1_GX = 0x12;
    public static final byte ROUND_1_ZKP1 = 0x13;
    public static final byte ROUND_1_ZKP2 = 0x14;

    public static final byte ROUND_2_GX = 0x21;
    public static final byte ROUND_2_B = 0x22;
    public static final byte ROUND_2_ZKP1 = 0x23;
    public static final byte ROUND_2_ZKP2 = 0x24;
    public static final byte ROUND_2_ZKP3 = 0x25;

    public static final byte ROUND_3_A = 0x31;
    public static final byte ROUND_3_ZKP1 = 0x32;

    public static final byte ROUND_HELLO = 0x41;
    public static final byte ESTABLISHED = 0x42; // COmmand reset

    private static SecureChannel sc;
    private JPakePassword pin;
    private JPake jpake;
    private MagicAes aes;
    private RandomData rand;
    private PKCS5Padding padding;

    private byte[] myID;
    private byte[] state;

    private byte[] Gx1;
    private byte[] Gx2;
    private byte[] Gx3;
    private byte[] Gx4;
    private byte[] A;
    private byte[] B;
    private byte[] zkp1_v;
    private BigInteger zkp1_r;
    private byte[] zkp2_v;
    private BigInteger zkp2_r;
    private byte[] zkp3_v;
    private BigInteger zkp3_r;
    private byte[] participantIDA;
    private byte[] challenge;

    private short counter;

    public static class UnexpectedError extends Exception {
        public UnexpectedError() {
            super();
        }
    }

    private SecureChannel() {
        rand = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        state = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        state[0] = 0x00;
        pin = new JPakePassword((byte) PIN_TRIES , (byte) PIN_SIZE);
        JPakeECParam param = new JPakeECParam();
        myID = new byte[SIZE_ID];
        rand.nextBytes(myID, (short) 0, SIZE_ID);
        jpake = new JPake(myID, pin, param);
        aes = new MagicAes();
        padding = new PKCS5Padding((short) 16);

        Gx1 = new byte[SIZE_EC_POINT];
        Gx2 = new byte[SIZE_EC_POINT];
        Gx3 = new byte[SIZE_EC_POINT];
        Gx4 = new byte[SIZE_EC_POINT];
        A = new byte[SIZE_EC_POINT];
        B = new byte[SIZE_EC_POINT];
        zkp1_v = new byte[SIZE_EC_POINT];
        zkp2_v = new byte[SIZE_EC_POINT];
        zkp3_v = new byte[SIZE_EC_POINT];
        participantIDA = new byte[SIZE_ID];
        challenge = new byte[SIZE_CHALLENGE];

        counter = 0;
    }

    public static SecureChannel getSecureChannel() {
        if (sc == null) {
            sc = new SecureChannel();
        }
        return sc;
    }

    public void setPin(byte[] newPin, short offset, byte length) throws UnexpectedError {
        if (length != PIN_SIZE) {
            throw new UnexpectedError();
        }
        if (pin == null) {
            pin = new JPakePassword((byte) PIN_TRIES , (byte) PIN_SIZE);
        }
        pin.update(newPin, offset, length);
    }


    public boolean isEstablished() {
        return state[0] == ESTABLISHED;
    }

    public short processIncoming(
            APDU apdu
            ) throws UnexpectedError {

        byte[] inBuffer = apdu.getBuffer();
        short inOffset = ISO7816.OFFSET_CDATA;
        short inLen = apdu.getIncomingLength();
        byte[] outBuffer = inBuffer;
        short outOffset = inOffset;
        short outLen = 256;

        short size;
        byte command = inBuffer[ISO7816.OFFSET_INS];
        switch (command) {
            case ROUND_1_ID:
                checkPinSTate();
                checkLength(inLen, SIZE_ID, SIZE_ID);
                pin.decrement();
                state[0] = ROUND_1_GX;
                parseIDA(inBuffer, inOffset, inLen);
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_1_GX:
                checkLength(inLen, (short) (2*SIZE_EC_POINT), (short) (2*SIZE_EC_POINT));
                checkState(command);
                parseECPoint(inBuffer, inOffset, inLen, Gx1);
                parseECPoint(inBuffer, (short)(inOffset+SIZE_EC_POINT), (short)(inLen-SIZE_EC_POINT), Gx2);
                state[0] = ROUND_1_ZKP1;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_1_ZKP1:
                checkLength(inLen, (short) (1+SIZE_EC_POINT), (short)255);
                checkState(command);
                parseZKP(inBuffer, inOffset, inLen, (short) 1);
                state[0] = ROUND_1_ZKP2;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_1_ZKP2:
                checkLength(inLen, (short) (1+SIZE_EC_POINT), (short)255);
                checkState(command);
                parseZKP(inBuffer, inOffset, inLen, (short) 2);
                validateRound1();
                generateRound2();
                size = encodeIDB(outBuffer, outOffset, outLen);
                state[0] = ROUND_2_GX; // Response should contain participant ID
                sendSuccess(apdu, outOffset, size);
                break;
            case ROUND_2_GX:
                checkState(command);
                size = encodeECPoint(outBuffer, outOffset, outLen, Gx3);
                size += encodeECPoint(outBuffer, (short)(outOffset+SIZE_EC_POINT), outLen, Gx4);
                state[0] = ROUND_2_B;
                sendSuccess(apdu, outOffset, size);
                break;
            case ROUND_2_B:
                checkState(command);
                size = encodeECPoint(outBuffer, outOffset, outLen, B);
                state[0] = ROUND_2_ZKP1;
                sendSuccess(apdu, outOffset, size);
                break;
            case ROUND_2_ZKP1:
                checkState(command);
                size = encodeZKP(outBuffer, outOffset, outLen, zkp1_v, zkp1_r);
                state[0] = ROUND_2_ZKP2;
                sendSuccess(apdu, outOffset, size);
                break;
            case ROUND_2_ZKP2:
                checkState(command);
                size = encodeZKP(outBuffer, outOffset, outLen, zkp2_v, zkp2_r);
                state[0] = ROUND_2_ZKP3;
                sendSuccess(apdu, outOffset, size);
                break;
            case ROUND_2_ZKP3:
                checkState(command);
                size = encodeZKP(outBuffer, outOffset, outLen, zkp3_v, zkp3_r);
                state[0] = ROUND_3_A;
                sendSuccess(apdu, outOffset, size);
                break;
            case ROUND_3_A:
                checkLength(inLen, SIZE_EC_POINT, SIZE_EC_POINT);
                checkState(command);
                parseECPoint(inBuffer, inOffset, inLen, A);
                state[0] = ROUND_3_ZKP1;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_3_ZKP1:
                checkLength(inLen, (short) (1+SIZE_EC_POINT), (short)255);
                checkState(command);
                parseZKP(inBuffer, inOffset, inLen, (short) 1);
                validateRound3();
                prepareForHello(outBuffer, outOffset, outLen);
                state[0] = ROUND_HELLO;
                sendSuccess(apdu, outOffset, (short) (SIZE_CHALLENGE));
                break;
            case ESTABLISHED: // RESET
                state[0] = 0x00;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_HELLO:
                checkLength(inLen, (short) (SIZE_CHALLENGE*2), (short) (SIZE_CHALLENGE*2));
                checkState(command);
                inLen = unCheckedUnwrap(
                        inBuffer, inOffset, inLen,
                        inBuffer, inOffset, inLen
                );
                establishmentHello(
                        inBuffer, inOffset, inLen,
                        outBuffer, outOffset, outLen
                );
                state[0] = ESTABLISHED;
                unCheckedWrap(outBuffer, outOffset, (short)(2* SIZE_CHALLENGE), outBuffer, outOffset, outLen);
                pin.correct();
                counter = 0;
                sendSuccess(apdu, outOffset, (short) (2* SIZE_CHALLENGE));
                break;
            default:
                checkState(ESTABLISHED);
                if (counter >= ROUNDS_PER_KEY ) ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                counter++;
                if (inLen == 0) {
                    aes.nextIV();
                    return 0;
                }
                outLen = unwrap(
                        inBuffer, inOffset, inLen,
                        outBuffer, outOffset, outLen
                );
                short off = padding.unpad(outBuffer, outOffset, outLen);
                return (short)(off - outOffset);
        }
        return (short) 0;
    }

    public short wrap(
            byte[] inBuffer,
            short inOffset,
            short inLen,
            short totalLen
    ) {
        checkState(ESTABLISHED);

        short l;
        if (inLen < 1) {
            aes.nextIV();
            return (short)0;
        } else {
            l = (short) (padding.padLength(inLen) + inLen);
        }
        if (l > 256 || l > totalLen) {
            return -1;
        }
        padding.pad(
                inBuffer,
                inOffset,
                inLen,
                totalLen
        );
        return unCheckedWrap(
                inBuffer, inOffset, l,
                inBuffer, inOffset, totalLen
        );
    }

    private short unwrap(
            byte[] inBuffer,
            short inOffset,
            short inLen,
            byte[] outBuffer,
            short outOffset,
            short outLen
    ) {
        checkState(ESTABLISHED);
        if (inLen % 16 != 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return unCheckedUnwrap(
                inBuffer, inOffset, inLen,
                outBuffer, outOffset, outLen
        );
    }

    private short unCheckedWrap(
            byte[] inBuffer,
            short inOffset,
            short inLen,
            byte[] outBuffer,
            short outOffset,
            short outLen
    ) {
        return aes.encrypt(
                inBuffer, inOffset, inLen,
                outBuffer, outOffset, outLen
        );
    }

    private short unCheckedUnwrap(
            byte[] inBuffer,
            short inOffset,
            short inLen,
            byte[] outBuffer,
            short outOffset,
            short outLen
    ) {
        return aes.decrypt(
                inBuffer, inOffset, inLen,
                outBuffer, outOffset, outLen
        );
    }

    private void sendSuccess(APDU apdu, short offset, short len) {
        apdu.setOutgoingAndSend(offset, len);
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    private void parseIDA(
            byte[] incoming, short incomingOffset, short incomingLength
    ) {
        Util.arrayCopy(
                incoming, incomingOffset,
                participantIDA, (short) 0,
                SIZE_ID
        );
    }

    private short encodeIDB(
            byte[] outgoing, short outgoingOffset, short outgoingLength
    ) {
        Util.arrayCopy(
                myID, (short) 0,
                outgoing, outgoingOffset,
                SIZE_ID
        );
        return SIZE_ID;
    }

    private void parseECPoint(
            byte[] incoming, short incomingOffset, short incomingLength, byte[] dst
    ) {
        Util.arrayCopy(
                incoming, incomingOffset,
                dst, (short) 0,
                SIZE_EC_POINT
        );
    }

    private short encodeECPoint(
            byte[] outgoing, short outgoingOffset, short outgoingLength, byte[] src
    ) {
        Util.arrayCopy(
                src, (short) 0,
                outgoing, outgoingOffset,
                SIZE_EC_POINT
        );
        return SIZE_EC_POINT;
    }

    private void parseZKP(
            byte[] incoming, short incomingOffset, short incomingLength, short t
    ) throws UnexpectedError {
        byte[] target;
        switch (t) {
            case 1:
                target = zkp1_v;
                break;
            case 2:
                target = zkp2_v;
                break;
            case 3:
                target = zkp3_v;
                break;
            default:
                throw new UnexpectedError();
        }
        Util.arrayCopy(
                incoming, incomingOffset,
                target, (short) 0,
                SIZE_EC_POINT
        );
        short l = (short) (incomingLength-SIZE_EC_POINT);
        byte[] tmp = new byte[l];
        Util.arrayCopy(
                incoming, (short) (incomingOffset+SIZE_EC_POINT),
                tmp, (short) 0,
                (short) (l)
        );
        BigInteger tmpBigInteger = new BigInteger(tmp);
        switch (t) {
            case 1:
                zkp1_r = tmpBigInteger;
                break;
            case 2:
                zkp2_r = tmpBigInteger;
                break;
            case 3:
                zkp3_r = tmpBigInteger;
                break;

        }
    }

    private short encodeZKP(
            byte[] outgoing, short outgoingOffset, short outgoingLength,
            byte[] zkp_V, BigInteger zkp_r
    ) {
        Util.arrayCopy(
                zkp_V, (short) 0,
                outgoing, outgoingOffset,
                SIZE_EC_POINT
        );
        byte[] tmp = zkp_r.toByteArray();
        short l = (short) tmp.length;
        if (l > outgoingLength - SIZE_EC_POINT) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        Util.arrayCopy(
                tmp, (short) 0,
                outgoing, (short)(outgoingOffset+SIZE_EC_POINT),
                l
        );
        return (short) (SIZE_EC_POINT+l);
    }

    private void validateRound1() {
        if (!jpake.validateRound1PayloadReceived(
                Gx1, Gx2,
                zkp1_v, zkp1_r,
                zkp2_v, zkp2_r,
                participantIDA
        )) {
            state[0] = 0x00;
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void generateRound2() {
        zkp1_r = new BigInteger("0");
        zkp2_r = new BigInteger("0");
        zkp3_r = new BigInteger("0");
        BigInteger[] r = jpake.createRound2PayloadToSend(
                Gx3, Gx4, B,
                zkp1_v, zkp1_r,
                zkp2_v, zkp2_r,
                zkp3_v, zkp3_r,
                myID
        );
        zkp1_r = r[0];
        zkp2_r = r[1];
        zkp3_r = r[2];
    }

    private void validateRound3() {
        if (!jpake.validateRound3PayloadReceived(
                A,
                zkp1_v, zkp1_r,
                participantIDA
        )) {
            state[0] = 0x00;
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private short prepareForHello(
            byte[] outgoing, short outgoingOffset, short outgoingLength
    ) throws UnexpectedError {
        if (outgoingLength < SIZE_CHALLENGE) {
            throw new UnexpectedError(); // TODO
        }
        rand.nextBytes(challenge, (short) 0, SIZE_CHALLENGE);

        byte[] keyingMaterial = jpake.calculateKeyingMaterial();
        aes.generateKey(
                keyingMaterial,
                challenge
        );
        // Outgoing
        Util.arrayCopy(
                challenge, (short) 0,
                outgoing, outgoingOffset,
                SIZE_CHALLENGE
        );
        return SIZE_CHALLENGE;
    }

    private void establishmentHello(
            byte[] incoming, short incomingOffset, short incomingLength,
            byte[] outgoing, short outgoingOffset, short outgoingLength
    ) {
        for (short i = 0; i < SIZE_CHALLENGE; i++) {
            if ( incoming[incomingOffset+ SIZE_CHALLENGE +i] != (byte) (
                    challenge[i] ^ incoming[incomingOffset+i]
            ) ) {
                state[0] = 0x00;
                ISOException.throwIt(ISO7816.SW_DATA_INVALID); // TODO throw something
            }
        }
        rand.nextBytes(outgoing, SIZE_CHALLENGE, SIZE_CHALLENGE);
        for (short i = 0; i < SIZE_CHALLENGE; i++) {
            outgoing[outgoingOffset + i] =  (byte) (
                    challenge[i] ^ outgoing[outgoingOffset + SIZE_CHALLENGE + i]
            );
        }
    }

    private void checkPinSTate() {
        if (pin.getTriesRemaining() == 0x00) {
            state[0] = 0x00;
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void checkLength(short inLen, short lower, short upper) {
        if (lower > inLen || inLen > upper) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }

    private void checkState(byte expected) {
        checkPinSTate();
        if (state[0] != expected) {
            state[0] = 0x00;
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
    }



}

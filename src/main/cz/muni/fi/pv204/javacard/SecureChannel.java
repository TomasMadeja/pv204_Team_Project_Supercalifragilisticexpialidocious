package cz.muni.fi.pv204.javacard;

import cz.muni.fi.pv204.javacard.crypto.MagicAes;
import cz.muni.fi.pv204.javacard.jpake.JPake;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

import cz.muni.fi.pv204.javacard.crypto.NIZKP;
import cz.muni.fi.pv204.javacard.jpake.JPakePassword;
import javacard.security.RandomData;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.math.BigInteger;


public class SecureChannel {

    public static final short challengeLength = 32; // sha 256 - 128 for AES IV
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
    public static final byte ESTABLISHED = 0x42;

    private static SecureChannel sc = null;
    private static JPakePassword pin = null;
    private JPake jpake;
    private MagicAes aes;
    private RandomData rand;

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
    private byte[] zkp2;
    private byte[] zkp3;
    private byte[] participantIDA;
    private byte[] participantIDB;
    private byte[] keyingMaterial;
    private byte[] challenge;

    private SecureChannel() {
//        throw new NotImplementedException();
        rand = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        state = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    }

    public static SecureChannel getSecureChannel() {
        if (sc == null) {
            sc = new SecureChannel();
        }
        return sc;
    }

    public static void setPin(byte[] newPin, short offset, byte length) {
        if (pin == null) {
            pin = new JPakePassword((byte) 3, (byte) 4, new NIZKP());
        }
        pin.update(newPin, offset, length);
    }


    public boolean isEstablished() {
        return state[0] == ESTABLISHED;
    }

    public short processIncoming(
            byte command,
            byte[] inBuffer,
            short inOffset,
            short inLen,
            byte[] outBuffer,
            short outOffset,
            short outLen
            ) throws Exception {

        switch (command) {
            case ROUND_1_ID:
                // TODO do something
                state[0] = ROUND_1_GX;
                parseIDA(inBuffer, inOffset, inLen);
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_1_GX:
                // TODO throw something
                if (state[0] != command) throw new NotImplementedException();
                parseECPoint(inBuffer, inOffset, inLen, Gx1);
                parseECPoint(inBuffer, (short)(inOffset+SIZE_EC_POINT), (short)(inLen-SIZE_EC_POINT), Gx2);
                state[0] = ROUND_1_ZKP1;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_1_ZKP1:
                // TODO throw something
                if (state[0] != command) throw new NotImplementedException();
                parseZKP(inBuffer, inOffset, inLen, (short) 1);
                state[0] = ROUND_1_ZKP2;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_1_ZKP2:
                // TODO throw something
                if (state[0] != command) throw new NotImplementedException();
                parseZKP(inBuffer, inOffset, inLen, (short) 2);
                state[0] = ROUND_2_GX; // Response should contain participant ID
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_2_GX:
                // TODO throw something
                if (state[0] != command) throw new NotImplementedException();
                // TODO do something
                state[0] = ROUND_2_B;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_2_B:
                // TODO throw something
                if (state[0] != command) throw new NotImplementedException();
                // TODO do something
                state[0] = ROUND_2_ZKP1;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_2_ZKP1:
                // TODO throw something
                if (state[0] != command) throw new NotImplementedException();
                // TODO do something
                state[0] = ROUND_2_ZKP2;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_2_ZKP2:
                // TODO throw something
                if (state[0] != command) throw new NotImplementedException();
                // TODO do something
                state[0] = ROUND_2_ZKP3;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_2_ZKP3:
                // TODO throw something
                if (state[0] != command) throw new NotImplementedException();
                // TODO do something
                state[0] = ROUND_3_A;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_3_A:
                // TODO throw something
                if (state[0] != command) throw new NotImplementedException();
                parseECPoint(inBuffer, inOffset, inLen, A);
                state[0] = ROUND_3_ZKP1;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_3_ZKP1:
                // TODO throw something
                if (state[0] != command) throw new NotImplementedException();
                parseZKP(inBuffer, inOffset, inLen, (short) 1);
                state[0] = ROUND_HELLO;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case ROUND_HELLO:
                if (state[0] != command) throw new NotImplementedException(); // TODO
                inLen = unwrap(
                        inBuffer, inOffset, inLen,
                        inBuffer, inOffset, inLen
                );
                establishmentHello(
                        inBuffer, inOffset, inLen,
                        outBuffer, outOffset, outLen
                );
                state[0] = ESTABLISHED;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            default:
                if (state[0] != ESTABLISHED) throw new NotImplementedException(); // TODO
                return unwrap(
                        inBuffer, inOffset, inLen,
                        outBuffer, outOffset, outLen
                );
        }

        return (short) 0;
    }

    public short wrap(
            byte[] inBuffer,
            short inOffset,
            short inLen,
            byte[] outBuffer,
            short outOffset,
            short outLen
    ) {
        if (state[0] != ESTABLISHED) {
            throw new NotImplementedException(); // TODO
        }
        return aes.encrypt(
                inBuffer, inOffset, inLen,
                outBuffer, outOffset, outLen
        );
    }

    public short unwrap(
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
                participantIDB, (short) 0,
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
    ) throws Exception {
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
                throw new Exception();
        }
        Util.arrayCopy(
                incoming, incomingOffset,
                target, (short) 0,
                SIZE_EC_POINT
        );
        byte[] tmp = new byte[incomingLength-SIZE_EC_POINT];
        Util.arrayCopy(
                incoming, (short) (incomingOffset+SIZE_EC_POINT),
                zkp1_v, (short) 0,
                (short) (incomingLength-SIZE_EC_POINT)
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
        jpake.validateRound1PayloadReceived(
                Gx1, Gx2,
                zkp1_v, zkp1_r,
                zkp2_v, zkp2_r,
                participantIDA
        );
    }

    private void generateRound2() {
        zkp1_r = new BigInteger("0");
        zkp2_r = new BigInteger("0");
        zkp3_r = new BigInteger("0");
        jpake.createRound2PayloadToSend(
                Gx3, Gx4, B,
                zkp1_v, zkp1_r,
                zkp2_v, zkp2_r,
                zkp3_v, zkp3_r,
                participantIDB
        );
    }

    private void validateRound3() {
        jpake.validateRound3PayloadReceived(
                B,
                zkp1_v, zkp1_r,
                participantIDA
        );
    }



    private void establishmentHello(
            byte[] incoming, short incomingOffset, short incomingLength,
            byte[] outgoing, short outgoingOffset, short outgoingLength
    ) {
        if (incomingLength != 2*challengeLength || outgoingLength != challengeLength) {
            throw new NotImplementedException(); // TODO throw something
        }

        for (short i = 0; i < challengeLength; i++) {
            if ( incoming[incomingOffset+challengeLength+i] != (byte) (
                    challenge[i] ^ incoming[incomingOffset+i]
            ) ) {
                throw new NotImplementedException(); // TODO throw something
            }
        }
        rand.nextBytes(outgoing, challengeLength, challengeLength);
        for (short i = 0; i < challengeLength; i++) {
            outgoing[outgoingOffset + i] =  (byte) (
                    challenge[i] ^ outgoing[outgoingOffset + challengeLength + i]
            );
        }
    }



}

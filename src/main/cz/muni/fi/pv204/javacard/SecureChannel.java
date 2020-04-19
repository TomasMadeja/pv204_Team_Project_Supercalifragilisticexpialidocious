package cz.muni.fi.pv204.javacard;

import cz.muni.fi.pv204.javacard.crypto.MagicAes;
import cz.muni.fi.pv204.javacard.jpake.JPake;
import javacard.framework.JCSystem;
import javacard.framework.Util;

import cz.muni.fi.pv204.javacard.crypto.NIZKP;
import cz.muni.fi.pv204.javacard.jpake.JPakePassword;
import javacard.security.RandomData;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class SecureChannel {

    public static final short challengeLength = 6;

    public static final byte ROUND_1 = 0x01;
    public static final byte ROUND_3 = 0x02;
    public static final byte ROUND_HELLO = 0x03;
    public static final byte ESTABLISHED = 0x04;

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
    private byte[] zkp1;
    private byte[] zkp2;
    private byte[] zkp3;
    private byte[] participantIDA;
    private byte[] participantIDB;
    private byte[] keyingMaterial;
    private byte[] challange;

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

    public static boolean check(byte[] inPin, short offset, byte length) {
        return pin.check(inPin, offset, length);
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
            ) {

        switch (command) {
            case ROUND_1:
                establishmentRound2(
                        inBuffer, inOffset, inLen,
                        outBuffer, outOffset, outLen
                );
                state[0] = ROUND_3;
                break;
            case ROUND_3:
                if (state[0] != command) throw new NotImplementedException(); // TODO
                establishmentChallenge(
                        inBuffer, inOffset, inLen,
                        outBuffer, outOffset, outLen
                );
                state[0] = ROUND_HELLO;
                break;
            case ROUND_HELLO:
                if (state[0] != command) throw new NotImplementedException(); // TODO
                establishmentHello(
                        inBuffer, inOffset, inLen,
                        outBuffer, outOffset, outLen
                );
                state[0] = ESTABLISHED;
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

    private void establishmentRound2(
            byte[] incoming, short incomingOffset, short incomingLength,
            byte[] outgoing, short outgoingOffset, short outgoingLength
    ) {
        if (incomingLength != (short) (
                2*jpake.sizeOfGx + 2*jpake.sizeOfZKP + jpake.sizeOfID
        )) {
            throw new NotImplementedException();
        }
        else if (outgoingLength != (short) (
                2*jpake.sizeOfGx + jpake.sizeOfAB + 3*jpake.sizeOfZKP + jpake.sizeOfID
        )) {
            throw new NotImplementedException();
        }
        // Incoming Round 1, outgoing Round 2
        // Incoming
        short offset = incomingOffset; // Gx1
        Util.arrayCopy(
                incoming, offset,
                Gx1, (short) 0,
                jpake.sizeOfGx
        );
        offset += jpake.sizeOfGx; // Gx2
        Util.arrayCopy(
                incoming, offset,
                Gx2, (short) 0,
                jpake.sizeOfGx
        );
        offset += jpake.sizeOfGx; // ZKP x1
        Util.arrayCopy(
                incoming, offset,
                zkp1, (short) 0,
                jpake.sizeOfZKP
        );
        offset += jpake.sizeOfZKP; // ZKP x2
        Util.arrayCopy(
                incoming, offset,
                zkp2, (short) 0,
                jpake.sizeOfZKP
        );
        offset += jpake.sizeOfZKP; // ID
        Util.arrayCopy(
                incoming, offset,
                participantIDA, (short) 0,
                jpake.sizeOfID
        );
        // Validate and Build round 2
        jpake.validateRound1PayloadReceived(Gx1, Gx2, zkp1, zkp2, participantIDA);
        jpake.createRound2PayloadToSend(Gx3, Gx4, B, zkp1, zkp2, zkp3, participantIDB);
        // Outgoing
        offset = outgoingOffset; // Gx3
        Util.arrayCopy(
                Gx3, (short) 0,
                outgoing, offset,
                jpake.sizeOfGx
        );
        offset += jpake.sizeOfGx; // Gx2
        Util.arrayCopy(
                Gx4, (short) 0,
                outgoing, offset,
                jpake.sizeOfGx
        );
        offset += jpake.sizeOfGx; // B
        Util.arrayCopy(
                B, (short) 0,
                outgoing, offset,
                jpake.sizeOfAB
        );
        offset += jpake.sizeOfAB; // ZKP X3
        Util.arrayCopy(
                zkp1, (short) 0,
                outgoing, offset,
                jpake.sizeOfZKP
        );
        offset += jpake.sizeOfZKP; // ZKP X4
        Util.arrayCopy(
                zkp2, (short) 0,
                outgoing, offset,
                jpake.sizeOfZKP
        );
        offset += jpake.sizeOfZKP; // ZKP X4s
        Util.arrayCopy(
                zkp3, (short) 0,
                outgoing, offset,
                jpake.sizeOfZKP
        );
        offset += jpake.sizeOfZKP; // ID
        Util.arrayCopy(
                participantIDB, (short) 0,
                outgoing, offset,
                jpake.sizeOfID
        );
    }

    private void establishmentChallenge(
            byte[] incoming, short incomingOffset, short incomingLength,
            byte[] outgoing, short outgoingOffset, short outgoingLength
    ) {
        // Incoming Round 3, outgoing random challange
        if (incomingLength != (short) (
                jpake.sizeOfAB + jpake.sizeOfZKP + jpake.sizeOfID
        )) {
            throw new NotImplementedException();
        }
        else if (outgoingLength != (short) (
                2*jpake.sizeOfGx + jpake.sizeOfAB + 3*jpake.sizeOfZKP + jpake.sizeOfID
        )) {
            throw new NotImplementedException();
        }
        // TODO compare IDs between rounds
        // Incoming Round 3, outgoing challange
        // Incoming
        short offset = incomingOffset; // A
        Util.arrayCopy(
                incoming, offset,
                A, (short) 0,
                jpake.sizeOfAB
        );
        offset += jpake.sizeOfAB; // ZKP X2s
        Util.arrayCopy(
                incoming, offset,
                zkp1, (short) 0,
                jpake.sizeOfZKP
        );
        offset += jpake.sizeOfZKP; // ID
        Util.arrayCopy(
                incoming, offset,
                participantIDA, (short) 0,
                jpake.sizeOfID
        );
        // Validate and Build round 2
        jpake.validateRound3PayloadReceived(A, zkp1, participantIDA);
        jpake.calculateKeyingMaterial(keyingMaterial);
        aes.generateKey(keyingMaterial);
        // Outgoing
        rand.nextBytes(challange, (short) 0, challengeLength);
        Util.arrayCopy(
                challange, (short) 0,
                outgoing, outgoingOffset,
                challengeLength
        );
    }

    private void establishmentHello(
            byte[] incoming, short incomingOffset, short incomingLength,
            byte[] outgoing, short outgoingOffset, short outgoingLength
    ) {
        if (incomingLength != 2*challengeLength || outgoingLength != challengeLength) {
            throw new NotImplementedException(); // TODO throw something
        }
        // Incoming hmaced hello, outgoing hmaced hello
        for (short i = 0; i < challengeLength; i++) {
            if ( challange[i] != (byte) (challange[i] ^ incoming[incomingOffset+i]) ) {
                throw new NotImplementedException(); // TODO throw something
            }
        }
        for (short i = 0; i < challengeLength; i++) {
            outgoing[outgoingOffset + i] =  (byte) (
                    challange[i] ^ outgoing[outgoingOffset + challengeLength + i]
            );
        }
    }



}

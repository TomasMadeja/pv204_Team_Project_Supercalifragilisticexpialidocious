package cz.muni.fi.pv204.javacard;

import javacard.framework.*;
import javacard.security.RandomData;

// Delete me when done implementing

public class SCApplet extends Applet {

    private static final byte INS_HELLO = (byte) 0xF1;
    private static final byte INS_ECHO = (byte) 0xF2;
    private static final byte INS_RAND = (byte) 0xF3;

    private SecureChannel sc;
    private RandomData rand;


    private SCApplet(byte[] bArray, short bOffset, byte bLength) {
        // offset + [PIN_LENGTH | PIN] + [MORE_DATA]
        sc = SecureChannel.getSecureChannel();
        rand = RandomData.getInstance(RandomData.ALG_TRNG);
        try {
            for (short i=(short)(bOffset+1); i < bArray[bOffset]; i++) {
                if (i > 0x09 || i < 0x00) {
                    throw new RuntimeException();
                }
            }
            if (bArray[bOffset] != 4) {
                throw new RuntimeException();
            }

            sc.setPin(
                    bArray,
                    (short) (bOffset + 1),
                    bArray[bOffset]
            );
        } catch (SecureChannel.UnexpectedError e) {
            throw new RuntimeException();
        }
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // format - (offset +) [length|pin] + [length|AID]
        new SCApplet(
                bArray,
                bOffset,
                bLength
        ).register(
                bArray,
                (short) (bOffset + bArray[bOffset] + 2),
                bArray[bOffset + bArray[bOffset] + 1]
        );
    }

    public void process(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] buffer = apdu.getBuffer();
        short length = 0;

        try {
            length = sc.processIncoming(
                    apdu
            );
        } catch (SecureChannel.UnexpectedError e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }


        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_HELLO:
                buffer[ISO7816.OFFSET_CDATA] = (byte) 0x42;
                length = sc.wrap(buffer, ISO7816.OFFSET_CDATA, (short)1, (short) 256);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) length);
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case INS_ECHO:
                length = (short)(length % 37);
                length = sc.wrap(buffer, ISO7816.OFFSET_CDATA, length, (short) 256);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) length);
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case INS_RAND:
                length = (short) 100;
                rand.nextBytes(buffer, ISO7816.OFFSET_CDATA, length);
                length = sc.wrap(buffer, ISO7816.OFFSET_CDATA, length, (short) 256);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, length);
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            default:
                sc.wrap(buffer, (short) 0, (short) 0, (short) 0);
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }
    }




}

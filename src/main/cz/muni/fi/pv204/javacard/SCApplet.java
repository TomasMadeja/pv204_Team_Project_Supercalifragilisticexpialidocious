package cz.muni.fi.pv204.javacard;

import cz.muni.fi.pv204.javacard.jpake.JPakeECParam;

import javacard.framework.*;

// Delete me when done implementing
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class SCApplet extends Applet {

    private static final byte INS_HELLO = (byte) 0xFA;

    private SecureChannel sc;


    private SCApplet(byte[] bArray, short bOffset, byte bLength) {
        // offset + [PIN_LENGTH | PIN] + [MORE_DATA]
        try {
            SecureChannel.setPin(
                    bArray,
                    (short) (bOffset + 1),
                    bArray[bOffset]
            );
        } catch (SecureChannel.UnexpectedError e) {
            throw new RuntimeException();
        }

        sc = SecureChannel.getSecureChannel();
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
        short length;

        try {
            length = sc.processIncoming(
                    apdu
            );
        } catch (SecureChannel.UnexpectedError e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }


        switch (buffer[ISO7816.OFFSET_INS]) {

            case INS_HELLO:
                byte data[] = {(byte) 0xFF};
                Util.arrayCopy(data, (short) 0, buffer, ISO7816.OFFSET_CDATA, (short) 1);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 1);
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;

        }
    }




}

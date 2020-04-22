package cz.muni.fi.pv204.javacard;

import cz.muni.fi.pv204.javacard.jpake.JPakeECParam;

import javacard.framework.Applet;
import javacard.framework.APDU;

// Delete me when done implementing
import javacard.framework.ISO7816;
import javacard.framework.Util;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class SCApplet extends Applet {

    private static final byte INS_HELLO = (byte) 0xFA;

    private SecureChannel sc;


    private SCApplet(byte[] bArray, short bOffset, byte bLength) {
        // offset + [PIN_LENGTH | PIN] + [MORE_DATA]
        SecureChannel.setPin(
                bArray,
                (short) (bOffset + 1),
                bArray[bOffset]
        );

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
        byte[] buffer = apdu.getBuffer();
        short length = apdu.setIncomingAndReceive();

        sc.processIncoming(
                buffer[ISO7816.OFFSET_INS],
                buffer, ISO7816.OFFSET_CDATA, length,
                buffer, ISO7816.OFFSET_CDATA, length
                );


        switch (buffer[ISO7816.OFFSET_INS]) {

            case INS_HELLO:
                byte data[] = {(byte) 0xFF};
                Util.arrayCopy(data, (short) 0, buffer, ISO7816.OFFSET_CDATA, (short) 1);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 1);
                break;

        }
    }




}

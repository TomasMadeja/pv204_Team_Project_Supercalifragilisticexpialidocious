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

        byte media = (byte)(APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);

        boolean contactless = (	media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A ||
                media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B);

        boolean isSecureChannel = true;

        //
        // Process any outstanding chain requests
        // NOTES:
        // - If there is an outstanding chain request to process, this method will throw an ISOException
        //	 (including SW_NO_ERROR) and no further processing will occur.
        // - It is important that this command is handled before any GP SCP authentication is called to prevent a
        //	 downgrade attack where the attacker waits for a sensitive large-command to be executed and then
        //	 intercepts the session and cancels the secure channel (thus removing session encryption).

        // We pass the APDU here because this will send data on our behalf
//        chainBuffer.processOutgoing(apdu);

        // We pass the byte array, offset and length here because the previous call to unwrap() may have altered the length
//        chainBuffer.processIncomingObject(buffer, apdu.getOffsetCdata(), length);

        //
        // Normal APDU processing
        //

        // Call the appropriate process method based on the INS
        switch (buffer[ISO7816.OFFSET_INS]) {

            case INS_HELLO:
                byte data[] = {(byte) 0xFF};
                Util.arrayCopy(data, (short) 0, buffer, ISO7816.OFFSET_CDATA, (short) 1);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 1);
                break;

        }
    }




}

package cz.muni.fi.pv204.javacard;

import cz.muni.fi.pv204.host.JCardSymInterface;
import cz.muni.fi.pv204.host.cardTools.Util;
import cz.muni.fi.pv204.javacard.crypto.MagicAes;
import javacard.framework.*;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import javax.crypto.spec.PBEKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;


public class TestMagicAes {

    public static class TestApplet extends Applet {

        public static final byte INS_ENCRYPT = 0x01;
        public static final byte INS_DECRYPT = 0x02;

        public static final byte[] AES_KEY = {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        };

        public static final byte[] IV = {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
        };

        private MagicAes aes;

        public TestApplet() {
            aes = new MagicAes();
            aes.generateKey(AES_KEY, IV);
        }

        public static void install(byte[] bArray, short bOffset, byte bLength) {
            // format - (offset +) [length|pin] + [length|AID]
            new TestApplet().register(
                    bArray,
                    (short) (bOffset + bArray[bOffset] + 2),
                    bArray[bOffset + bArray[bOffset] + 1]
            );
        }

        @Override
        public void process(APDU apdu) throws ISOException {
            byte[] buffer = apdu.getBuffer();
            short l = apdu.setIncomingAndReceive();

            switch (buffer[ISO7816.OFFSET_INS]) {

                case INS_ENCRYPT:
                    l = aes.encrypt(
                            buffer,
                            ISO7816.OFFSET_CDATA,
                            l,
                            buffer,
                            ISO7816.OFFSET_CDATA,
                            l
                    );
                    apdu.setOutgoingAndSend(
                            ISO7816.OFFSET_CDATA,
                            l
                    );
                    break;
                case INS_DECRYPT:
                    if ((l % 16) != 0) {
                        ISOException.throwIt((short) 0x6710);
                    }
                    l = aes.decrypt(
                            buffer,
                            ISO7816.OFFSET_CDATA,
                            l,
                            buffer,
                            ISO7816.OFFSET_CDATA,
                            l
                    );
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, l);
                    break;

            }
        }
    }

    @Test
    public void bounceOnce() throws Exception {
        String msg = (
                "11223344" +
                        "11223344" +
                        "11223344" +
                        "11223344"
        );

        JCardSymInterface sym = new JCardSymInterface(
                JCardSymInterface.APPLET_AID_BYTE,
                JCardSymInterface.INSTALL_DATA_BYTE,
                TestApplet.class
        );
        sym.Connect();

        cz.muni.fi.pv204.host.MagicAes aes = new cz.muni.fi.pv204.host.MagicAes();
        aes.generateKey(TestApplet.AES_KEY, TestApplet.IV);

        byte[] msg_b = Util.hexStringToByteArray(
                "8001000010" + msg
        );
        ResponseAPDU response = sym.transmit(
                new CommandAPDU(
                        msg_b
                )
        );
        Assertions.assertNotNull(response);
        byte[] resp = response.getData();
        Assertions.assertNotNull(resp);

        byte[] r = new byte[16];
        aes.decrypt(
                resp, (short) 0, (short) resp.length,
                r, (short) 0, (short) resp.length
        );

        Assertions.assertEquals(msg.toLowerCase(), Util.bytesToHex(r).toLowerCase());
    }

    @Test
    public void bounceTwice() throws Exception {
        String msg = (
                "11223344" +
                        "11223344" +
                        "11223344" +
                        "11223344"
        );

        JCardSymInterface sym = new JCardSymInterface(
                JCardSymInterface.APPLET_AID_BYTE,
                JCardSymInterface.INSTALL_DATA_BYTE,
                TestApplet.class
        );
        sym.Connect();

        cz.muni.fi.pv204.host.MagicAes aes = new cz.muni.fi.pv204.host.MagicAes();
        aes.generateKey(TestApplet.AES_KEY, TestApplet.IV);

        byte[] msg_b;
        byte[] resp;
        ResponseAPDU response;

        msg_b = Util.hexStringToByteArray(
                "8001000010" + msg
        );
        response = sym.transmit(
                new CommandAPDU(
                        msg_b
                )
        );

        resp = response.getData();
        aes.decrypt(
                resp, (short) 0, (short) resp.length,
                resp, (short) 0, (short) resp.length
        );
        Assertions.assertEquals(msg.toLowerCase(), Util.bytesToHex(resp).toLowerCase(), "Round 1");

        msg_b = Util.hexStringToByteArray(
                "8001000010" + Util.bytesToHex(resp)
        );
        response = sym.transmit(
                new CommandAPDU(
                        msg_b
                )
        );

        resp = response.getData();
        aes.decrypt(
                resp, (short) 0, (short) resp.length,
                resp, (short) 0, (short) resp.length
        );
        Assertions.assertEquals(msg.toLowerCase(), Util.bytesToHex(resp).toLowerCase(), "Round 2");
    }

}

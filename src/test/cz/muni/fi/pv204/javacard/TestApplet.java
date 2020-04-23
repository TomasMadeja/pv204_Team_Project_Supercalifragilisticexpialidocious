package cz.muni.fi.pv204.javacard;

import cz.muni.fi.pv204.host.JCardSymInterface;
import cz.muni.fi.pv204.host.SecureChannel;
import cz.muni.fi.pv204.host.cardTools.Util;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class TestApplet {

    public static final byte[] CMD_HELLO = Util.hexStringToByteArray("08F10000");
    public static final byte[] CMD_ECHO = Util.hexStringToByteArray("08F20000" + "03" + "040102");
    public static final byte[] CMD_RAND = Util.hexStringToByteArray("08F30000");

    @Test
    public void installApplet() throws Exception {
        Assertions.assertNotNull(
            JCardSymInterface.defaultCreateConnect()
        );
    }

    @Test
    public void hello() throws Exception {
        JCardSymInterface sym = JCardSymInterface.defaultCreateConnect();

        ResponseAPDU response = sym.transmit(
                new CommandAPDU(
                        Util.hexStringToByteArray("80FA000001")
                )
        );
        System.out.println(Util.bytesToHex(response.getBytes()));
    }

    @Test
    public void handshakeTest() throws Exception {
        JCardSymInterface sym = JCardSymInterface.defaultCreateConnect();

        byte[] id = Util.hexStringToByteArray("00010203040506070809");
        char[] password = {'1', '1', '1', '1'};
        SecureChannel channel = new SecureChannel(sym, id, password);
        channel.establishSC();

        ResponseAPDU r;
        byte[] buff;
        r = channel.send(CMD_HELLO);
        buff = r.getData();
        System.out.println(channel.decryptDataBuffer(buff));
        System.out.println(Util.bytesToHex(buff));

        r = channel.send(CMD_ECHO);
        buff = r.getData();
        System.out.println(channel.decryptDataBuffer(buff));
        System.out.println(Util.bytesToHex(buff));

        r = channel.send(CMD_RAND);
        buff = r.getData();
        System.out.println(channel.decryptDataBuffer(buff));
        System.out.println(Util.bytesToHex(buff));
    }

}

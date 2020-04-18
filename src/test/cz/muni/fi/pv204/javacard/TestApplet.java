package cz.muni.fi.pv204.javacard;

import cz.muni.fi.pv204.host.JCardSymInterface;
import cz.muni.fi.pv204.host.cardTools.Util;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class TestApplet {

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

}

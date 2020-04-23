package cz.muni.fi.pv204.host;

import cz.muni.fi.pv204.host.cardTools.Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;


public class TestParticipant {

    @Test
    public void simpleConversation() throws Exception {
//        ECNamedCurveTable.getNames().
//        System.out.println(ECNamedCurveTable.getNames());
        byte[] pin = {0x00,0x01,0x02,0x03};
        byte[] pin2 = {0x00,0x01,0x02,0x03};
        Participant p1 = new Participant(
                Util.hexStringToByteArray("01020304050607080900"),
                pin
        );
        Participant p2 = new Participant(
                Util.hexStringToByteArray("01020304050607080901"),
                pin2
        );
        p2.validateRound1PayloadReceived(p1.createRound1PayloadToSend());
        p1.validateRound2PayloadReceived(p2.createRound2PayloadToSend());
        p2.validateRound3PayloadReceived(p1.createRound3PayloadToSend());

        ECPoint k1 = p1.calculateKeyingMaterial();
        ECPoint k2 = p2.calculateKeyingMaterial();
        Assertions.assertEquals(k1, k2);
    }
}

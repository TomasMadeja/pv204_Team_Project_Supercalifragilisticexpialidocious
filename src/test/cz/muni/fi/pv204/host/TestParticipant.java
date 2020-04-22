package cz.muni.fi.pv204.host;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;


public class TestParticipant {

    @Test
    public void simpleConversation() throws Exception {
//        ECNamedCurveTable.getNames().
//        System.out.println(ECNamedCurveTable.getNames());
        char[] pin = {'0','1','2','3'};
        char[] pin2 = {'0','1','2','3'};
        Participant p1 = new Participant(
                "1",
                pin
        );
        Participant p2 = new Participant(
                "2",
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

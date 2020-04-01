package cz.muni.fi.pv204.javacard;

import javacard.framework.Applet;
import javacard.framework.APDU;

// Delete me when done implementing
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class SCApplet extends Applet {

    private SCApplet() {
        throw new NotImplementedException();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // new OpenFIPS201().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
        throw new NotImplementedException();
    }

    public void process(APDU apdu) {
        throw new NotImplementedException();
    }

}

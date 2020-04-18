package cz.muni.fi.pv204.javacard;

import cz.muni.fi.pv204.javacard.crypto.NIZKP;
import cz.muni.fi.pv204.javacard.jpake.JPakePassword;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class SecureChannel {

    private static SecureChannel sc = null;
    private static JPakePassword pin = null;

    private SecureChannel() {
//        throw new NotImplementedException();
    }

    public static SecureChannel getSecureChannel() {
        if (sc == null) {
            sc = new SecureChannel();
        }
        return sc;
    }

    public static void setPin(byte[] newPin, short offset, byte length) {
        if (pin == null) {
            pin = new JPakePassword((byte) 3, (byte) 4, new NIZKP());
        }
        pin.update(newPin, offset, length);
    }

    public static boolean check(byte[] inPin, short offset, byte length) {
        return pin.check(inPin, offset, length);
    }

    public boolean isEstablished() {
        throw new NotImplementedException();
    }

    public void process() {
        throw new NotImplementedException();
    }

    public void wrap() {
        throw new NotImplementedException();
    }

    public void unwrap() {
        throw new NotImplementedException();
    }

    private void establishmentRound2(
            byte[] incoming, short incomingOffset, short incomingLength,
            byte[] outgoing, short outgoingOffset, short outgoingLength
    ) {
        // Incoming Round 1, outgoing Round 2

    }

    private void establishmentChallenge(
            byte[] incoming, short incomingOffset, short incomingLength,
            byte[] outgoing, short outgoingOffset, short outgoingLength
    ) {
        // Incoming Round 3, outgoing random challange
    }

    private void establishmentHello(
            byte[] incoming, short incomingOffset, short incomingLength,
            byte[] outgoing, short outgoingOffset, short outgoingLength
    ) {
        // Incoming hmaced hello, outgoing hmaced hello
    }

}

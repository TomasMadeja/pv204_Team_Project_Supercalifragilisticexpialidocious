package cz.muni.fi.pv204.javacard;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class SecureChannel {

    private static SecureChannel sc = null;

    private SecureChannel() {
        throw new NotImplementedException();
    }

    public static SecureChannel getSecureChannel() {
        if (sc == null) {
            sc = new SecureChannel();
        }
        return sc;
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

}

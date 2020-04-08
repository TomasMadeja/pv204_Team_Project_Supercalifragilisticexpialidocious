package cz.muni.fi.pv204.javacard;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class ECDH {

    void setKey(
        byte[] keyBuffer,
        short keyOffset,
        short keyLength
    ) {
        throw new NotImplementedException();
    }

    public void resetKey() {
        throw new NotImplementedException();
    }

    public short generateSecret(
        byte[] publicData,
        short publicOffset,
        short publicLength,
        byte[] secret,
        short secretOffset
    ) {
        throw new NotImplementedException();
    }

}

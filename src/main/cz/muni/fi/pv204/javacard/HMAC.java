package cz.muni.fi.pv204.javacard;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class HMAC {

    public HMAC() {
        throw new NotImplementedException();
    }

    public void setKey(
            byte[] keyBuffer,
            short keyOffset,
            short keyLength
    ) {
        throw new NotImplementedException();
    }

    public void resetKey() {
        throw new NotImplementedException();
    }

    public short sign(
            byte[] inBuffer,
            short inOffset,
            short inLength,
            byte[] sigBuffer,
            short sigOffset
    ){
        throw new NotImplementedException();
    }

    public short verify(
            byte[] inBuffer,
            short inOffset,
            short inLength,
            byte[] sigBuff,
            short sigOffset,
            short sigLength
    ){
        throw new NotImplementedException();
    }
}

package cz.muni.fi.pv204.javacard.jpake;

import cz.muni.fi.pv204.javacard.crypto.NIZKP;
import javacard.framework.PIN;

public class JPakePassword implements PIN {

    public JPakePassword(byte tryLimit, byte maxPasswordSize, NIZKP zkp) {

    }

    @Override
    public byte getTriesRemaining() {
        return 0;
    }

    @Override
    public boolean check(byte[] bytes, short i, byte b) throws ArrayIndexOutOfBoundsException, NullPointerException {
        return false;
    }

    @Override
    public boolean isValidated() {
        return false;
    }

    @Override
    public void reset() {

    }

    public void update(byte[] data, short offset, short length) {

    }

    public void generateProof() {

    }
}

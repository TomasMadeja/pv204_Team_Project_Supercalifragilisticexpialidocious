package cz.muni.fi.pv204.javacard.jpake;

import javacard.framework.OwnerPIN;
import javacard.framework.Util;

public class JPakePassword extends OwnerPIN {

    private byte[] password;
    private byte[] wrongPassword;

    public JPakePassword(byte tries, byte length) {
        super(tries, length);
        password = new byte[length];
        wrongPassword = new byte[length];
    }

    @Override
    public void update(byte[] pin, short offset, byte length) {
        Util.arrayCopy(pin, offset, password, (short) 0, length);
        Util.arrayCopy(pin, offset, wrongPassword, (short) 0, length);
        wrongPassword[0] ^= 0xff;
        super.update(pin, offset, length);
    }

    public void decrement() {
        super.check(wrongPassword, (short) 0, (byte) wrongPassword.length);
    }

    public void correct() {
        super.check(password, (short) 0, (byte) password.length);
    }

    public byte[] getPassword() {return password;}
}

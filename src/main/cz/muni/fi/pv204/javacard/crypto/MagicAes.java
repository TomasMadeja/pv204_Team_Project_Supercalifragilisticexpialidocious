package cz.muni.fi.pv204.javacard.crypto;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class MagicAes {

    private MessageDigest sha;
    private Key key;
    private Cipher aes;

    private byte[] iv = new byte[32];

    public MagicAes() {
        key = KeyBuilder.buildKey(
                KeyBuilder.TYPE_AES,
                KeyBuilder.LENGTH_AES_256,
                false
        );
        try {
            aes = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        }
        catch (CryptoException e) {
            ISOException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    }

    public void generateKey(byte[] data, byte[] iv) {
        byte[] out = new byte [32];
        Util.arrayCopy(iv, (short) 0, this.iv, (short) 0, (short) 32);

        sha.reset();
        sha.doFinal(
                data, (short) 0, (short) data.length,
                out, (short) 0
        );

        ((AESKey) key).setKey(out, (short) 0);
    }

    public short encrypt(
            byte[] inBuffer,
            short inOffset,
            short inLen,
            byte[] outBuffer,
            short outOffset,
            short outLen
    ) {
        sha.doFinal(
                iv, (short) 0, (short) iv.length,
                iv, (short) 0
        );
        aes.init(
                key,
                Cipher.MODE_ENCRYPT,
                iv, (short) 0, (short) 16
        );
        return aes.doFinal(
                inBuffer, inOffset, inLen,
                outBuffer, outOffset
        );
    }

    public short decrypt(
            byte[] inBuffer,
            short inOffset,
            short inLen,
            byte[] outBuffer,
            short outOffset,
            short outLen
    ) {
        sha.doFinal(
                iv, (short) 0, (short) iv.length,
                iv, (short) 0
        );
        aes.init(
                key,
                Cipher.MODE_DECRYPT,
                iv, (short) 0, (short) 16
        );
        return aes.doFinal(
                inBuffer, inOffset, inLen,
                outBuffer, outOffset
        );
    }

    public void nextIV() {
        sha.doFinal(
                iv, (short) 0, (short) iv.length,
                iv, (short) 0
        );
    }

    public byte[] getIV() {
        return iv;
    }


}

package cz.muni.fi.pv204.javacard.crypto;

import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
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
        aes = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);

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
        aes.init(
                key,
                Cipher.MODE_ENCRYPT,
                iv, (short) 0, (short) 16
        );
        aes.init(
                key,
                Cipher.MODE_DECRYPT,
                iv, (short) 0, (short) 16
        );
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

    public byte[] getIV() {
        return iv;
    }


}

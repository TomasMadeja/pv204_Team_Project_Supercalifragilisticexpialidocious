package cz.muni.fi.pv204.host;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.DigestException;
import java.security.MessageDigest;

public class MagicAes {
    private MessageDigest sha;
    private Cipher aes;
    private SecretKeySpec key;

    private byte[] iv = new byte[32];

    public MagicAes() throws Exception {
        sha = MessageDigest.getInstance("SHA-256");
        aes = Cipher.getInstance("AES/CBC/NoPadding");
    }

    public void generateKey(byte[] data, byte[] iv) throws Exception {
        System.arraycopy(iv, 0, this.iv, 0, iv.length);
        sha.reset();
        key = new SecretKeySpec(sha.digest(data), 0, 32, "AES");
    }

    public int encrypt(
            byte[] inBuffer,
            short inOffset,
            short inLen,
            byte[] outBuffer,
            short outOffset,
            short outLen
    ) throws Exception {
        digest(
                iv, 0, iv.length,
                iv, 0, iv.length
        );
        aes.init(
                Cipher.ENCRYPT_MODE,
                key,
                new IvParameterSpec(iv, 0, 16)
        );
        return aes.doFinal(
                inBuffer, inOffset, inLen,
                outBuffer, outOffset
        );
    }

    public int decrypt(
            byte[] inBuffer,
            short inOffset,
            short inLen,
            byte[] outBuffer,
            short outOffset,
            short outLen
    ) throws Exception {
        digest(
                iv, 0, iv.length,
                iv, 0, iv.length
        );
        aes.init(
                Cipher.DECRYPT_MODE,
                key,
                new IvParameterSpec(iv, 0, 16)
        );
        return aes.doFinal(
                inBuffer, inOffset, inLen,
                outBuffer, outOffset
        );
    }

    public void nextIV() {
        sha.reset();
        iv = sha.digest(iv);
    }

    public byte[] getIV() {
        return iv;
    }

    private void digest(
            byte[] inBuffer,
            int inOffset,
            int inLen,
            byte[] outBuffer,
            int outOffset,
            int outLen
    ) throws DigestException {
        sha.reset();
        sha.update(inBuffer, inOffset, inLen);
        sha.digest(outBuffer, outOffset, outLen);
    }
}

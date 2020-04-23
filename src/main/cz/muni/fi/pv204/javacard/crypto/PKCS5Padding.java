package cz.muni.fi.pv204.javacard.crypto;

/**
 * @author  https://alvinalexander.com/java/jwarehouse/openjdk-8/jdk/src/share/classes/com/sun/crypto/provider/PKCS5Padding.java.shtml
 */
public class PKCS5Padding {

    private int blockSize;

    public PKCS5Padding(short blockSize) {
        this.blockSize = blockSize;
    }

    public void padWithLen(byte[] in, short off, short inLen, short paddingLen)
            throws Exception
    {
        short len = paddingLen;

        if (in == null)
            return;

        if ((off + len) > inLen) {
            throw new Exception();
        }

        byte paddingOctet = (byte) (len & 0xff);
        for (short i = 0; i < len; i++) {
            in[i + off] = paddingOctet;
        }
        return;
    }


    public short pad(
            byte[] buffer, short off, short currentLen, short avaliableLen
        ) {
        short l = padLength(currentLen);
        try {
            padWithLen(buffer, (short) (off + currentLen), (short) (avaliableLen - currentLen), l);
        } catch (Exception e) {}
        return (short) (currentLen + l);
    }

    public short unpad(byte[] in, short off, short len) {
        if ((in == null) ||
                (len == 0)) { // this can happen if input is really a padded buffer
            return 0;
        }

        byte lastByte = in[off + len - 1];
        short padValue = (short) ((short)lastByte & 0x0ff);
        if ((padValue < 0x01)
                || (padValue > blockSize)) {
            return -1;
        }

        short start = (short) (off + len - ((short) lastByte & 0x0ff));
        if (start < off) {
            return -1;
        }

        for (short i = 0; i < ((short)lastByte & 0x0ff); i++) {
            if (in[start+i] != lastByte) {
                return -1;
            }
        }

        return start;
    }

    public short padLength(short len) {
        short paddingOctet = (short) (blockSize - (len % blockSize));
        return paddingOctet;
    }
}

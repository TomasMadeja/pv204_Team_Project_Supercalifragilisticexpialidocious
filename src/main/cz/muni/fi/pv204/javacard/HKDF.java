package cz.muni.fi.pv204.javacard;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class HKDF {

    // might be possible to make static

    /**
     *
     * @param hashFunction specifies has to be used by hmac
     * @param salt random public salt
     * @param ikm input keying material
     * @param outputLength user-defined output size
     * @param output output array (to be written into)
     */
    public void hkdf(
            byte hashFunction,
            byte[] salt,
            byte[] ikm,
            byte[] outputLength,
            byte[] output
    ) {
        throw new NotImplementedException();
    }

}

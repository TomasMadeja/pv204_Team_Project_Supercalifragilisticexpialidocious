package cz.muni.fi.pv204.javacard.jpake;

public class JPakeECParam {

    public final byte[] m;
    public final byte[] f;
    public final byte[] a;
    public final byte[] b;
    public final byte[] G;
    public final byte[] n;
    public final byte[] h;

    JPakeECParam(
            byte[] m,
            byte[] f,
            byte[] a,
            byte[] b,
            byte[] G,
            byte[] n,
            byte[] h
    ) {
        this.m = m;
        this.f = f;
        this.a = a;
        this.b = b;
        this.G = G;
        this.n = n;
        this.h = h;
    }

}

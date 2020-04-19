package cz.muni.fi.pv204.javacard.jpake;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import cz.muni.fi.pv204.javacard.jcmathlib.*;



public class JPakeECParam extends Applet {
    public final byte[] p;
    public final byte[] a;
    public final byte[] b;
    public final byte[] G;
    public final byte[] r;
    public final byte[] pt1;
    public final byte[] pt2;
    public final byte[] scalar;

    //to do, change the values as per standard
    final static short INS_ADD = (short) 0x42;
    final static short INS_MUL = (short) 0x43;

    ECConfig ecc =null;
    ECCurve curve= null;
    ECPoint point1 =null;
    ECPoint point2 = null;

    JPakeECParam(  byte[] p,   byte[] a,     byte[] b,  byte[] G,  byte[] r ,byte[] pt1,byte[]pt2,byte[]scalar)
    {
        this.p = p;
        this.a = a;
        this.b = b;
        this.G = G;
        this.r = r;
        this.pt1 = pt1;
        this.pt2 = pt2;
        this.scalar = scalar;


        ECConfig ecc = new ECConfig((short) 256);
        // Pre-allocate standard SecP256r1 curve and two EC points on this curve
        //ECCurve curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);
        // take arguements from my curve perimeters
        ECCurve curve = new ECCurve(false, p, a, b, G, r);
        ECPoint point1 = new ECPoint(curve, ecc.ech);
        ECPoint point2 = new ECPoint(curve, ecc.ech);

    }


    void addPoints(byte[]a, byte[]b)
    {
        byte[]temp = new byte[200];
        // set point values
        point1.setW(a,(short)0,(short)a.length);
        point2.setW(b,(short)0,(short)b.length);
        point1.add(point2);

        point1.getW(temp,(short)0);
        System.out.println(temp);
        //to do, result processing

    }
    void mulPoints(byte[]a,byte[]scalar)
    {
        byte[]temp = new byte[200];
        // Multiply point by large scalar
        point1.setW(a,(short)0,(short)a.length);
        point1.multiplication(scalar, (short) 0, (short) scalar.length);

        point1.getW(temp,(short)0);
        System.out.println(temp);
        //to do, result processing
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        switch(buffer[ISO7816.OFFSET_INS])
        {
            case (byte) INS_ADD:
                addPoints(pt1,pt2);
                break;
            case (byte) INS_MUL:
                mulPoints(pt1,scalar);
                break;
            default :
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }


    }
}

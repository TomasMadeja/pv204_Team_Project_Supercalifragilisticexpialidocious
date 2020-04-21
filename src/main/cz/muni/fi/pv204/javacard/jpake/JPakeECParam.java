package cz.muni.fi.pv204.javacard.jpake;

import javacard.framework.*;
import cz.muni.fi.pv204.javacard.jcmathlib.*;
import javacard.security.*;


public class JPakeECParam {
    public final byte[] p;
    public final byte[] a;
    public final byte[] b;
    public final byte[] G;
    public final byte[] r;


    //to do, change the values as per standard
    final static short INS_ADD = (short) 0x42;
    final static short INS_MUL = (short) 0x43;
    final static short INS_GEN_SS = (short) 0x44;

    private byte[] sharedSecret= null;
    private AESKey sessionKey=null;
    ECConfig ecc =null;
    ECCurve curve= null;
    ECPoint point1 =null;
    ECPoint point2 = null;

    JPakeECParam(  byte[] p,   byte[] a,     byte[] b,  byte[] G,  byte[] r )
    {
        this.p = p;
        this.a = a;
        this.b = b;
        this.G = G;
        this.r = r;


        ECConfig ecc = new ECConfig((short) 256);
        // Pre-allocate standard SecP256r1 curve and two EC points on this curve
        //ECCurve curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);
        // take arguements from my curve perimeters
        ECCurve curve = new ECCurve(false, p, a, b, G, r);
        ECPoint point1 = new ECPoint(curve, ecc.ech);
        ECPoint point2 = new ECPoint(curve, ecc.ech);


    }


    public byte[] addPoints(byte[]a, byte[]b)
    {
        byte[]result = new byte[200];
        // set point values
        point1.setW(a,(short)0,(short)a.length);
        point2.setW(b,(short)0,(short)b.length);
        point1.add(point2);

        point1.getW(result,(short)0);
        System.out.println(result);
        //to do, result processing
        return result;

    }
    public byte[] mulPoints(byte[]a,byte[]scalar)
    {
        byte[]result = new byte[200];
        // Multiply point by large scalar
        point1.setW(a,(short)0,(short)a.length);
        point1.multiplication(scalar, (short) 0, (short) scalar.length);
        point1.getW(result,(short)0);
        System.out.println(result);
        //to do, result processing
        return result;
    }

    public byte[] getGenCard(byte []P1, byte[] P2, byte[] P3, byte[]x2Scalar)
    {
        byte[] temp,temp2;
        byte[] result;
        temp= addPoints(P1,P2);
        temp2 = addPoints(temp,P3);
        result = mulPoints(temp2,x2Scalar);
        return result;
    }
    public byte[] getSharedKey(byte[] host, byte[] P4, byte[] x2Scalar, byte[] x2 )
    {
        byte [] temp, temp1;
        temp = mulPoints(P4,x2Scalar);
        ECPoint point1 = new ECPoint(curve, ecc.ech);
        point1.setW(temp,(short)0,(short)temp.length);
        point1.negate();
        byte [] temp3=null;
        point1.getW(temp3,(short)0);
        temp1 = addPoints(host,temp3);
        byte[] temp4;
        temp4 = mulPoints(temp1,x2);
      return temp4;

    }









}

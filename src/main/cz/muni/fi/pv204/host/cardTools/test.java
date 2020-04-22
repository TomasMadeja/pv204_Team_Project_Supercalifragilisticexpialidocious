package cz.muni.fi.pv204.host.cardTools;
/*
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import cz.muni.fi.pv204.javacard.jcmathlib.*;

public class test {


//    public final byte[] p;
//    public final byte[] a;
//    public final byte[] b;
//    public final byte[] G;
//    public final byte[] r;
    // public final byte[] pt1;
 //   public final byte[] pt2;
    // public final byte[] scalar;

    //to do, change the values as per standard
    final static short INS_ADD = (short) 0x42;
    final static short INS_MUL = (short) 0x43;

    ECConfig ecc = null;
    ECCurve curve = null;
    ECPoint point1 = null;
    ECPoint point2 = null;
    final static byte[] pt11 = {(byte) 0x04, (byte) 0x3B, (byte) 0xC1, (byte) 0x5B, (byte) 0xE5, (byte) 0xF7, (byte) 0x52, (byte) 0xB3, (byte) 0x27, (byte) 0x0D, (byte) 0xB0, (byte) 0xAE, (byte) 0xF2, (byte) 0xBC, (byte) 0xF0, (byte) 0xEC, (byte) 0xBD, (byte) 0xB5, (byte) 0x78, (byte) 0x8F, (byte) 0x88, (byte) 0xE6, (byte) 0x14, (byte) 0x32, (byte) 0x30, (byte) 0x68, (byte) 0xC4, (byte) 0xC4, (byte) 0x88, (byte) 0x6B, (byte) 0x43, (byte) 0x91, (byte) 0x4C, (byte) 0x22, (byte) 0xE1, (byte) 0x67, (byte) 0x68, (byte) 0x3B, (byte) 0x32, (byte) 0x95, (byte) 0x98, (byte) 0x31, (byte) 0x19, (byte) 0x6D, (byte) 0x41, (byte) 0x88, (byte) 0x0C, (byte) 0x9F, (byte) 0x8C, (byte) 0x59, (byte) 0x67, (byte) 0x60, (byte) 0x86, (byte) 0x1A, (byte) 0x86, (byte) 0xF8, (byte) 0x0D, (byte) 0x01, (byte) 0x46, (byte) 0x0C, (byte) 0xB5, (byte) 0x8D, (byte) 0x86, (byte) 0x6C, (byte) 0x09};
    final static byte[] scalar1 = {(byte) 0xE8, (byte) 0x05, (byte) 0xE8, (byte) 0x02, (byte) 0xBF, (byte) 0xEC, (byte) 0xEE, (byte) 0x91, (byte) 0x9B, (byte) 0x3D, (byte) 0x3B, (byte) 0xD8, (byte) 0x3C, (byte) 0x7B, (byte) 0x52, (byte) 0xA5, (byte) 0xD5, (byte) 0x35, (byte) 0x4C, (byte) 0x4C, (byte) 0x06, (byte) 0x89, (byte) 0x80, (byte) 0x54, (byte) 0xB9, (byte) 0x76, (byte) 0xFA, (byte) 0xB1, (byte) 0xD3, (byte) 0x5A, (byte) 0x10, (byte) 0x91};

   // test(byte[] p, byte[] a, byte[] b, byte[] G, byte[] r, byte[] pt1, byte[] pt2, byte[] scalar) {
     test(){
  //      this.p = p;
  //      this.a = a;
  //      this.b = b;
  //      this.G = G;
  //      this.r = r;
        //  this.pt1 = pt1;
  //      this.pt2 = pt2;
        //  this.scalar = scalar;


        ECConfig ecc = new ECConfig((short) 256);
        // Pre-allocate standard SecP256r1 curve and two EC points on this curve
        ECCurve curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);
        ECPoint point1 = new ECPoint(curve, ecc.ech);
        ECPoint point2 = new ECPoint(curve, ecc.ech);

    }


    void addPoints(byte[] a, byte[] b) {

        ECConfig ecc = new ECConfig((short) 256);
        ECCurve curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);
        System.out.println(curve);
        System.out.println("$$$$$$$$$$$$");
        ECPoint point1 = new ECPoint(curve, ecc.ech);
        point1.setW(a, (short) 0, (short) a.length);
        ECPoint point2 = new ECPoint(curve, ecc.ech);
        point2.randomize(); // Generate first point at random

        point1.add(point2);
        byte[]buffer= new byte[200];
        point1.getW(buffer, (short) 0);
        System.out.println(buffer);
        //to do, result processing
    }

    void mulPoints(byte[] a, byte[] scalar) {
        ECConfig ecc = new ECConfig((short) 256);
        ECCurve curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);
         System.out.println(curve);
         System.out.println("$$$$$$$$$$$$");
        ECPoint point1 = new ECPoint(curve, ecc.ech);

        // System.out.println(point1);
        byte[] temp = new byte[200];
        // Multiply point by large scalar
        point1.setW(pt11, (short) 0, (short) pt11.length);
        //point1.multiplication(scalar, (short) 0, (short) scalar.length);
        point1.multiplication(scalar1, (short) 0, (short) scalar1.length); // Multiply point by large scalar

        point1.getW(temp, (short) 0);
        System.out.println(temp);
        //to do, result processing
    }


    public static void main(String[] args) {
        new test().mulPoints(pt11, scalar1);

    }
}
*/
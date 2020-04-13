/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.muni.fi.pv204.host;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;


/**
 *
 * @author minh
 */
public class Host {
    private String enteredPIN = "1234";
    private String TerminalID = "Terminal";
    
    
    public String createRound1PayloadToSend()
    {
        return "Some points on EC";
    }
    
    public int validateRound1PayloadReceived(String cardsPayload) 
    {
        return 0;
    }
    
    public String createRound2PayloadToSend()
    {
        return "Some points on EC";
    }
    
    
    public int validateRound2PayloadReceived(String cardsPayload) 
    {
        return 0;
    }
    
    
    public String createRound3PayloadToSend()
    {
        return "Some points on EC";
    }
 
    public int validateRound3PayloadReceived(String cardsPayload) 
    {
        return 0;
    }
}

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.muni.fi.pv204.host;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 * @author minh
 */
public class ParticipantTest {
    
    public ParticipantTest() {
    }
    
    @BeforeAll
    public static void setUpClass() {
    }
    
    @AfterAll
    public static void tearDownClass() {
    }
    
    @BeforeEach
    public void setUp() {
    }
    
    @AfterEach
    public void tearDown() {
    }

    /**
     * Test of getState method, of class Participant.
     */
    @Test
    public void testGetState() {
        System.out.println("getState");
        Participant instance = null;
        int expResult = 0;
        int result = instance.getState();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of createRound1PayloadToSend method, of class Participant.
     */
    @Test
    public void testCreateRound1PayloadToSend() {
        System.out.println("createRound1PayloadToSend");
        Participant instance = null;
        Round1Payload expResult = null;
        Round1Payload result = instance.createRound1PayloadToSend();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of validateRound1PayloadReceived method, of class Participant.
     */
    @Test
    public void testValidateRound1PayloadReceived() throws Exception {
        System.out.println("validateRound1PayloadReceived");
        Round1Payload round1PayloadReceived = null;
        Participant instance = null;
        instance.validateRound1PayloadReceived(round1PayloadReceived);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of createRound2PayloadToSend method, of class Participant.
     */
    @Test
    public void testCreateRound2PayloadToSend() {
        System.out.println("createRound2PayloadToSend");
        Participant instance = null;
        Round2Payload expResult = null;
        Round2Payload result = instance.createRound2PayloadToSend();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of validateRound2PayloadReceived method, of class Participant.
     */
    @Test
    public void testValidateRound2PayloadReceived() throws Exception {
        System.out.println("validateRound2PayloadReceived");
        Round2Payload round2PayloadReceived = null;
        Participant instance = null;
        instance.validateRound2PayloadReceived(round2PayloadReceived);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of calculateKeyingMaterial method, of class Participant.
     */
    @Test
    public void testCalculateKeyingMaterial() {
        System.out.println("calculateKeyingMaterial");
        Participant instance = null;
        ECPoint expResult = null;
        ECPoint result = instance.calculateKeyingMaterial();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of createRound3PayloadToSend method, of class Participant.
     */
    @Test
    public void testCreateRound3PayloadToSend() {
        System.out.println("createRound3PayloadToSend");
        Participant instance = null;
        Round3Payload expResult = null;
        Round3Payload result = instance.createRound3PayloadToSend();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of validateRound3PayloadReceived method, of class Participant.
     */
    @Test
    public void testValidateRound3PayloadReceived() throws Exception {
        System.out.println("validateRound3PayloadReceived");
        Round3Payload round3PayloadReceived = null;
        Participant instance = null;
        instance.validateRound3PayloadReceived(round3PayloadReceived);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    
}

package cz.muni.fi.pv204.host;

import cz.muni.fi.pv204.host.cardTools.CardManager;
import cz.muni.fi.pv204.host.cardTools.RunConfig;
import cz.muni.fi.pv204.host.cardTools.Util;
import cz.muni.fi.pv204.javacard.SCApplet;

public class JCardSymInterface extends CardManager {

    public static String APPLET_AID = "FFFFFFFFFF010101";
    public static String PIN = "01010101";
    public static byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);
    public static byte INSTALL_DATA_BYTE[] = Util.hexStringToByteArray("04" + PIN + "08" + APPLET_AID);


    private RunConfig runCfg;

    public JCardSymInterface(
            byte[] appletAID,
            byte[] installData,
            Class applet
    ) {
        super(true, appletAID);
        runCfg = RunConfig.getDefaultConfig();
        runCfg.setInstallData(installData);
        runCfg.setAppletToSimulate(applet); // main class of applet to simulate
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator
    }

    public boolean Connect() throws Exception {
        return this.Connect(runCfg);
    }

    public static JCardSymInterface defaultCreateConnect() throws Exception {
        JCardSymInterface jc = new JCardSymInterface(
                APPLET_AID_BYTE,
                INSTALL_DATA_BYTE,
                SCApplet.class
        );
        if (jc.Connect()) return jc;
        return null;
    }
}

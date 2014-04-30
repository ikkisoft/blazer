/*
 * BurpExtender.java
 *
 * Copyright (c) 2012 Luca Carettoni
 *
 * This file is part of Blazer, a Burp extension to perform gray-box AMF Testing.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version. This program is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY.
 *
 */
package burp;

import com.mtso.blazer.AMFUtil;
import com.mtso.blazer.BlazerUIView;
import com.mtso.blazer.TaskManager;
import java.net.URL;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.UIManager;
import javax.swing.UIManager.LookAndFeelInfo;

/*
 * This class implements the IBurpExtender interface to make use of Burp Extender
 * 
 * As of v1.5.01, Burp Extender uses a new API. This extension has been adapted to run
 * on both old and new versions, with native support for Burp standard output and error tabs
 */
public class BurpExtender implements IBurpExtender {

    private static String version = "v0.3";
    private static boolean flagSM = false;

    public static String getBanner() {
        return "Blazer " + version;
    }

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.issueAlert("[" + getBanner() + "]");
        callbacks.registerMenuItem("Blazer - AMF Testing", new CustomMenuItem(callbacks));
        callbacks.registerMenuItem("Blazer - AMF2XML Export", new CustomMenuItem(callbacks));
        callbacks.registerMenuItem("Blazer - Enable/Disable Security Manager", new CustomMenuItem(callbacks));
        callbacks.setProxyInterceptionEnabled(false); //avoid interception. In case, users can re-enable it from the GUI
    }

    public byte[] processProxyMessage(int i, boolean bln, String string, int i1, boolean bln1, String string1, String string2, String string3, String string4, String string5, byte[] bytes, int[] ints) {
        //do nothing
        return bytes;
    }

    public void applicationClosing() {
        //do nothing
    }

    public void processHttpMessage(String string, boolean bln, IHttpRequestResponse ihrr) {
        //do nothing
    }

    public void newScanIssue(IScanIssue isi) {
        //do nothing
    }

    public static void toggleSM() {
        if (flagSM == true) {
            flagSM = false;
        } else {
            flagSM = true;
        }
    }

    public static boolean getFlagSM() {
        return flagSM;
    }

    public void setCommandLineArgs(String[] strings) {
        //do nothing
    }
}

class CustomMenuItem implements IMenuItemHandler {

    private IBurpExtenderCallbacks callbacks;
    private TaskManager manager;

    public CustomMenuItem(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    public void menuItemClicked(String menuItemCaption, IHttpRequestResponse[] messageInfo) {
        try {
            // User clicked on the Blazer extension contextual menu
            if (menuItemCaption.equalsIgnoreCase("Blazer - AMF Testing")) { //Standard Blazer GUI
                BlazerUIView gui = initializeAndDisplay(messageInfo);

                //Does the request contain a valid AMF RemotingMessage? Just notify the user
                if (!AMFUtil.isAMF(messageInfo[0].getRequest(), manager.getStdOut(), manager.getStdErr())) {
                    this.callbacks.issueAlert("[Blazer] The request does not contain a valid AMF RemotingMessage");
                }

                //Remove export tab
                JPanel myJPanel = (JPanel) gui.getComponent(0);
                JTabbedPane myJTabbedPane = (JTabbedPane) myJPanel.getComponent(0);
                Thread.sleep(500);
                myJTabbedPane.remove(5);
                gui.setVisible(true);

                /*
                 * Deploy our custom SecurityManager
                 * 
                 * (1) By default, we grant "java.security.AllPermission" for all
                 * (2) BlazerSecurityManager checks the execution stack and detect unauthorized operations originated from ObjectGenerator.generate() 
                 */
                ClassLoader cl = getClass().getClassLoader();
                URL policyURL = cl.getResource("burp/blazer.policy");
                System.setProperty("java.security.policy", policyURL.toString());
                SecurityManager security = System.getSecurityManager();
                if (security == null && BurpExtender.getFlagSM()) {
                    System.setSecurityManager(new BlazerSecurityManager(manager));
                }
            } else if (menuItemCaption.equalsIgnoreCase("Blazer - AMF2XML Export")) { //Export Blazer GUI
                BlazerUIView gui = initializeAndDisplay(messageInfo);

                //Does the request contain a valid AMF RemotingMessage? Just notify the user
                if (!AMFUtil.isAMF(messageInfo[0].getRequest(), manager.getStdOut(), manager.getStdErr())) {
                    this.callbacks.issueAlert("[Blazer] The request does not contain a valid AMF RemotingMessage");
                }

                //Remove unused tabs
                JPanel myJPanel = (JPanel) gui.getComponent(0);
                JTabbedPane myJTabbedPane = (JTabbedPane) myJPanel.getComponent(0);
                Thread.sleep(500);
                myJTabbedPane.remove(1);
                myJTabbedPane.remove(1);
                myJTabbedPane.remove(1);
                myJTabbedPane.remove(1);
                gui.setVisible(true);
            } else if (menuItemCaption.equalsIgnoreCase("Blazer - Enable/Disable Security Manager")) { //Disable SecurityManager option
                BurpExtender.toggleSM();
                if (BurpExtender.getFlagSM()) {
                    this.callbacks.issueAlert("[Blazer] Custom Security Manager has been enabled");
                    JOptionPane.showMessageDialog(null, "Using the Security Manager, any security exception will automatically shutdown Burp Suite and Blazer", "Alert!", JOptionPane.ERROR_MESSAGE);
                } else {
                    this.callbacks.issueAlert("[Blazer] Custom Security Manager has been disabled");
                }
            }
        } catch (Exception ex) {
            manager.getStdErr().println("[!] Blazer BurpExtender Exception: ");
            manager.getStdErr().println(ex.toString());
        }
    }

    private BlazerUIView initializeAndDisplay(IHttpRequestResponse[] messageInfo) throws Exception {
        manager = new TaskManager(callbacks, messageInfo);

        try {
            for (LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (Exception e) {
            // Nimbus L&F is not available, set the GUI to Metal or whatever is available
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        }

        return new BlazerUIView(manager);
    }
}

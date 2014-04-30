/*
 * MessageGenerator.java
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
package com.mtso.blazer;

import com.thoughtworks.xstream.XStream;
import flex.messaging.io.ArrayCollection;
import flex.messaging.io.amf.client.AMFConnection;
import flex.messaging.io.amf.client.exceptions.ClientStatusException;
import flex.messaging.io.amf.client.exceptions.ServerStatusException;
import flex.messaging.messages.RemotingMessage;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.util.Iterator;

/*
 * This class is used to craft and send AMF requests
 */
public class MessageGenerator {

    /* Proxy settings */
    private boolean proxyEnabled;
    private String proxyHost;
    private String proxyPort;
    private String endpoint;
    private String cookies;
    private AMFConnection amfConnection;
    private PrintWriter stdOut;
    private PrintWriter stdErr;
    private XStream xstream;

    public MessageGenerator(String proxyHost, String proxyPort, String endpoint, String cookies, PrintWriter stdOut, PrintWriter stdErr) {
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        this.endpoint = endpoint;
        this.cookies = cookies;
        this.stdOut = stdOut;
        this.stdErr = stdErr;
        this.xstream = new XStream();

        // Setup proxy and SSL checks
        amfConnection = new AMFConnection();
        proxyEnabled = proxySetup(amfConnection);

        //Initialize AMF connection
        try {
            amfConnection.connect(endpoint);
        } catch (ClientStatusException eClient) {
            stdErr.println("[!] ClientStatusException - Connection: " + eClient.toString().trim());
        }

        amfConnection.addHttpRequestHeader("Content-type", "application/x-amf");
        if (cookies == null ? "" != null : !cookies.equals("")) {
            amfConnection.addHttpRequestHeader("Cookie", cookies);
        }

        AMFConnection.registerAlias("DSA", flex.messaging.messages.AsyncMessageExt.class.getName());
        AMFConnection.registerAlias("DSK", flex.messaging.messages.AcknowledgeMessageExt.class.getName());
        AMFConnection.registerAlias("DSC", flex.messaging.messages.CommandMessageExt.class.getName());

        //AMF v3
        AMFConnection.setDefaultObjectEncoding(3);

        //no-check-certificate
        try {
            noCheckCertConnection();
        } catch (NoSuchAlgorithmException ex) {
            stdErr.println("[!] NoSuchAlgorithmException: " + ex.toString().trim());
        } catch (KeyManagementException ex) {
            stdErr.println("[!] KeyManagementException: " + ex.toString().trim());
        }
    }

    public boolean isProxyEnabled() {
        return this.proxyEnabled;
    }

    /*
     * Configure the HTTP/HTTPS proxy in order to tunnel all Blazer connections.
     * By default, it is the local instance of Burp
     */
    private boolean proxySetup(AMFConnection amfConn) {
        if (proxyHost != null && proxyPort != null) {
            amfConn.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, Integer.parseInt(proxyPort))));
            //Using older Adobe Flex libraries, this seems required
            System.setProperty("https.proxyHost", proxyHost);
            System.setProperty("http.proxyHost", proxyHost);
            System.setProperty("https.proxyPort", proxyPort);
            System.setProperty("http.proxyPort", proxyPort);
            return true;
        } else {
            return false;
        }
    }

    //no-check-certificate equivalent
    private void noCheckCertConnection() throws NoSuchAlgorithmException, KeyManagementException {

        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        public void checkClientTrusted(X509Certificate[] certs, String authType) {
        }

        public void checkServerTrusted(X509Certificate[] certs, String authType) {
        }
    }};
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
    }

    public void send(MessageSkeleton packet) {

        Object response = null;

        amfConnection.addHttpRequestHeader("Blazer", packet.getPacketString());

        RemotingMessage message = new RemotingMessage();
        message.setMessageId(flex.messaging.util.UUIDUtils.createUUID());

        /*
         * IMPORTANT!
         * If your application uses customized invocation objects, modify the code below
         */
        message.setDestination(packet.getDestination());
        message.setOperation(packet.getOperation());

        ArrayCollection arguments = new ArrayCollection();
        Iterator parsIt = packet.getPars().iterator();
        while (parsIt.hasNext()) {
            arguments.add(parsIt.next());
        }

        message.setBody(arguments);

        stdOut.println("[*] Sending AMF message with signature --> " + packet.getPacketString());

        try {
            response = amfConnection.call(packet.getDestination() + "." + packet.getOperation(), message);

        } catch (ClientStatusException eClient) {
            // Older versions of Adobe Flex libraries may return this client-side exception
            stdErr.println("[!] ClientStatusException: " + eClient.toString().trim());
        } catch (ServerStatusException eServer) {
            stdErr.println("[!] ServerStatusException: " + eServer.toString().trim());
        } catch (Exception eGeneric) {
            stdErr.println("[!] Generic Exception: " + eGeneric.toString().trim());
        } finally {
            //In any case, dump the response
            if (response != null) {
                stdOut.println("\n[*] ---------------------------------------------------------");
                stdOut.println(xstream.toXML(response));
                stdOut.println("[*] ---------------------------------------------------------\n");
            }
        }
    }

    public void disconnectAll() {
        amfConnection.close();
    }

    public String getCookies() {
        return cookies;
    }

    public String getEndpoint() {
        return endpoint;
    }
}

/*
 * Exporter.java
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

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import com.thoughtworks.xstream.XStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.DateFormat;
import java.util.Date;
import java.util.regex.Pattern;

/*
 * This class is used by the AMF2XML export functionality
 */
public class Exporter {

    private XStream xstream;
    private File exportFile = null;
    private boolean exportRequests = false;
    private boolean exportResponses = false;
    private Object[] applicationLibs = null;
    private TaskManager manager;

    public Exporter(TaskManager manager, boolean exportRequests, boolean exportResponses, File exportFile) {

        xstream = new XStream();

        this.exportFile = exportFile;
        this.exportResponses = exportResponses;
        this.exportRequests = exportRequests;
        this.manager = manager;
        this.applicationLibs = manager.getTask().getLibraries().toArray();

        /*
         * Include all application libraries at runtime 
         */
        try {

            URL[] classUrls = new URL[applicationLibs.length];

            for (int lCont = 0; lCont < applicationLibs.length; lCont++) {
                String absoluteVodka = ((File) applicationLibs[lCont]).getCanonicalPath();
                if (absoluteVodka.endsWith(".jar")) {
                    classUrls[lCont] = (new File(absoluteVodka)).toURI().toURL(); //loading JARs
                } else if (absoluteVodka.endsWith(".class")) {
                    String classPathName = JavaUtil.retrieveCanonicalNameFromClass(((File) applicationLibs[lCont]));
                    if (File.separator.equalsIgnoreCase("/")) {
                        classPathName = classPathName.replaceAll("\\.", "/") + ".class";
                    } else {
                        classPathName = classPathName.replaceAll("\\.", "\\\\") + ".class";
                    }
                    absoluteVodka = absoluteVodka.replaceAll(Pattern.quote(classPathName), "");
                    classUrls[lCont] = (new File(absoluteVodka)).toURI().toURL(); //loading top directory containing selected classes
                }
            }

            JavaUtil.addURLs(classUrls, manager.getStdOut(), manager.getStdErr());

        } catch (MalformedURLException ex) {
            manager.getStdErr().println("[!] AMF2XML Exporter MalformedURLException: " + ex.toString().trim());
        } catch (NoSuchMethodException ex) {
            manager.getStdErr().println("[!] AMF2XML Exporter NoSuchMethodException: " + ex.toString().trim());
        } catch (IllegalArgumentException ex) {
            manager.getStdErr().println("[!] AMF2XML Exporter IllegalArgumentException: " + ex.toString().trim());
        } catch (IllegalAccessException ex) {
            manager.getStdErr().println("[!] AMF2XML Exporter IllegalAccessException: " + ex.toString().trim());
        } catch (InvocationTargetException ex) {
            manager.getStdErr().println("[!] AMF2XML Exporter InvocationTargetException: " + ex.toString().trim());
        } catch (FileNotFoundException ex) {
            manager.getStdErr().println("[!] AMF2XML Exporter FileNotFoundException: " + ex.toString().trim());
        } catch (IOException ex) {
            manager.getStdErr().println("[!] AMF2XML Exporter IOException: " + ex.toString().trim());
        }
    }

    public void export(IHttpRequestResponse[] messageInfo) throws Exception {

        StringBuilder reqsDet = new StringBuilder();

        //Header
        reqsDet.append(GenericUtil.repeat("-", 100)).append(System.getProperty("line.separator"));
        DateFormat formatter = DateFormat.getDateTimeInstance(DateFormat.LONG, DateFormat.LONG);
        reqsDet.append(BurpExtender.getBanner()).append(" - AMF2XML Export - ").append(formatter.format(new Date())).append(System.getProperty("line.separator"));
        reqsDet.append(GenericUtil.repeat("-", 100)).append(System.getProperty("line.separator"));

        for (IHttpRequestResponse singleMsg : messageInfo) {
            //Request or Response details
            reqsDet.append("Host:").append(singleMsg.getHttpService().getHost()).append(System.getProperty("line.separator"));
            reqsDet.append("Port:").append(singleMsg.getHttpService().getPort()).append(System.getProperty("line.separator"));
            reqsDet.append("Protocol:").append(singleMsg.getHttpService().getProtocol()).append(System.getProperty("line.separator"));
            reqsDet.append("Comment:").append(singleMsg.getComment()).append(System.getProperty("line.separator"));
            if (exportRequests) {
                reqsDet.append("HTTP Request:").append(System.getProperty("line.separator")).append(xstream.toXML(AMFUtil.extractAM(singleMsg.getRequest(), manager.getStdOut(), manager.getStdErr())).replaceAll("\n", System.getProperty("line.separator"))).append(System.getProperty("line.separator"));
            }
            if (exportResponses) {
                reqsDet.append("HTTP Response:").append(System.getProperty("line.separator")).append(xstream.toXML(AMFUtil.extractAM(singleMsg.getResponse(), manager.getStdOut(), manager.getStdErr())).replaceAll("\n", System.getProperty("line.separator"))).append(System.getProperty("line.separator"));
            }
            reqsDet.append(GenericUtil.repeat("-", 100)).append(System.getProperty("line.separator"));
        }

        if (exportFile != null) { //Export to file
            try {
                if (!exportFile.exists()) {
                    exportFile.createNewFile();
                }
                FileWriter fw = new FileWriter(exportFile.getAbsoluteFile());
                BufferedWriter bw = new BufferedWriter(fw);
                bw.write(reqsDet.toString());
                bw.close();
                manager.getStdOut().println("[*] AMF2XML Exporter just saved: " + exportFile.getCanonicalPath());
            } catch (IOException ex) {
                manager.getStdErr().println("[!] AMF2XML Exporter File IOException:" + ex.toString().trim());
            }
        } else { //Export to standard output
            manager.getStdOut().println(reqsDet.toString());
        }
    }
}

/*
 * GenericUtil.java
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

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Map;

/*
 * This class implements multiple general purpose auxiliary utils
 */
public class GenericUtil {

    /*
     * Retrieve the HTTP message body from a request/response
     */
    public static byte[] getBody(byte[] request) {
        int offset = 0;
        byte[] body = null;

        for (int i = 0; i < request.length; i++) {
            if (i + 3 <= request.length) {
                if (request[i] == 13 && request[i + 1] == 10 && request[i + 2] == 13 && request[i + 3] == 10) {
                    offset = i + 4; //Got a \r\n\r\n
                }
            }
        }

        if (offset != 0 && offset < request.length) {
            body = new byte[request.length - offset];
            int cont = 0;
            for (int i = offset; i < request.length; i++) {
                body[cont] = request[i];
                cont++;
            }
        }
        return body;
    }

    /*
     * Retrieve the cookies header field from a request/response
     */
    public static String getCookies(byte[] request) {

        String requestStr = new String(request);
        String cookies = "";

        if (requestStr.contains("Cookie:")) {
            cookies = requestStr.substring(requestStr.indexOf("Cookie:"));
            cookies = cookies.substring(7, cookies.indexOf("\r\n")).trim();
        }

        return cookies;
    }

    /*
     * Retrieve the content of a given wordlist
     */
    public static String[] retrieveWordlist(File file, PrintWriter stdOut, PrintWriter stdErr) {

        ArrayList lineIter = new ArrayList();
        try {
            FileInputStream fstream = new FileInputStream(file);
            DataInputStream in = new DataInputStream(fstream);
            BufferedReader br = new BufferedReader(new InputStreamReader(in));
            String strLine;
            while ((strLine = br.readLine()) != null) {
                lineIter.add(strLine);
            }
            in.close();
        } catch (Exception ioe) {
            stdErr.println("[!] Blazer GenericUtil Exception: " + ioe.toString().trim());
        }

        String[] strArray = new String[lineIter.size()];
        return (String[]) lineIter.toArray(strArray);
    }

    /*
     * Retrieve the proxy settings from Burp's configuration dump
     * E.g. "proxy.listener0 => 1.8888.1.0..0.0.1.0..0..0."
     */
    public static String burpProxySettings(Map configs) {
        String[] fields;
        String burpHost = "", burpPort = "";
        //Search the first active listener
        for (int i = 0; i < configs.size(); i++) {
            if (configs.containsKey("proxy.listener" + i)) {
                fields = ((String) (configs.get("proxy.listener" + i))).split("\\.");
                if (fields[0].equalsIgnoreCase("1")) {
                    //Retrieve the port value
                    burpPort = fields[1];
                    //Retrieve the host value
                    String fullHost = fields[2];
                    if (fullHost.charAt(0) == '1') {
                        burpHost = "127.0.0.1"; //localhost
                    } else if (fullHost.charAt(0) == '0') {
                        burpHost = "127.0.0.1"; //all interfaces, use localhost
                    } else if (fullHost.charAt(0) == '2') {
                        burpHost = fullHost.substring(1); //custom network interface
                        if (burpHost.contains("|")) { //In case, convert | back to .
                            burpHost = burpHost.replaceAll("\\|", ".");
                        }
                    }
                }
            }
        }
        return burpHost + ":" + burpPort;
    }

    /*
     * String repeat basic implementation
     */
    public static String repeat(String str, int times) {

        if (str == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < times; i++) {
            sb.append(str);
        }
        return sb.toString();
    }
}

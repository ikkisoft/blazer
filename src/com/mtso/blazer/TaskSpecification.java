/*
 * TaskSpecification.java
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

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;

/*
 * This class represents the gray-box testing task, containing all configurations and status
 */
class TaskSpecification {

    /* Status attributes */
    static final int STARTED = 1;
    static final int PAUSED = 2;
    static final int STOPPED = 3;
    private int status;

    /* Configuration attributes */
    private String proxyHost = "";
    private String proxyPort = "";
    private ArrayList libraries;
    private ArrayList signatures;
    private boolean fuzzing = false;
    private int threads = 1;
    private int permutations = 5;
    private float vectorsLikelihood = 50;
    private ArrayList vectors;
    // Data pools for primitive types
    private ArrayList bytePool;
    private ArrayList shortPool;
    private ArrayList intPool;
    private ArrayList longPool;
    private ArrayList floatPool;
    private ArrayList doublePool;
    private ArrayList booleanPool;
    private ArrayList charPool;
    private ArrayList stringPool;

    /* Request attributes*/
    private String cookies = "";
    private String endpoint = "";

    /* Standard output/error attributes*/
    private PrintWriter stdOut;
    private PrintWriter stdErr;

    protected TaskSpecification(PrintWriter stdOut, PrintWriter stdErr) {
        this.stdOut = stdOut;
        this.stdErr = stdErr;
        libraries = new ArrayList();
        signatures = new ArrayList();
        proxyHost = "";
        proxyPort = "";
        vectors = new ArrayList();
        vectors.add(""); //bogus value for generation only 
        bytePool = new ArrayList();
        shortPool = new ArrayList();
        intPool = new ArrayList();
        longPool = new ArrayList();
        floatPool = new ArrayList();
        doublePool = new ArrayList();
        booleanPool = new ArrayList();
        charPool = new ArrayList();
        stringPool = new ArrayList();
        this.status = STOPPED;
    }

    protected void setStatus(int status) {
        this.status = status;
    }

    protected int getStatus() {
        return status;
    }

    protected void setLibraries(final File resource) {
        if (!libraries.contains(resource)) {
            libraries.add(resource);

            if (resource.getName().endsWith(".jar")) {
                try {
                    addSignatures(JavaUtil.retrieveSignaturesFromJAR(resource, signatures.size()));
                } catch (Exception ex) {
                    stdErr.println("[!] Blazer TaskSpecification retrieveSignaturesFromJAR Exception: " + ex.toString().trim());
                }
            } else if (resource.getName().endsWith(".class")) {
                try {
                    addSignatures(JavaUtil.retrieveSignaturesFromClass(resource, signatures.size()));
                } catch (Exception ex) {
                    stdErr.println("[!] Blazer TaskSpecification retrieveSignaturesFromClass Exception: " + ex.toString().trim());;
                }
            } else if (resource.getName().endsWith(".java")) {
                try {
                    addSignatures(JavaUtil.retrieveSignaturesFromSrc(resource, signatures.size()));
                } catch (Exception ex) {
                    stdErr.println("[!] Blazer TaskSpecification retrieveSignaturesFromSrc Exception: " + ex.toString().trim());;
                }
            }
        }
    }

    protected ArrayList getLibraries() {
        return libraries;
    }

    protected void resetLibraries() {
        libraries = new ArrayList();
    }

    protected void resetSignatures() {
        signatures = new ArrayList();
    }

    protected void resetVectors() {
        vectors = new ArrayList();
    }

    protected void setSignatures(ArrayList signatures) {
        this.signatures = signatures;
    }

    protected void addSignatures(ArrayList signatures) {
        this.signatures.addAll(signatures);
    }

    protected ArrayList getSignatures() {
        return signatures;
    }

    protected void setThreads(int threads) {
        this.threads = threads;
    }

    protected int getThreads() {
        return threads;
    }

    protected void setPermutations(int permutations) {
        this.permutations = permutations;
    }

    protected int getPermutations() {
        return permutations;
    }

    protected void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    protected String getProxyHost() {
        return proxyHost;
    }

    protected void setProxyPort(String proxyPort) {
        this.proxyPort = proxyPort;
    }

    protected String getProxyPort() {
        return proxyPort;
    }

    protected void setCookies(String cookies) {
        this.cookies = cookies;
    }

    protected String getCookies() {
        return cookies;
    }

    protected void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    protected String getEndpoint() {
        return endpoint;
    }

    protected void setVectorsLikehood(int vectorsLikelihood) {
        this.vectorsLikelihood = vectorsLikelihood;
    }

    protected float getVectorsLikehood() {
        return vectorsLikelihood;
    }

    protected void setVectors(ArrayList vectors) {
        this.vectors = vectors;
    }

    protected ArrayList getVectors() {
        return vectors;
    }

    protected void setFuzzing(boolean fuzzing) {
        this.fuzzing = fuzzing;
    }

    protected boolean doFuzzing() {
        return fuzzing;
    }

    protected void setBytePool(ArrayList bytePool) {
        this.bytePool = bytePool;
    }

    protected ArrayList getBytePool() {
        return bytePool;
    }

    protected void setShortPool(ArrayList shortPool) {
        this.shortPool = shortPool;
    }

    protected ArrayList getShortPool() {
        return shortPool;
    }

    protected void setIntPool(ArrayList intPool) {
        this.intPool = intPool;
    }

    protected ArrayList getIntPool() {
        return intPool;
    }

    protected void setLongPool(ArrayList longPool) {
        this.longPool = longPool;
    }

    protected ArrayList getLongPool() {
        return longPool;
    }

    protected void setFloatPool(ArrayList floatPool) {
        this.floatPool = floatPool;
    }

    protected ArrayList getFloatPool() {
        return floatPool;
    }

    protected void setDoublePool(ArrayList doublePool) {
        this.doublePool = doublePool;
    }

    protected ArrayList getDoublePool() {
        return doublePool;
    }

    protected void setBooleanPool(ArrayList booleanPool) {
        this.booleanPool = booleanPool;
    }

    protected ArrayList getBooleanPool() {
        return booleanPool;
    }

    protected void setCharPool(ArrayList charPool) {
        this.charPool = charPool;
    }

    protected ArrayList getCharPool() {
        return charPool;
    }

    protected void setStringPool(ArrayList stringPool) {
        this.stringPool = stringPool;
    }

    protected ArrayList getStringPool() {
        return stringPool;
    }
}

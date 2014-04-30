/*
 * MessageSkeleton.java
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

import java.util.Vector;

/*
 * This class contains the skeleton of a basic AMF request
 */
public class MessageSkeleton {

    private String destination;
    private String operation;
    private Vector parameters;
    private String parSignatures;

    public MessageSkeleton(String destination, String operation, String parSignatures) {
        this.destination = destination;
        this.operation = operation;
        this.parameters = new Vector();
        this.parSignatures = parSignatures;
    }

    /*
     * This method is supposed to be used through BeanShell only
     */
    protected MessageSkeleton(String destination, String operation) {
        this.destination = destination;
        this.operation = operation;
        this.parameters = new Vector();
        this.parSignatures = null;
    }

    public String getDestination() {
        return destination;
    }

    public String getOperation() {
        return operation;
    }

    public String getParSignatures() {
        return parSignatures;
    }

    public String getPacketString() {
        return destination + ":" + operation + ":" + parameters.toString() + System.currentTimeMillis();
    }

    public boolean addPar(Object par) {
        return this.parameters.add(par);
    }

    public Vector getPars() {
        return this.parameters;
    }

    public void resetPars() {
        this.parameters.clear();
    }

    public int getParsSize() {
        return this.parameters.size();
    }
}
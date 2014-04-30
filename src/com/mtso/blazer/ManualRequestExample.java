/*
 * ManualRequestExample.java
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

import java.io.PrintWriter;

/**
 * A basic example on how to use Blazer from a stand-alone Java program
 *
 * Custom clients can use "com.mtso.blazer.MessageGenerator" and
 * "com.mtso.blazer.MessageSkeleton" to build and send valid AMF messages
 */
public class ManualRequestExample {

    public static void main(String[] args) {
        // blazeds-turnkey-4.0.1.21287 test-case
        MessageGenerator myGen = new MessageGenerator("127.0.0.1", "8080", "http://127.0.0.1:8400/samples/messagebroker/amf", "fakeCookie", new PrintWriter(System.out), new PrintWriter(System.err));
        MessageSkeleton message = new MessageSkeleton("productService", "getProductsByName");
        //add your custom parameters here!
        message.addPar("Nokia");
        myGen.send(message);
    }
}

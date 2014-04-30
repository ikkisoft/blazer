/*
 * AMFUtil.java
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

import flex.messaging.io.SerializationContext;
import flex.messaging.io.amf.ActionContext;
import flex.messaging.io.amf.ActionMessage;
import flex.messaging.io.amf.AmfMessageDeserializer;
import flex.messaging.messages.RemotingMessage;
import java.io.ByteArrayInputStream;
import java.io.PrintWriter;

/*
 * This class implements multiple AMF auxiliary utils
 */
public class AMFUtil {

    /*
     * Verify that the request contains a valid AMF message.
     * The "Content-Type" header can also be used, however this is more reliable
     */
    public static boolean isAMF(byte[] request, PrintWriter stdOut, PrintWriter stdErr) {

        Object[] out;
        byte[] requestBody;

        SerializationContext serialContext = SerializationContext.getSerializationContext();
        AmfMessageDeserializer localAmfMessageDeserializer = new AmfMessageDeserializer();
        requestBody = GenericUtil.getBody(request);
        try {
            localAmfMessageDeserializer.initialize(serialContext, new ByteArrayInputStream(requestBody, 0, requestBody.length), null);
            ActionMessage localActionMessage = new ActionMessage();
            localAmfMessageDeserializer.readMessage(localActionMessage, new ActionContext());
            //Expecting at least one "flex.messaging.messages.RemotingMessage". Note that messages can be encapsulated
            for (int i = 0; i < localActionMessage.getBodyCount(); i++) {
                out = (Object[]) localActionMessage.getBody(i).getData();
                for (int j = 0; j < out.length; j++) {
                    if (out[j] instanceof RemotingMessage) {
                        return true;
                    }
                }
            }
        } catch (flex.messaging.MessageException exM) {
            if (exM.getCode().equalsIgnoreCase("Client.Message.Encoding")) {
                //Something wrong while deserializating. Custom objects?
                stdErr.println("[!] Blazer isAMF Exception: " + exM.toString().trim());
                return true; //load Blazer anyway
            } else {
                return false;
            }
        } catch (Exception ex) {
            stdErr.println("[!] Blazer isAMF Exception: " + ex.toString().trim());
            stdErr.println("[!] Does the request contain a valid 'flex.messaging.messages.RemotingMessage' ?!?");
            return false;
        }
        return false;
    }

    /*
     * Extract ActionMessage from an HTTP request/response
     */
    public static ActionMessage extractAM(byte[] reqresp, PrintWriter stdOut, PrintWriter stdErr) {

        ActionMessage localActionMessage = null;

        SerializationContext serialContext = SerializationContext.getSerializationContext();
        AmfMessageDeserializer localAmfMessageDeserializer = new AmfMessageDeserializer();
        byte[] body = GenericUtil.getBody(reqresp);

        try {
            localAmfMessageDeserializer.initialize(serialContext, new ByteArrayInputStream(body, 0, body.length), null);
            localActionMessage = new ActionMessage();
            localAmfMessageDeserializer.readMessage(localActionMessage, new ActionContext());
        } catch (Exception ex) {
            stdErr.println("[!] Blazer extractAM Exception: " + ex.toString().trim());
        }
        return localActionMessage;
    }
}

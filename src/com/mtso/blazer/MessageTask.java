/*
 * MessageTask.java
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

/*
 * This class is responsible for the actual object generation and trasmission
 */
class MessageTask extends NotifyingThread implements Comparable {

    private ObjectGenerator testCaseObj;
    private int objPermutations;
    private MessageSkeleton msgSpecification;
    private MessageGenerator msgGenerator;
    private boolean threadPaused;
    private boolean threadStopped;

    protected MessageTask(ObjectGenerator testCaseObj, int objPermutations, MessageSkeleton msgSpecification, MessageGenerator msgGenerator) {
        this.testCaseObj = testCaseObj;
        this.objPermutations = objPermutations;
        this.msgSpecification = msgSpecification;
        this.msgGenerator = msgGenerator;
        threadPaused = false;
        threadStopped = false;
    }

    @Override
    protected void doRun() {

        int permCounter = 0;

        threadIteration:
        // Iterate for all requested permutations
        while (permCounter < objPermutations) {

            msgSpecification.resetPars();

            //  Generate method's parameters as in the signature
            String[] argSignatures = msgSpecification.getParSignatures().split(",");
            for (int argCont = 0; argCont < argSignatures.length; argCont++) {
                if (!argSignatures[argCont].isEmpty()) {
                    Object tcObj = testCaseObj.generate(argSignatures[argCont].trim());
                    msgSpecification.addPar(tcObj);
                }
            }

            msgGenerator.send(msgSpecification);
            TaskManager.oneMoreDone();
            permCounter++;

            //Occasionally, check if we need to pause the thread
            synchronized (this) {
                if (threadStopped) {
                    break threadIteration;
                }
                while (threadPaused) {
                    try {
                        wait();
                    } catch (InterruptedException ie) {
                    }
                }
            }

        }
        //All iterations completed, it's time to disconnect the AMFConnection
        msgGenerator.disconnectAll();
    }

    // compareTo() implementation to allow array sorting
    public int compareTo(Object o) {
        MessageTask obj = (MessageTask) o;
        if (this.getId() < obj.getId()) {
            return -1;
        } else if (this.getId() > obj.getId()) {
            return 1;
        } else {
            return 0;
        }
    }

    protected void pauseThread() {
        threadPaused = true;
    }

    protected void resumeThread() {
        threadPaused = false;
    }

    protected void stopThread() {
        threadStopped = true;
    }
}

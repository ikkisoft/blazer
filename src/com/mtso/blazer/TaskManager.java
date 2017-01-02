/*
 * TaskManager.java
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
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import java.beans.PropertyChangeSupport;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

/*
 * This class is the core component of Blazer.
 * It creates and validates testing tasks. Also, it is responsible for starting
 * and monitoring task instances.
 */
public class TaskManager implements ThreadCompleteListener {

    private IBurpExtenderCallbacks burpCallbacks;
    private IHttpRequestResponse requestResponse;
    private IHttpRequestResponse[] itemsUserSelection;
    private TaskSpecification currentTask;
    private MessageTask[] threadsContainer;
    private int threadsTracker = 0;
    private static PropertyChangeSupport pcs;
    //Custom stdOut and stdErr used by PrintWriter
    private PrintWriter stdout;
    private PrintWriter stderr;

    /* Runtime metrics */
    private static int requestsDone = 0;
    private long startTime = 0;

    public TaskManager(IBurpExtenderCallbacks burpCallbacks, IHttpRequestResponse[] requestResponse) throws Exception {

        Float majorVer = new Float(burpCallbacks.getBurpVersion()[1]);
        Float minorVer = new Float(0);
        if (burpCallbacks.getBurpVersion()[2] != null && !burpCallbacks.getBurpVersion()[2].isEmpty()) {
            minorVer = new Float(burpCallbacks.getBurpVersion()[2]);
        }

        //If running Burp Suite >= [Burp Suite Professional][1.5].[01], enable custom Stdout and Stderr       
        if (majorVer >= 1.5 && minorVer >= 1.0) {
            //new registerExtenderCallbacks interface
            burpCallbacks.setExtensionName(BurpExtender.getBanner());
            stdout = new PrintWriter(burpCallbacks.getStdout(), true);
            stderr = new PrintWriter(burpCallbacks.getStderr(), true);
        } else {
            //old registerExtenderCallbacks interface
            stdout = new PrintWriter(System.out, true);
            stderr = new PrintWriter(System.err, true);
        }

        this.burpCallbacks = burpCallbacks;
        this.itemsUserSelection = requestResponse;
        this.requestResponse = requestResponse[0]; //for generation/fuzzing, we use the first selected request to retrieve endpoint, cookies, ...

        pcs = new PropertyChangeSupport(this);

        currentTask = new TaskSpecification(this.getStdOut(), this.getStdErr());
        String[] proxySettings = GenericUtil.burpProxySettings(burpCallbacks.saveConfig()).split(":");
        currentTask.setProxyHost(proxySettings[0]);
        currentTask.setProxyPort(proxySettings[1]);
        currentTask.setCookies(GenericUtil.getCookies(this.requestResponse.getRequest()));
        currentTask.setEndpoint(this.burpCallbacks.getHelpers().analyzeRequest(this.requestResponse).getUrl().toString());
    }

    public PrintWriter getStdOut() {
        return stdout;
    }

    public PrintWriter getStdErr() {
        return stderr;
    }

    public void issueAlert(String msg) {
        burpCallbacks.issueAlert(msg);
    }

    protected TaskSpecification getTask() {
        return currentTask;
    }

    protected PropertyChangeSupport getPropertyChangeSupport() {
        return pcs;
    }

    protected void startCurrentTask() throws InterruptedException {

        if (!currentTask.doFuzzing()) {
            burpCallbacks.issueAlert("[Blazer] Starting current task (generation only)");
        } else {
            burpCallbacks.issueAlert("[Blazer] Starting current task (fuzzing)");
        }
        currentTask.setStatus(TaskSpecification.STARTED);
        //Reset metrics
        startTime = System.currentTimeMillis();
        requestsDone = 0;

        ArrayList listAttack = currentTask.getVectors();
        ArrayList listSign = currentTask.getSignatures();

        // Create the threads container with the minimum number of elements
        threadsContainer = new MessageTask[Math.min(currentTask.getThreads(), listAttack.size() * getSignaturesSelectedCounter())];

        for (int aCont = 0; aCont < listAttack.size(); aCont++) { //For all attack vectors. Bogus value in case of a generation task.
            ObjectGenerator testCaseObj = null;
            if (!currentTask.doFuzzing()) {
                testCaseObj = new ObjectGenerator(currentTask, null, this.getStdOut(), this.getStdErr());
            } else {
                testCaseObj = new ObjectGenerator(currentTask, (String) listAttack.get(aCont), this.getStdOut(), this.getStdErr());
            }

            for (int sCont = 0; sCont < listSign.size(); sCont++) { // For all destinations/operations
                if (currentTask.getStatus() == TaskSpecification.STARTED) {
                    Object[] row = (Object[]) listSign.get(sCont);
                    Boolean row0 = (Boolean) row[0];
                    if (row0.booleanValue()) { // Choose selected signatures only
                        if (threadsTracker < currentTask.getThreads()) {

                            MessageGenerator mGen = new MessageGenerator(currentTask.getProxyHost(), currentTask.getProxyPort(), currentTask.getEndpoint(), currentTask.getCookies(), this.getStdOut(), this.getStdErr());
                            MessageSkeleton mSpec = new MessageSkeleton((String) row[3], (String) row[4], (String) row[5]);

                            threadsContainer[threadsTracker] = new MessageTask(testCaseObj, currentTask.getPermutations(), mSpec, mGen);
                            threadsContainer[threadsTracker].addListener(this);
                            threadsContainer[threadsTracker].start();
                            threadsContainer[threadsTracker].setName(String.valueOf(threadsContainer[threadsTracker].getId()));
                            threadsTracker++;
                        } else {
                            Thread.sleep(4000);
                            sCont--; //no threads available, repeat the same item
                        }
                    }
                }
            }
        }
    }

    public void notifyOfThreadComplete(Thread thread) {
        //First, reorder the threads container
        thread.setName(String.valueOf(Long.MAX_VALUE));
        Arrays.sort(threadsContainer);
        threadsTracker--;

        if (threadsTracker == 0 && requestsDone == getRequestsTot()) {
            //All thread finished
            currentTask.setStatus(TaskSpecification.STOPPED);
            pcs.firePropertyChange("taskStopped", null, null);
        }
    }

    protected void pauseCurrentTask() {
        burpCallbacks.issueAlert("[Blazer] Pausing current task");
        currentTask.setStatus(TaskSpecification.PAUSED);

        for (int threadsCont = 0; threadsCont < threadsContainer.length; threadsCont++) {
            if (threadsContainer[threadsCont] != null) {
                synchronized (threadsContainer[threadsCont]) {
                    threadsContainer[threadsCont].pauseThread();
                }
            }
        }
    }

    protected void resumeCurrentTask() {
        burpCallbacks.issueAlert("[Blazer] Resuming current task");
        currentTask.setStatus(TaskSpecification.STARTED);

        for (int threadsCont = 0; threadsCont < threadsContainer.length; threadsCont++) {
            if (threadsContainer[threadsCont] != null) {
                synchronized (threadsContainer[threadsCont]) {
                    threadsContainer[threadsCont].resumeThread();
                    threadsContainer[threadsCont].notify();
                }
            }
        }
    }

    protected void stopCurrentTask() {
        burpCallbacks.issueAlert("[Blazer] Stopping current task");
        currentTask.setStatus(TaskSpecification.STOPPED);

        for (int threadsCont = 0; threadsCont < threadsContainer.length; threadsCont++) {
            if (threadsContainer[threadsCont] != null) {
                synchronized (threadsContainer[threadsCont]) {
                    threadsContainer[threadsCont].stopThread();
                }
            }
        }

        pcs.firePropertyChange("taskStopped", null, null);
        try {
            Thread.sleep(1000);
        } catch (InterruptedException ie) {
            this.getStdErr().println("[!] InterruptedException - Connection: " + ie.toString().trim());
        }
        //reset all TaskManager variables
        threadsTracker = 0;
        requestsDone = 0;
        startTime = 0;
    }

    protected static void oneMoreDone() {
        requestsDone = requestsDone + 1;
        pcs.firePropertyChange("requestsDone", null, null);
    }

    protected int getRequestsDone() {
        return requestsDone;
    }

    protected int getRequestsTot() {
        if (currentTask.getVectors() != null) {
            return (currentTask.getVectors().size() * getSignaturesSelectedCounter() * currentTask.getPermutations());
        }else{
            return 0;
        }
    }

    protected float getAverageSpeed() {
        if (getOverallTime() > 2) { //wait first 2 seconds to a get better estimate
            return (getRequestsDone() / getOverallTime());
        }
        return 0;
    }

    protected float getOverallTime() {
        float diffTime = System.currentTimeMillis() - startTime;
        return (diffTime / 1000);
    }

    protected float getTimeToFinish() {
        int diffReq = getRequestsTot() - getRequestsDone();
        if (getAverageSpeed() != 0) {
            return (float) (diffReq / (Math.round(getAverageSpeed()) + 0.1));
        }
        return 0;
    }

    protected boolean isReady() {

        if (!currentTask.getLibraries().isEmpty() && !currentTask.getSignatures().isEmpty()
                && !currentTask.getProxyHost().isEmpty() && !currentTask.getProxyPort().isEmpty()
                && currentTask.getThreads() >= 1 && currentTask.getPermutations() >= 1
                && currentTask.getVectorsLikehood() >= 1 && !currentTask.getVectors().isEmpty()
                && !currentTask.getBytePool().isEmpty() && !currentTask.getShortPool().isEmpty()
                && !currentTask.getIntPool().isEmpty() && !currentTask.getLongPool().isEmpty()
                && !currentTask.getFloatPool().isEmpty() && !currentTask.getDoublePool().isEmpty()
                && !currentTask.getBooleanPool().isEmpty() && !currentTask.getCharPool().isEmpty()
                && !currentTask.getStringPool().isEmpty() && !currentTask.getEndpoint().isEmpty()) {

            //At least a signature should be selected
            if (getSignaturesSelectedCounter() != 0) {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    protected int getSignaturesSelectedCounter() {
        int cont = 0;
        Iterator listSign = currentTask.getSignatures().iterator();
        while (listSign.hasNext()) {
            Boolean row = (Boolean) ((Object[]) listSign.next())[0];
            if (row.booleanValue()) {
                cont = cont + 1;
            }
        }
        return cont;
    }

    protected IHttpRequestResponse[] getItemsUserSelection() {
        return itemsUserSelection;
    }
}

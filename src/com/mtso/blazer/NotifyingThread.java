/*
 * NotifyingThread.java
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

import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

/*
 * This class extends thread to implement a notification mechanism.
 * Based on http://stackoverflow.com/a/702460
 */
abstract class NotifyingThread extends Thread {

    private final Set<ThreadCompleteListener> listeners = new CopyOnWriteArraySet<ThreadCompleteListener>();

    protected final void addListener(final ThreadCompleteListener listener) {
        listeners.add(listener);
    }

    protected final void removeListener(final ThreadCompleteListener listener) {
        listeners.remove(listener);
    }

    protected final void notifyListeners() {
        for (ThreadCompleteListener listener : listeners) {
            listener.notifyOfThreadComplete(this);
        }
    }

    @Override
    public final void run() {
        try {
            doRun();
        } finally {
            notifyListeners();
        }
    }

    protected abstract void doRun();
}
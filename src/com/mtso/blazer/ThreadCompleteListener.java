/*
 * ThreadCompleteListener.java
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
 * This interface is used to implement a basic thread notification mechanism.
 * Based on http://stackoverflow.com/a/702460
 */
interface ThreadCompleteListener {

    void notifyOfThreadComplete(final Thread thread);
}

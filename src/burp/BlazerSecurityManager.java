/*
 * BlazerSecurityManager.java
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
package burp;

import com.mtso.blazer.TaskManager;
import java.io.FileDescriptor;
import java.net.InetAddress;
import java.security.Permission;

/**
 * This is a custom Java SecurityManager used to limit operations originated
 * from com.mtso.blazer.ObjectGenerato.generate()
 */
public class BlazerSecurityManager extends SecurityManager {

    private TaskManager manager;

    public BlazerSecurityManager(TaskManager manager) {
        super();
        this.manager = manager;
    }

    public void detectException(String checkName) {
        for (StackTraceElement elem : Thread.currentThread().getStackTrace()) {
            if ("com.mtso.blazer.ObjectGenerator".equals(elem.getClassName()) && "generate".equals(elem.getMethodName())) {
                manager.issueAlert("[Blazer] SecurityManager: UNAUTHORIZED OPERATION detected by " + checkName);
                manager.issueAlert("[Blazer] SecurityManager will shutdown all Java processes to prevent a potentially dangerous operation");
                manager.getStdErr().println("[!] BlazerSecurityManager ---------> UNAUTHORIZED OPERATION detected by " + checkName);
                manager.getStdErr().println("[!] Blazer will shutdown all Java processes to prevent a potentially dangerous operation");
                for(int i=10; i>=0; i=i-1){
                    manager.issueAlert("[Blazer] Shutdown in " + i);
                    manager.getStdErr().println("[!] Shutdown in " + i);
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ex) {
                        System.exit(-1); //Emergency shutdown 
                    }
                }
                System.exit(-1); //Emergency shutdown 
            }
        }
    }

    public void detectException(String checkName, Permission perm) {
        for (StackTraceElement elem : Thread.currentThread().getStackTrace()) {
            if ("com.mtso.blazer.ObjectGenerator".equals(elem.getClassName()) && "generate".equals(elem.getMethodName())) {
                manager.getStdOut().println("[*] BlazerSecurityManager permissions monitor --> " + perm.toString());
            }
        }
    }

    /*
     * To customize permissions, please refer to http://docs.oracle.com/javase/1.5.0/docs/api/java/lang/SecurityManager.html
     */
    @Override
    public void checkPermission(Permission perm) {
        detectException("checkPermission", perm);
        super.checkPermission(perm);
    }

    @Override
    public void checkPermission(Permission perm, Object context) {
        detectException("checkPermission", perm);
        super.checkPermission(perm, context);
    }

    @Override
    public void checkCreateClassLoader() {
        detectException("checkCreateClassLoader");
        super.checkCreateClassLoader();
    }

    @Override
    public void checkAccess(Thread t) {
        super.checkAccess(t);
    }

    @Override
    public void checkAccess(ThreadGroup g) {
        super.checkAccess(g);
    }

    @Override
    public void checkExit(int status) {
        super.checkExit(status);
    }

    @Override
    public void checkExec(String cmd) {
        detectException("checkExec");
        super.checkExec(cmd);
    }

    @Override
    public void checkLink(String lib) {
        detectException("checkLink");
        super.checkLink(lib);
    }

    @Override
    public void checkRead(FileDescriptor fd) {
        super.checkRead(fd);
    }

    @Override
    public void checkRead(String file) {
        super.checkRead(file);
    }

    @Override
    public void checkRead(String file, Object context) {
        super.checkRead(file, context);
    }

    @Override
    public void checkWrite(FileDescriptor fd) {
        detectException("checkWrite");
        super.checkWrite(fd);
    }

    @Override
    public void checkWrite(String file) {
        detectException("checkWrite");
        super.checkWrite(file);
    }

    @Override
    public void checkDelete(String file) {
        detectException("checkDelete");
        super.checkDelete(file);
    }

    @Override
    public void checkConnect(String host, int port) {
        detectException("checkConnect");
        super.checkConnect(host, port);
    }

    @Override
    public void checkConnect(String host, int port, Object context) {
        detectException("checkConnect");
        super.checkConnect(host, port, context);
    }

    @Override
    public void checkListen(int port) {
        detectException("checkListen");
        super.checkListen(port);
    }

    @Override
    public void checkAccept(String host, int port) {
        detectException("checkAccept");
        super.checkAccept(host, port);
    }

    @Override
    public void checkMulticast(InetAddress maddr) {
        detectException("checkMulticast");
        super.checkMulticast(maddr);
    }

    @Override
    public void checkPropertiesAccess() {
        detectException("checkPropertiesAccess");
        super.checkPropertiesAccess();
    }

    @Override
    public void checkPropertyAccess(String key) {
        super.checkPropertyAccess(key);
    }

    @Override
    public boolean checkTopLevelWindow(Object window) {
        return super.checkTopLevelWindow(window);
    }

    @Override
    public void checkPrintJobAccess() {
        super.checkPrintJobAccess();
    }

    @Override
    public void checkSystemClipboardAccess() {
        super.checkSystemClipboardAccess();
    }

    @Override
    public void checkAwtEventQueueAccess() {
        super.checkAwtEventQueueAccess();
    }

    @Override
    public void checkPackageAccess(String pkg) {
        super.checkPackageAccess(pkg);
    }

    @Override
    public void checkPackageDefinition(String pkg) {
        super.checkPackageDefinition(pkg);
    }

    @Override
    public void checkSetFactory() {
        detectException("checkSetFactory");
        super.checkSetFactory();
    }

    @Override
    public void checkMemberAccess(Class<?> clazz, int which) {
        super.checkMemberAccess(clazz, which);
    }

    @Override
    public void checkSecurityAccess(String target) {
        detectException("checkSecurityAccess");
        super.checkSecurityAccess(target);
    }
}

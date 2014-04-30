/*
 * ObjectGenerator.java
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
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Random;
import java.util.regex.Pattern;

/*
 * This class generates Java Objects from signatures
 */
public class ObjectGenerator {

    private TaskSpecification task = null;
    private Object artifact = null;
    private SecureRandom rnd = null;
    private ArrayList pool = null;
    private PrintWriter stdOut;
    private PrintWriter stdErr;
    private URLClassLoader ucl = null;

    /*
     * Construct an object generator given a specific task, containing attack vectors and likelihood factor.
     * 
     * In case of generation tasks, the 'vectors' ArrayList should be empty. The 'vectorLikelihood' is the
     * percentuage of attack vectors in the String pool, used to unbalance the selection of samples
     */
    protected ObjectGenerator(TaskSpecification task, String attackVector, PrintWriter stdOut, PrintWriter stdErr) {

        this.stdOut = stdOut;
        this.stdErr = stdErr;
        this.task = task;
        rnd = new SecureRandom();
        pool = (ArrayList) task.getStringPool().clone();


        if (!task.doFuzzing()) {
            //Generation only - do nothing
        } else {
            //Fuzzing - unbalance the String pool adding % attack vectors 
            float poolSize = pool.size();
            int addCounter = StrictMath.abs(StrictMath.round(((poolSize / ((100 - task.getVectorsLikehood()) / 100)) - poolSize)));
            for (int i = 0; i < addCounter; i++) {
                pool.add(attackVector);
            }
        }

        try {
            //Load application libraries at runtime
            Object[] applicationLibs = task.getLibraries().toArray();
            URL[] classUrls = new URL[applicationLibs.length];
            for (int lCont = 0; lCont < applicationLibs.length; lCont++) {
                String absoluteVodka = ((File) applicationLibs[lCont]).getCanonicalPath();
                if (absoluteVodka.endsWith(".jar")) {
                    classUrls[lCont] = (new File(absoluteVodka)).toURI().toURL(); //loading JARs
                } else if (absoluteVodka.endsWith(".class")) {
                    String classPathName = JavaUtil.retrieveCanonicalNameFromClass(((File) applicationLibs[lCont]));
                    if (File.separator.equalsIgnoreCase("/")) {
                        classPathName = classPathName.replaceAll("\\.", "/") + ".class";
                    } else {
                        classPathName = classPathName.replaceAll("\\.", "\\\\") + ".class";
                    }
                    absoluteVodka = absoluteVodka.replaceAll(Pattern.quote(classPathName), "");
                    classUrls[lCont] = (new File(absoluteVodka)).toURI().toURL(); //loading top directory containing selected classes
                }
            }

            ClassLoader cl = ClassLoader.getSystemClassLoader();
            if (cl instanceof URLClassLoader) {
                JavaUtil.addURLs(classUrls, stdOut, stdErr);
                ucl = (URLClassLoader) cl;
            } else {
                stdErr.println("[!] \"SystemClassLoader\" is not instance of \"URLClassLoader\"");
                stdErr.println("[!] BlazerSecurityManager won't work...");
                ucl = new URLClassLoader(classUrls);
            }
        } catch (MalformedURLException ex) {
            stdErr.println("[!] ObjectGenerator MalformedURLException: " + ex.toString().trim());
        } catch (NoSuchMethodException ex) {
            stdErr.println("[!] ObjectGenerator NoSuchMethodException: " + ex.toString().trim());
        } catch (IllegalArgumentException ex) {
            stdErr.println("[!] ObjectGenerator IllegalArgumentException: " + ex.toString().trim());
        } catch (IllegalAccessException ex) {
            stdErr.println("[!] ObjectGenerator IllegalAccessException: " + ex.toString().trim());
        } catch (InvocationTargetException ex) {
            stdErr.println("[!] ObjectGenerator InvocationTargetException: " + ex.toString().trim());
        } catch (IOException ex) {
            stdErr.println("[!] ObjectGenerator IOException: " + ex.toString().trim());
        }
    }

    protected Object generate(String signature) {

        artifact = null;
        Random methodRnd = new Random();

        if (signature.equals("boolean")) {
            artifact = task.getBooleanPool().get(rnd.nextInt(task.getBooleanPool().size()));
        } else if (signature.equals("boolean[]")) {
            boolean[] atemp = new boolean[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = ((Boolean) task.getBooleanPool().get(rnd.nextInt(task.getBooleanPool().size()))).booleanValue();
            }
            artifact = atemp;
        } else if (signature.equals("java.lang.Boolean")) {
            artifact = (Boolean) task.getBooleanPool().get(rnd.nextInt(task.getBooleanPool().size()));
        } else if (signature.equals("java.lang.Boolean[]")) {
            Boolean[] atemp = new Boolean[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = (Boolean) task.getBooleanPool().get(rnd.nextInt(task.getBooleanPool().size()));
            }
            artifact = atemp;
        } else if (signature.equals("int")) {
            artifact = task.getIntPool().get(rnd.nextInt(task.getIntPool().size()));
        } else if (signature.equals("int[]")) {
            int[] atemp = new int[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = ((Integer) task.getIntPool().get(rnd.nextInt(task.getIntPool().size()))).intValue();
            }
            artifact = atemp;
        } else if (signature.equals("java.lang.Integer")) {
            artifact = (Integer) task.getIntPool().get(rnd.nextInt(task.getIntPool().size()));
        } else if (signature.equals("java.lang.Integer[]")) {
            Integer[] atemp = new Integer[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = (Integer) task.getIntPool().get(rnd.nextInt(task.getIntPool().size()));
            }
            artifact = atemp;
        } else if (signature.equalsIgnoreCase("java.lang.String") || (signature.equalsIgnoreCase("java.lang.Object"))) { //In case of Object, handle as String
            artifact = pool.get(rnd.nextInt(pool.size()));
        } else if (signature.equalsIgnoreCase("java.lang.String[]") || (signature.equalsIgnoreCase("java.lang.Object[]"))) { //In case of Object, handle as String
            String[] atemp = new String[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = (String) pool.get(rnd.nextInt(pool.size()));
            }
            artifact = atemp;
        } else if (signature.equals("byte")) {
            artifact = task.getBytePool().get(rnd.nextInt(task.getBytePool().size()));
        } else if (signature.equals("byte[]")) {
            byte[] atemp = new byte[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = ((Byte) task.getBytePool().get(rnd.nextInt(task.getBytePool().size()))).byteValue();
            }
            artifact = atemp;
        } else if (signature.equals("java.lang.Byte")) {
            artifact = (Byte) task.getBytePool().get(rnd.nextInt(task.getBytePool().size()));
        } else if (signature.equals("java.lang.Byte[]")) {
            Byte[] atemp = new Byte[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = (Byte) task.getBytePool().get(rnd.nextInt(task.getBytePool().size()));
            }
            artifact = atemp;
        } else if (signature.equals("short")) {
            artifact = task.getShortPool().get(rnd.nextInt(task.getShortPool().size()));
        } else if (signature.equals("short[]")) {
            short[] atemp = new short[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = ((Short) task.getShortPool().get(rnd.nextInt(task.getShortPool().size()))).shortValue();
            }
            artifact = atemp;
        } else if (signature.equals("java.lang.Short")) {
            artifact = (Short) task.getShortPool().get(rnd.nextInt(task.getShortPool().size()));
        } else if (signature.equals("java.lang.Short[]")) {
            Short[] atemp = new Short[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = (Short) task.getShortPool().get(rnd.nextInt(task.getShortPool().size()));
            }
            artifact = atemp;
        } else if (signature.equals("long")) {
            artifact = task.getLongPool().get(rnd.nextInt(task.getLongPool().size()));
        } else if (signature.equals("long[]")) {
            long[] atemp = new long[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = ((Long) task.getLongPool().get(rnd.nextInt(task.getLongPool().size()))).longValue();
            }
            artifact = atemp;
        } else if (signature.equals("java.lang.Long")) {
            artifact = (Long) task.getLongPool().get(rnd.nextInt(task.getLongPool().size()));
        } else if (signature.equals("java.lang.Long[]")) {
            Long[] atemp = new Long[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = (Long) task.getLongPool().get(rnd.nextInt(task.getLongPool().size()));
            }
            artifact = atemp;
        } else if (signature.equals("float")) {
            artifact = task.getFloatPool().get(rnd.nextInt(task.getFloatPool().size()));
        } else if (signature.equals("float[]")) {
            float[] atemp = new float[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = ((Float) task.getFloatPool().get(rnd.nextInt(task.getFloatPool().size()))).floatValue();
            }
            artifact = atemp;
        } else if (signature.equals("java.lang.Float")) {
            artifact = (Float) task.getFloatPool().get(rnd.nextInt(task.getFloatPool().size()));
        } else if (signature.equals("java.lang.Float[]")) {
            Float[] atemp = new Float[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = (Float) task.getFloatPool().get(rnd.nextInt(task.getFloatPool().size()));
            }
            artifact = atemp;
        } else if (signature.equals("double")) {
            artifact = task.getDoublePool().get(rnd.nextInt(task.getDoublePool().size()));
        } else if (signature.equals("double[]")) {
            double[] atemp = new double[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = ((Double) task.getDoublePool().get(rnd.nextInt(task.getDoublePool().size()))).doubleValue();
            }
            artifact = atemp;
        } else if (signature.equals("java.lang.Double")) {
            artifact = (Double) task.getDoublePool().get(rnd.nextInt(task.getDoublePool().size()));
        } else if (signature.equals("java.lang.Double[]")) {
            Double[] atemp = new Double[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = (Double) task.getDoublePool().get(rnd.nextInt(task.getDoublePool().size()));
            }
            artifact = atemp;
        } else if (signature.equals("char")) {
            artifact = task.getCharPool().get(rnd.nextInt(task.getCharPool().size()));
        } else if (signature.equals("char[]")) {
            char[] atemp = new char[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = ((Character) task.getCharPool().get(rnd.nextInt(task.getCharPool().size()))).charValue();
            }
            artifact = atemp;
        } else if (signature.equals("java.lang.Character")) {
            artifact = (Character) task.getCharPool().get(rnd.nextInt(task.getCharPool().size()));
        } else if (signature.equals("java.lang.Character[]")) {
            Character[] atemp = new Character[rnd.nextInt(10)];
            for (int i = 0; i < atemp.length; i++) {
                atemp[i] = (Character) task.getCharPool().get(rnd.nextInt(task.getCharPool().size()));
            }
            artifact = atemp;
        } else if (signature.equalsIgnoreCase("java.lang.Class")
                || signature.equalsIgnoreCase("java.lang.Class[]")
                || signature.equalsIgnoreCase("<init>")
                || signature.isEmpty()) {
            artifact = null; //avoid endless loop
        } else {
            /* Build a custom Object using reflection */
            Class<Object> fc = null;
            Object newObj = null;

            try {
                fc = (Class<Object>) ucl.loadClass(signature); //use our custom classloader, containing application libraries

                if (!fc.isInterface() && !fc.isEnum() && !fc.isAnnotation()) { //avoid interfaces
                    //create an instance of the Object using one of the declared constructor
                    Constructor cc[] = (fc.getConstructors());
                    Collections.shuffle(Arrays.asList(cc)); //fuzzing's magic sauce
                    building:
                    for (int cCont = 0; cCont < cc.length; cCont++) {
                        cc[cCont].setAccessible(true);
                        Class pcc[] = cc[cCont].getParameterTypes();
                        if (pcc.length == 0 || pcc == null) {
                            //Default constructor with no arguments
                            newObj = cc[cCont].newInstance();
                            break building;
                        } else {
                            //Iterate through all arguments for this constructor
                            Object[] parsInstance = new Object[pcc.length];
                            for (int pCont = 0; pCont < pcc.length; pCont++) {
                                String newSign = pcc[pCont].getCanonicalName();
                                if (!newSign.equalsIgnoreCase(signature)) { //Recursion watchdog
                                    parsInstance[pCont] = generate(newSign);
                                }
                            }
                            newObj = cc[cCont].newInstance(parsInstance);
                            break building;
                        }
                    }
                    //At this point, we need to populate all attributes of an Object
                    if (newObj != null) {
                        Method mc[] = fc.getDeclaredMethods();
                        Collections.shuffle(Arrays.asList(mc)); //fuzzing's magic sauce
                        //For all methods
                        for (int mCont = 0; mCont < mc.length; mCont++) {
                            //Do not invoke all methods for a specific class
                            //Soon or later, multiple iterations and randomness should help to build a valid object as required by the remote method
                            if (methodRnd.nextBoolean()) {
                                mc[mCont].setAccessible(true);
                                //For all parameters
                                Class pvec[] = mc[mCont].getParameterTypes();
                                Object[] parsInstance = null;
                                //Invoke methods (setters) having at least one argument
                                if (pvec.length > 0) {
                                    parsInstance = new Object[pvec.length];
                                    for (int pCont = 0; pCont < pvec.length; pCont++) {
                                        String newSign = pvec[pCont].getCanonicalName();
                                        if (!newSign.equalsIgnoreCase(signature)) {  //Recursion watchdog
                                            parsInstance[pCont] = generate(newSign);
                                        }
                                    }
                                    mc[mCont].invoke(newObj, parsInstance);
                                }
                            }
                        }
                    }
                    artifact = newObj;
                }
            } catch (InvocationTargetException ex) {
                stdErr.println("[!] InvocationTargetException: " + ex.toString().trim());
                stdErr.println("[!] Using the object built so far...");
                artifact = newObj;
            } catch (InstantiationException ex) {
                stdErr.println("[!] InstantiationException: " + ex.toString().trim());
            } catch (ClassNotFoundException ex) {
                stdErr.println("[!] ClassNotFoundException: " + ex.toString().trim());
                stdErr.println("[!] --> Make sure that you have imported all libraries");
            } catch (IllegalAccessException ex) {
                stdErr.println("[!] IllegalAccessException: " + ex.toString().trim());
            } catch (IllegalArgumentException ex) {
                stdErr.println("[!] IllegalArgumentException: " + ex.toString().trim());
            } catch (Exception ex) {
                stdErr.println("[!] General Exception: " + ex.toString().trim());
                stdErr.println("[!] --> Make sure that you have imported all libraries");
            }
        }
        return artifact;
    }
}

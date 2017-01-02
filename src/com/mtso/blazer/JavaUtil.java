/*
 * JavaUtil.java
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

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.ImportDeclaration;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.ModifierSet;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.TypeDeclaration;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

/*
 * This class implements multiple Java auxiliary utils
 */
public class JavaUtil {

    /*
     * Signature reference {Boolean, Integer, String, String, String, String, String}
     * [0] Boolean (used for table selection)
     * [1] Integer - signature's ID
     * [2] String - type (interface or class)
     * [3] String - class name
     * [4] String - method name
     * [5] String - method parameters
     * [6] String - method annotations
     */
    /*
     * Retrieve all public method signatures from a given Java file
     */
    public static ArrayList retrieveSignaturesFromSrc(File srcFile) throws Exception {
        return JavaUtil.retrieveSignaturesFromSrc(srcFile, 0);
    }

    public static ArrayList retrieveSignaturesFromSrc(File srcFile, int signId) throws Exception {

        ArrayList signatures = new ArrayList();
        Object[] signature = new Object[7];
        int methoCnt = signId;

        signature[0] = new Boolean(false); //used for signature selection

        CompilationUnit cu;
        cu = JavaParser.parse(srcFile);

        //Populate lookup table for classes/packages
        HashMap hmPck = new HashMap();
        //Primite types
        hmPck.put("byte", "byte");
        hmPck.put("short", "short");
        hmPck.put("int", "int");
        hmPck.put("long", "long");
        hmPck.put("float", "float");
        hmPck.put("double", "double");
        hmPck.put("boolean", "boolean");
        hmPck.put("char", "char");
        hmPck.put("String", "java.lang.String");
        hmPck.put("Boolean", "java.lang.Boolean");
        hmPck.put("Integer", "java.lang.Integer");
        hmPck.put("Byte", "java.lang.Byte");
        hmPck.put("Short", "java.lang.Short");
        hmPck.put("Long", "java.lang.Long");
        hmPck.put("Float", "java.lang.Float");
        hmPck.put("Double", "java.lang.Double");
        hmPck.put("Character", "java.lang.Character");
        hmPck.put("byte[]", "byte[]");
        hmPck.put("short[]", "short[]");
        hmPck.put("int[]", "int[]");
        hmPck.put("long[]", "long[]");
        hmPck.put("float[]", "float[]");
        hmPck.put("double[]", "double[]");
        hmPck.put("boolean[]", "boolean[]");
        hmPck.put("char[]", "char[]");
        hmPck.put("String[]", "java.lang.String[]");
        hmPck.put("Boolean[]", "java.lang.Boolean[]");
        hmPck.put("Integer[]", "java.lang.Integer[]");
        hmPck.put("Byte[]", "java.lang.Byte[]");
        hmPck.put("Short[]", "java.lang.Short[]");
        hmPck.put("Long[]", "java.lang.Long[]");
        hmPck.put("Float[]", "java.lang.Float[]");
        hmPck.put("Double[]", "java.lang.Double[]");
        hmPck.put("Character[]", "java.lang.Character[]");
        //Declared imports        
        List<ImportDeclaration> imports = cu.getImports();
        if (imports != null && !imports.isEmpty()) {
            for (ImportDeclaration imp : imports) {
                hmPck.put(imp.getName().getName(), imp.getName().toString());
            }
        }

        List<TypeDeclaration> types = cu.getTypes();
        for (TypeDeclaration type : types) {
            if (type instanceof ClassOrInterfaceDeclaration) {
                //We are either in a class or in an interface
                ClassOrInterfaceDeclaration classDec = (ClassOrInterfaceDeclaration) type;
                if (classDec.getModifiers() == ModifierSet.PUBLIC) {
                    //The class or interface is public
                    if (classDec.isInterface()) {
                        signature[2] = "Interface"; //interface
                    } else {
                        signature[2] = "Class"; //class
                    }
                    //convert to javaCase
                    signature[3] = classDec.getName().substring(0, 1).toLowerCase() + classDec.getName().substring(1);
                }

                List<BodyDeclaration> members = type.getMembers();
                for (BodyDeclaration member : members) {
                    if (member instanceof MethodDeclaration) {
                        //We are in a method
                        MethodDeclaration methoDec = (MethodDeclaration) member;
                        if (methoDec.getModifiers() == ModifierSet.PUBLIC) {
                            //the method is public
                            signature[1] = new Integer(methoCnt);
                            methoCnt++; //increment the signature's ID
                            signature[4] = methoDec.getName();

                            //retrieve method's pars
                            List pars = methoDec.getParameters();
                            if (pars != null) {
                                StringBuilder parsStr = new StringBuilder();

                                for (int i = 0; i < pars.size(); i++) {
                                    if (i > 0) {
                                        parsStr.append(", ");
                                    }
                                    Parameter sPar = (Parameter) pars.get(i);

                                    String sParCleaned = sPar.getType().toString();
                                    //remove Java generics definition, if present
                                    if (sPar.getType().toString().contains("<")) {
                                        sParCleaned = sParCleaned.substring(0, sParCleaned.indexOf("<"));
                                    }
                                    //before appending the parameter type, retrieve the package-class name from our lookup table
                                    if (hmPck.containsKey(sParCleaned)) {
                                        parsStr.append(hmPck.get(sParCleaned));
                                    } else {
                                        parsStr.append("NotFound"); //this prevents null values
                                    }
                                }
                                signature[5] = parsStr.toString();
                            } else {
                                //method with no parameter
                                signature[5] = "";
                            }

                            //retrieve method's annotations
                            List anns = methoDec.getAnnotations();

                            if (anns != null) {
                                StringBuilder annStr = new StringBuilder();

                                for (int i = 0; i < anns.size(); i++) {
                                    if (i > 0) {
                                        annStr.append(", ");
                                    }
                                    annStr.append(anns.get(i));
                                }

                                signature[6] = annStr.toString();
                            } else {
                                //method with no annotations
                                signature[6] = "";
                            }

                            //add signature[] to master signatures[]
                            signatures.add(signature.clone());
                            signature[4] = "";
                            signature[5] = "";
                            signature[6] = "";
                        }
                    }
                }
            } else {
                //bogus signature, no classes found - this is just to prevent GUI crashes
                signature[1] = new Integer(methoCnt);
                signature[2] = "";
                signature[3] = "";
                signature[4] = "";
                signature[5] = "";
                signature[6] = "";
            }
        }
        return signatures;
    }

    /*
     * Retrieve full class name, including package with dot notation
     */
    public static String retrieveCanonicalNameFromClass(File classFile) throws FileNotFoundException, IOException {

        ClassNode classNode = new ClassNode();
        InputStream classFileInputStream = new FileInputStream(classFile);
        try {
            ClassReader classReader = new ClassReader(classFileInputStream);
            classReader.accept((ClassVisitor) classNode, 0);
        } finally {
            classFileInputStream.close();
        }

        Type classType = Type.getObjectType(classNode.name);
        return classType.getClassName();
    }


    /*
     * Retrieve all public method signatures from a given Class file
     */
    public static ArrayList retrieveSignaturesFromClass(File classFile) throws Exception {
        return JavaUtil.retrieveSignaturesFromClass(new FileInputStream(classFile), 0);
    }

    public static ArrayList retrieveSignaturesFromClass(InputStream classFileIS) throws Exception {
        return JavaUtil.retrieveSignaturesFromClass(classFileIS, 0);
    }

    public static ArrayList retrieveSignaturesFromClass(File classFile, int signId) throws Exception {
        return retrieveSignaturesFromClass(new FileInputStream(classFile), signId);
    }

    public static ArrayList retrieveSignaturesFromClass(InputStream classFileIS, int signId) throws Exception {

        /*
         * Dynamic array containing multiple signatures arrays
         */
        ArrayList signatures = new ArrayList();

        Object[] signature = new Object[7];
        signature[0] = new Boolean(false); //used for signature selection

        ClassNode classNode = new ClassNode();
        InputStream classFileInputStream = classFileIS;
        try {
            ClassReader classReader = new ClassReader(classFileInputStream);
            classReader.accept((ClassVisitor) classNode, 0);
        } finally {
            classFileInputStream.close();
        }

        Type classType = Type.getObjectType(classNode.name);

        if ((classNode.access & Opcodes.ACC_PUBLIC) != 0) {

            if ((classNode.access & Opcodes.ACC_INTERFACE) != 0) {
                signature[2] = "Interface"; //interface
            } else {
                signature[2] = "Class"; //class
            }

            String name = classType.getClassName();
            name = name.substring(name.lastIndexOf('.') + 1); //packages are not required
            signature[3] = name.substring(0, 1).toLowerCase() + name.substring(1); //convert to javaCase
            @SuppressWarnings("unchecked")
            List<MethodNode> methodNodes = classNode.methods;

            for (MethodNode methodNode : methodNodes) {

                Type[] argumentTypes = Type.getArgumentTypes(methodNode.desc);

                if ((methodNode.access & Opcodes.ACC_PUBLIC) != 0) {

                    signature[4] = methodNode.name;

                    if (methodNode.visibleAnnotations != null) {

                        Iterator c = methodNode.visibleAnnotations.iterator();
                        while (c.hasNext()) {
                            AnnotationNode anode = (AnnotationNode) c.next();
                            String annotations = anode.desc;
                            annotations = annotations.substring(annotations.lastIndexOf('/') + 1, annotations.lastIndexOf(';'));
                            signature[6] = "@".concat(annotations); //convert to standard format
                        }
                    }

                    StringBuilder pars = new StringBuilder();

                    for (int i = 0; i < argumentTypes.length; i++) {

                        Type argumentType = argumentTypes[i];
                        if (i > 0) {
                            pars.append(", ");
                        }
                        pars.append(argumentType.getClassName());
                    }

                    signature[5] = pars.toString();

                    /* list here all exceptions */
                    if (!signature[4].equals("<init>")) {
                        signature[1] = new Integer(signId);
                        signatures.add(signature.clone());
                        signId++;
                    }
                    signature[5] = "";
                }
                signature[4] = "";
                signature[6] = "";
            }
        }
        return signatures;
    }

    /*
     * Retrieve all public method signatures from a given JAR
     */
    public static ArrayList retrieveSignaturesFromJAR(File jarFile) throws Exception {
        return JavaUtil.retrieveSignaturesFromJAR(jarFile, 0);
    }

    public static ArrayList retrieveSignaturesFromJAR(File jarFile, int signId) throws Exception {

        /*
         * Dynamic array containing multiple signatures arrays
         */
        ArrayList signaturesGl = new ArrayList();
        int signIdGlobal = signId;

        JarFile myJar = new JarFile(jarFile);

        Enumeration<JarEntry> entries = myJar.entries();
        while (entries.hasMoreElements()) {

            JarEntry entry = entries.nextElement();
            String entryName = entry.getName();

            if (entryName.endsWith(".class")) {
                ArrayList res = retrieveSignaturesFromClass(myJar.getInputStream(entry), signIdGlobal);
                signaturesGl.addAll(res);
                signIdGlobal = signIdGlobal + res.size();
            }
        }
        return signaturesGl;
    }


    /*
     * Recursively traverse a directory looking for .jar/.class/.java files
     */
    public static void findAllLibs(File root, List<File> toBuildUp) {

        if (!root.isDirectory() && (root.getName().endsWith(".java") || root.getName().endsWith(".jar") || root.getName().endsWith(".class"))) {
            toBuildUp.add(root);
        } else if (root.isDirectory()) {
            for (File f : root.listFiles()) {
                findAllLibs(f, toBuildUp);
            }
        } else {
            return;
        }
    }

    /*
     * Include custom resources into the SystemClassLoader at runtime
     * Hack: this code is probably unreliable and may not work on all JVMs 
     */
    public static void addURLs(URL[] urls, PrintWriter stdOut, PrintWriter stdErr) throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        ClassLoader cl = ClassLoader.getSystemClassLoader();
        if (cl instanceof URLClassLoader) {
            URLClassLoader ul = (URLClassLoader) cl;
            Class<?>[] paraTypes = new Class[1];
            paraTypes[0] = URL.class;
            Method method = URLClassLoader.class.getDeclaredMethod("addURL", paraTypes);
            method.setAccessible(true);
            Object[] args = new Object[1];
            for (int i = 0; i < urls.length; i++) {
                args[0] = urls[i];
                method.invoke(ul, args);
            }
        } else {
            stdErr.println("[!] \"SystemClassLoader\" is not instance of \"URLClassLoader\"");
            stdErr.println("[!] Some functionalities may not work as expected (e.g. Export AMF2XML)");
        }
    }
}

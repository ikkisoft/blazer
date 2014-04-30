/*
 * BlazerUIView.java
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

import bsh.EvalError;
import bsh.Interpreter;
import bsh.util.JConsole;
import java.awt.Image;
import java.awt.Toolkit;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;
import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.filechooser.FileFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;

/*
 * This class is the main Blazer GUI
 */
public class BlazerUIView extends java.awt.Frame implements PropertyChangeListener {

    private TaskManager manager;

    public BlazerUIView(TaskManager manager) {
        this.manager = manager;
        initComponents();
        Toolkit kit = Toolkit.getDefaultToolkit();
        Image img = kit.createImage(getClass().getResource("/com/mtso/blazer/burn.png"));
        this.setIconImage(img);
        manager.getPropertyChangeSupport().addPropertyChangeListener(this); //Listener to trigger runtime GUI changes
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * Do NOT modify this code.
     */
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup1 = new javax.swing.ButtonGroup();
        jPanel1 = new javax.swing.JPanel();
        StepsPanel = new javax.swing.JTabbedPane();
        firstStep = new javax.swing.JTabbedPane();
        libraries = new javax.swing.JPanel();
        jScrollPane4 = new javax.swing.JScrollPane();
        jTree4 = new javax.swing.JTree();
        jButton3 = new javax.swing.JButton();
        jFileChooser1 = new javax.swing.JFileChooser();
        jButton4 = new javax.swing.JButton();
        secondStep = new javax.swing.JTabbedPane();
        signatures = new javax.swing.JPanel();
        jScrollPane5 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        SelectAllButton = new javax.swing.JButton();
        remotingIncludeOnly = new javax.swing.JCheckBox();
        DeselectAllButton = new javax.swing.JButton();
        interfaceOnly = new javax.swing.JCheckBox();
        thirdStep = new javax.swing.JTabbedPane();
        options = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();
        fuzzingLabel1 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        threads = new javax.swing.JSlider();
        jSeparator1 = new javax.swing.JSeparator();
        permutations = new javax.swing.JSlider();
        jCheckBox3 = new javax.swing.JCheckBox();
        vectorsLikelihood = new javax.swing.JSlider();
        fuzzingLabel2 = new javax.swing.JLabel();
        fuzzingButton = new javax.swing.JButton();
        jLabel14 = new javax.swing.JLabel();
        proxyHost = new javax.swing.JTextField();
        jLabel15 = new javax.swing.JLabel();
        proxyPort = new javax.swing.JTextField();
        jScrollPane3 = new javax.swing.JScrollPane();
        vectorsList = new javax.swing.JTextArea();
        jFileChooser2 = new javax.swing.JFileChooser();
        datatype = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        bytePool = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        shortPool = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        intPool = new javax.swing.JTextField();
        jLabel7 = new javax.swing.JLabel();
        longPool = new javax.swing.JTextField();
        floatPool = new javax.swing.JTextField();
        jLabel8 = new javax.swing.JLabel();
        doublePool = new javax.swing.JTextField();
        jLabel9 = new javax.swing.JLabel();
        booleanPool = new javax.swing.JTextField();
        jLabel10 = new javax.swing.JLabel();
        jLabel11 = new javax.swing.JLabel();
        charPool = new javax.swing.JTextField();
        jLabel12 = new javax.swing.JLabel();
        stringPool = new javax.swing.JTextField();
        fourthStep = new javax.swing.JTabbedPane();
        progress = new javax.swing.JPanel();
        jPanel10 = new javax.swing.JPanel();
        jSeparator14 = new javax.swing.JSeparator();
        jLabel102 = new javax.swing.JLabel();
        jLabel103 = new javax.swing.JLabel();
        methodSignatures = new javax.swing.JLabel();
        AMFReqSent = new javax.swing.JLabel();
        jLabel106 = new javax.swing.JLabel();
        avgT = new javax.swing.JLabel();
        finishTLabel = new javax.swing.JLabel();
        totTLabel = new javax.swing.JLabel();
        finishT = new javax.swing.JLabel();
        totT = new javax.swing.JLabel();
        StopButton = new javax.swing.JButton();
        StartButton = new javax.swing.JButton();
        progressBar = new javax.swing.JProgressBar();
        jLabel110 = new javax.swing.JLabel();
        status = new javax.swing.JLabel();
        jLabel104 = new javax.swing.JLabel();
        attackVectors = new javax.swing.JLabel();
        jLabel111 = new javax.swing.JLabel();
        statusTask = new javax.swing.JLabel();
        AMFReq3 = new javax.swing.JLabel();
        jLabel105 = new javax.swing.JLabel();
        fifthStep = new javax.swing.JTabbedPane();
        beanshell = new javax.swing.JPanel();
        sixthStep = new javax.swing.JTabbedPane();
        export = new javax.swing.JPanel();
        jButtonExport = new javax.swing.JButton();
        reqCheckBox = new javax.swing.JCheckBox();
        respCheckBox = new javax.swing.JCheckBox();
        jLabel3 = new javax.swing.JLabel();
        radioConsole = new javax.swing.JRadioButton();
        jLabel13 = new javax.swing.JLabel();
        radioFile = new javax.swing.JRadioButton();

        setBackground(java.awt.Color.white);
        setBounds(new java.awt.Rectangle(200, 200, 0, 0));
        setForeground(java.awt.Color.white);
        setResizable(false);
        setTitle("Blazer - AMF Testing Made Easy! by @_ikki");
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                exitForm(evt);
            }
        });

        jPanel1.setBackground(new java.awt.Color(255, 255, 255));
        jPanel1.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 0, 0), 0));
        jPanel1.setFocusable(false);
        jPanel1.setMaximumSize(new java.awt.Dimension(600, 500));
        jPanel1.setMinimumSize(new java.awt.Dimension(600, 500));
        jPanel1.setPreferredSize(new java.awt.Dimension(600, 500));

        StepsPanel.setFocusable(false);
        StepsPanel.setMaximumSize(new java.awt.Dimension(594, 490));
        StepsPanel.setMinimumSize(new java.awt.Dimension(594, 490));
        StepsPanel.setName(""); // NOI18N
        StepsPanel.setPreferredSize(new java.awt.Dimension(593, 490));
        StepsPanel.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                StepsPanelFocusGained(evt);
            }
            public void focusLost(java.awt.event.FocusEvent evt) {
                StepsPanelFocusLost(evt);
            }
        });

        firstStep.setFocusable(false);
        firstStep.setName("firstStep"); // NOI18N

        libraries.setBackground(new java.awt.Color(255, 255, 255));
        libraries.setPreferredSize(new java.awt.Dimension(600, 500));

        javax.swing.tree.DefaultMutableTreeNode treeNode1 = new javax.swing.tree.DefaultMutableTreeNode("No Libs");
        jTree4.setModel(new javax.swing.tree.DefaultTreeModel(treeNode1));
        javax.swing.ImageIcon leafIcon = new javax.swing.ImageIcon(getClass().getResource("/com/mtso/blazer/add.png"));
        if (leafIcon != null) {
            DefaultTreeCellRenderer renderer =  new DefaultTreeCellRenderer();
            renderer.setLeafIcon(leafIcon);
            jTree4.setCellRenderer(renderer);
        }
        jTree4.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        jTree4.setMinimumSize(new java.awt.Dimension(90, 20));
        jScrollPane4.setViewportView(jTree4);

        jButton3.setText("Add Libs");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        jFileChooser1.setVisible(false);
        jFileChooser1.setDialogTitle("Select all application libraries (JAR, Class, Java)");
        jFileChooser1.setFileFilter(new JARClassesSourceFileFilter());
        jFileChooser1.setFileSelectionMode(javax.swing.JFileChooser.FILES_AND_DIRECTORIES);
        jFileChooser1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jFileChooser1ActionPerformed(evt);
            }
        });

        jButton4.setText("Remove Libs");
        jButton4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton4ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout librariesLayout = new javax.swing.GroupLayout(libraries);
        libraries.setLayout(librariesLayout);
        librariesLayout.setHorizontalGroup(
            librariesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 576, Short.MAX_VALUE)
            .addGroup(librariesLayout.createSequentialGroup()
                .addGap(122, 122, 122)
                .addComponent(jButton3, javax.swing.GroupLayout.PREFERRED_SIZE, 123, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(93, 93, 93)
                .addComponent(jButton4, javax.swing.GroupLayout.PREFERRED_SIZE, 123, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(115, Short.MAX_VALUE))
            .addGroup(librariesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(librariesLayout.createSequentialGroup()
                    .addGap(68, 68, 68)
                    .addComponent(jFileChooser1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(73, Short.MAX_VALUE)))
        );
        librariesLayout.setVerticalGroup(
            librariesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, librariesLayout.createSequentialGroup()
                .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 341, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(librariesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton3, javax.swing.GroupLayout.PREFERRED_SIZE, 38, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton4, javax.swing.GroupLayout.PREFERRED_SIZE, 38, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18))
            .addGroup(librariesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(librariesLayout.createSequentialGroup()
                    .addGap(4, 4, 4)
                    .addComponent(jFileChooser1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
        );

        firstStep.addTab("Application Libraries", libraries);

        StepsPanel.addTab("", new javax.swing.ImageIcon(getClass().getResource("/com/mtso/blazer/green01.png")), firstStep); // NOI18N
        firstStep.getAccessibleContext().setAccessibleName("");

        secondStep.setName("secondStep"); // NOI18N
        secondStep.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                secondStepFocusGained(evt);
            }
        });

        signatures.setBackground(new java.awt.Color(255, 255, 255));
        signatures.setFocusable(false);

        jScrollPane5.setFocusable(false);

        jTable1.setAutoCreateRowSorter(true);
        jTable1.setFont(new java.awt.Font("DejaVu Sans", 0, 11)); // NOI18N
        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "", "Id", "Type", "Name", "Method", "Parameters", "Annotations"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Boolean.class, java.lang.Integer.class, java.lang.String.class, java.lang.String.class, java.lang.String.class, java.lang.String.class, java.lang.String.class
            };
            boolean[] canEdit = new boolean [] {
                true, false, false, true, true, true, false
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jTable1.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_ALL_COLUMNS);
        jTable1.setAutoscrolls(false);
        jTable1.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        jTable1.setFocusable(false);
        jTable1.setRequestFocusEnabled(false);
        jTable1.setSurrendersFocusOnKeystroke(true);
        jTable1.getTableHeader().setResizingAllowed(false);
        jTable1.getTableHeader().setReorderingAllowed(false);
        jScrollPane5.setViewportView(jTable1);
        jTable1.getColumnModel().getColumn(0).setResizable(false);
        jTable1.getColumnModel().getColumn(0).setPreferredWidth(6);
        jTable1.getColumnModel().getColumn(1).setResizable(false);
        jTable1.getColumnModel().getColumn(1).setPreferredWidth(6);
        jTable1.getColumnModel().getColumn(2).setResizable(false);
        jTable1.getColumnModel().getColumn(2).setPreferredWidth(20);
        jTable1.getModel().addTableModelListener(new TableModelListener() {

            public void tableChanged(TableModelEvent e) {

                //Browse all signatures, compare with rows and save the current state
                ArrayList oldSignatures = manager.getTask().getSignatures();

                if(oldSignatures != null && !oldSignatures.isEmpty()){
                    DefaultTableModel model = (DefaultTableModel) jTable1.getModel();
                    for (int i = 0; i < model.getRowCount(); i++) {
                        Object[] signature = (Object[]) oldSignatures.get(((Integer) model.getValueAt(i, 1)).intValue());

                        if (((Boolean) signature[0]).booleanValue() != ((Boolean) model.getValueAt(i, 0)).booleanValue()) {
                            oldSignatures.remove(i);
                            signature[0] = (Boolean) model.getValueAt(i, 0);
                            oldSignatures.add(i, signature);
                        } else if (!((String) signature[3]).equals((String) model.getValueAt(i, 3))) {
                            oldSignatures.remove(i);
                            signature[3] = (String) model.getValueAt(i, 3);
                            oldSignatures.add(i, signature);
                        } else if (!((String) signature[4]).equals((String) model.getValueAt(i, 4))) {
                            oldSignatures.remove(i);
                            signature[4] = (String) model.getValueAt(i, 4);
                            oldSignatures.add(i, signature);
                        } else if (!((String) signature[5]).equals((String) model.getValueAt(i, 5))) {
                            oldSignatures.remove(i);
                            signature[5] = (String) model.getValueAt(i, 5);
                            oldSignatures.add(i, signature);
                        }
                    }
                }
                manager.getTask().setSignatures(oldSignatures);
            }
        });

        SelectAllButton.setText("Select All");
        SelectAllButton.setFocusable(false);
        SelectAllButton.setMaximumSize(new java.awt.Dimension(85, 27));
        SelectAllButton.setMinimumSize(new java.awt.Dimension(85, 27));
        SelectAllButton.setPreferredSize(new java.awt.Dimension(85, 27));
        SelectAllButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SelectAllButtonActionPerformed(evt);
            }
        });

        remotingIncludeOnly.setFont(new java.awt.Font("DejaVu Sans", 0, 11)); // NOI18N
        remotingIncludeOnly.setText("@RemotingInclude only");
        remotingIncludeOnly.setFocusable(false);
        remotingIncludeOnly.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                remotingIncludeOnlyItemStateChanged(evt);
            }
        });

        DeselectAllButton.setText("Deselect All");
        DeselectAllButton.setFocusable(false);
        DeselectAllButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DeselectAllButtonActionPerformed(evt);
            }
        });

        interfaceOnly.setFont(new java.awt.Font("DejaVu Sans", 0, 11)); // NOI18N
        interfaceOnly.setText("Interfaces only");
        interfaceOnly.setFocusable(false);
        interfaceOnly.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                interfaceOnlyItemStateChanged(evt);
            }
        });

        javax.swing.GroupLayout signaturesLayout = new javax.swing.GroupLayout(signatures);
        signatures.setLayout(signaturesLayout);
        signaturesLayout.setHorizontalGroup(
            signaturesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(signaturesLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(signaturesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(remotingIncludeOnly)
                    .addComponent(interfaceOnly))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 143, Short.MAX_VALUE)
                .addComponent(SelectAllButton, javax.swing.GroupLayout.PREFERRED_SIZE, 118, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(DeselectAllButton, javax.swing.GroupLayout.PREFERRED_SIZE, 117, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
            .addComponent(jScrollPane5, javax.swing.GroupLayout.DEFAULT_SIZE, 576, Short.MAX_VALUE)
        );
        signaturesLayout.setVerticalGroup(
            signaturesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, signaturesLayout.createSequentialGroup()
                .addComponent(jScrollPane5, javax.swing.GroupLayout.DEFAULT_SIZE, 301, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(signaturesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(signaturesLayout.createSequentialGroup()
                        .addComponent(remotingIncludeOnly)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(interfaceOnly, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(signaturesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(SelectAllButton, javax.swing.GroupLayout.PREFERRED_SIZE, 38, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(DeselectAllButton, javax.swing.GroupLayout.PREFERRED_SIZE, 38, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(28, 28, 28))
        );

        secondStep.addTab("Remote Method Signatures", signatures);

        StepsPanel.addTab("", new javax.swing.ImageIcon(getClass().getResource("/com/mtso/blazer/teal02.png")), secondStep); // NOI18N
        secondStep.getAccessibleContext().setAccessibleName("");

        thirdStep.setName("thirdStep"); // NOI18N

        options.setBackground(new java.awt.Color(255, 255, 255));
        options.setFocusable(false);

        jLabel2.setText("# Threads:");
        jLabel2.setFocusable(false);

        fuzzingLabel1.setText("% Attack Vectors:");
        fuzzingLabel1.setEnabled(false);
        fuzzingLabel1.setFocusable(false);

        jLabel4.setText("# Permutations:");
        jLabel4.setFocusable(false);

        threads.setMajorTickSpacing(9);
        threads.setMinimum(1);
        threads.setMinorTickSpacing(1);
        threads.setPaintLabels(true);
        threads.setPaintTicks(true);
        threads.setSnapToTicks(true);
        threads.setValue(1);
        threads.setFocusable(false);
        threads.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                threadsStateChanged(evt);
            }
        });

        permutations.setMajorTickSpacing(9);
        permutations.setMinimum(1);
        permutations.setMinorTickSpacing(1);
        permutations.setPaintLabels(true);
        permutations.setPaintTicks(true);
        permutations.setSnapToTicks(true);
        permutations.setValue(5);
        permutations.setFocusable(false);
        permutations.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                permutationsStateChanged(evt);
            }
        });

        jCheckBox3.setText("Fuzzing");
        jCheckBox3.setFocusable(false);
        jCheckBox3.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                jCheckBox3StateChanged(evt);
            }
        });

        vectorsLikelihood.setMajorTickSpacing(9);
        vectorsLikelihood.setMaximum(99);
        vectorsLikelihood.setMinimum(1);
        vectorsLikelihood.setMinorTickSpacing(9);
        vectorsLikelihood.setPaintLabels(true);
        vectorsLikelihood.setPaintTicks(true);
        vectorsLikelihood.setSnapToTicks(true);
        vectorsLikelihood.setEnabled(false);
        vectorsLikelihood.setFocusable(false);
        vectorsLikelihood.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                vectorsLikelihoodStateChanged(evt);
            }
        });

        fuzzingLabel2.setText("Attack Vectors:");
        fuzzingLabel2.setEnabled(false);
        fuzzingLabel2.setFocusable(false);

        fuzzingButton.setText("Load");
        fuzzingButton.setEnabled(false);
        fuzzingButton.setFocusable(false);
        fuzzingButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                fuzzingButtonActionPerformed(evt);
            }
        });

        jLabel14.setText("Proxy Host:");
        jLabel14.setFocusable(false);

        proxyHost.setText(manager.getTask().getProxyHost());
        proxyHost.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                proxyHostFocusLost(evt);
            }
        });

        jLabel15.setText("Proxy Port:");
        jLabel15.setFocusable(false);

        proxyPort.setText(manager.getTask().getProxyPort());
        proxyPort.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                proxyPortFocusLost(evt);
            }
        });

        jScrollPane3.setFocusable(false);

        vectorsList.setColumns(20);
        vectorsList.setRows(5);
        vectorsList.setText(" Load your attack vectors wordlist...");
        vectorsList.setEnabled(false);
        vectorsList.setFocusCycleRoot(true);
        vectorsList.setFocusTraversalPolicyProvider(true);
        vectorsList.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                vectorsListFocusLost(evt);
            }
        });
        jScrollPane3.setViewportView(vectorsList);

        jFileChooser2.setVisible(false);
        jFileChooser2.setDialogTitle("Select your attack vectors wordlist");
        jFileChooser2.setFocusable(false);
        jFileChooser2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jFileChooser2ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout optionsLayout = new javax.swing.GroupLayout(options);
        options.setLayout(optionsLayout);
        optionsLayout.setHorizontalGroup(
            optionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, optionsLayout.createSequentialGroup()
                .addGroup(optionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(optionsLayout.createSequentialGroup()
                        .addGap(24, 24, 24)
                        .addGroup(optionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(javax.swing.GroupLayout.Alignment.LEADING, optionsLayout.createSequentialGroup()
                                .addGroup(optionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 122, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 88, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(optionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(optionsLayout.createSequentialGroup()
                                        .addComponent(jLabel14)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(proxyHost, javax.swing.GroupLayout.PREFERRED_SIZE, 85, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(jLabel15)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(proxyPort, javax.swing.GroupLayout.PREFERRED_SIZE, 51, javax.swing.GroupLayout.PREFERRED_SIZE))
                                    .addGroup(optionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                        .addComponent(permutations, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(threads, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 408, Short.MAX_VALUE))))
                            .addGroup(javax.swing.GroupLayout.Alignment.LEADING, optionsLayout.createSequentialGroup()
                                .addGap(2, 2, 2)
                                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 540, javax.swing.GroupLayout.PREFERRED_SIZE))))
                    .addGroup(optionsLayout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(optionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jCheckBox3, javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.LEADING, optionsLayout.createSequentialGroup()
                                .addGroup(optionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(fuzzingLabel1)
                                    .addGroup(optionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                        .addComponent(fuzzingButton, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(fuzzingLabel2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                                .addGap(18, 18, 18)
                                .addGroup(optionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jScrollPane3)
                                    .addComponent(vectorsLikelihood, javax.swing.GroupLayout.DEFAULT_SIZE, 404, Short.MAX_VALUE))))))
                .addGap(120, 120, 120)
                .addComponent(jFileChooser2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );
        optionsLayout.setVerticalGroup(
            optionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(optionsLayout.createSequentialGroup()
                .addGap(70, 70, 70)
                .addComponent(jFileChooser2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, optionsLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(optionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(optionsLayout.createSequentialGroup()
                        .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 43, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(optionsLayout.createSequentialGroup()
                        .addComponent(threads, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(permutations, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(33, 33, 33)
                .addGroup(optionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel14)
                    .addComponent(proxyHost, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(proxyPort, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel15))
                .addGap(28, 28, 28)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGroup(optionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(optionsLayout.createSequentialGroup()
                        .addGap(46, 46, 46)
                        .addComponent(vectorsLikelihood, javax.swing.GroupLayout.PREFERRED_SIZE, 69, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 85, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(optionsLayout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jCheckBox3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(fuzzingLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 39, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(32, 32, 32)
                        .addComponent(fuzzingLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 33, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(fuzzingButton)))
                .addGap(27, 27, 27))
        );

        jLabel4.getAccessibleContext().setAccessibleName("permutations");

        thirdStep.addTab("General Options", options);

        datatype.setBackground(new java.awt.Color(255, 255, 255));
        datatype.setFocusable(false);

        jLabel1.setText("byte:");
        jLabel1.setFocusable(false);

        bytePool.setText("-128,127");
        bytePool.setMaximumSize(new java.awt.Dimension(322, 25));
        manager.getTask().setBytePool(buildPoolArray(bytePool.getText(),"byte"));
        bytePool.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                bytePoolFocusLost(evt);
            }
        });

        jLabel5.setText("short:");
        jLabel5.setFocusable(false);

        shortPool.setText("-32768,32767");
        shortPool.setMaximumSize(new java.awt.Dimension(322, 25));
        manager.getTask().setShortPool(buildPoolArray(shortPool.getText(),"short"));
        shortPool.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                shortPoolFocusLost(evt);
            }
        });

        jLabel6.setText("int:");
        jLabel6.setFocusable(false);

        intPool.setText("0,1,2,3,4,5,6,7,8,9");
        intPool.setMaximumSize(new java.awt.Dimension(322, 25));
        manager.getTask().setIntPool(buildPoolArray(intPool.getText(),"int"));
        intPool.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                intPoolFocusLost(evt);
            }
        });

        jLabel7.setText("long:");
        jLabel7.setFocusable(false);

        longPool.setText("0,1,2,3,4,5,6,7,8,9");
        longPool.setMaximumSize(new java.awt.Dimension(322, 25));
        longPool.setPreferredSize(new java.awt.Dimension(322, 25));
        manager.getTask().setLongPool(buildPoolArray(longPool.getText(),"long"));
        longPool.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                longPoolFocusLost(evt);
            }
        });

        floatPool.setText("0,1,2,3,4,5,6,7,8,9");
        floatPool.setMaximumSize(new java.awt.Dimension(322, 25));
        manager.getTask().setFloatPool(buildPoolArray(floatPool.getText(),"float"));
        floatPool.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                floatPoolFocusLost(evt);
            }
        });

        jLabel8.setText("float:");
        jLabel8.setFocusable(false);

        doublePool.setText("0,1,2,3,4,5,6,7,8,9");
        doublePool.setMaximumSize(new java.awt.Dimension(322, 25));
        manager.getTask().setDoublePool(buildPoolArray(doublePool.getText(),"double"));
        doublePool.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                doublePoolFocusLost(evt);
            }
        });

        jLabel9.setText("double:");
        jLabel9.setFocusable(false);

        booleanPool.setText("true,false");
        booleanPool.setMaximumSize(new java.awt.Dimension(322, 25));
        manager.getTask().setBooleanPool(buildPoolArray(booleanPool.getText(),"boolean"));
        booleanPool.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                booleanPoolFocusLost(evt);
            }
        });

        jLabel10.setText("boolean: ");
        jLabel10.setFocusable(false);

        jLabel11.setText("char:");
        jLabel11.setFocusable(false);

        charPool.setText("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z");
        charPool.setMaximumSize(new java.awt.Dimension(322, 25));
        manager.getTask().setCharPool(buildPoolArray(charPool.getText(),"char"));
        charPool.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                charPoolFocusLost(evt);
            }
        });

        jLabel12.setText("String: ");
        jLabel12.setFocusable(false);

        stringPool.setText("test,foo,bar,key,example");
        stringPool.setMaximumSize(new java.awt.Dimension(322, 25));
        manager.getTask().setStringPool(buildPoolArray(stringPool.getText(),"string"));
        stringPool.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                stringPoolFocusLost(evt);
            }
        });

        javax.swing.GroupLayout datatypeLayout = new javax.swing.GroupLayout(datatype);
        datatype.setLayout(datatypeLayout);
        datatypeLayout.setHorizontalGroup(
            datatypeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(datatypeLayout.createSequentialGroup()
                .addGap(38, 38, 38)
                .addGroup(datatypeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel12, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel11)
                    .addComponent(jLabel10, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel9)
                    .addComponent(jLabel6)
                    .addComponent(jLabel5)
                    .addComponent(jLabel1)
                    .addGroup(datatypeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                        .addComponent(jLabel8)
                        .addComponent(jLabel7)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(datatypeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(stringPool, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(charPool, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(booleanPool, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(doublePool, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(floatPool, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(longPool, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(intPool, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(shortPool, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(bytePool, javax.swing.GroupLayout.PREFERRED_SIZE, 446, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(569, 569, 569))
        );
        datatypeLayout.setVerticalGroup(
            datatypeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(datatypeLayout.createSequentialGroup()
                .addGap(35, 35, 35)
                .addGroup(datatypeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(bytePool, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1))
                .addGap(9, 9, 9)
                .addGroup(datatypeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(shortPool, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel5))
                .addGap(9, 9, 9)
                .addGroup(datatypeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(intPool, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel6))
                .addGap(9, 9, 9)
                .addGroup(datatypeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(longPool, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel7))
                .addGap(9, 9, 9)
                .addGroup(datatypeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(floatPool, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel8))
                .addGap(9, 9, 9)
                .addGroup(datatypeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(doublePool, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel9))
                .addGap(9, 9, 9)
                .addGroup(datatypeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(booleanPool, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel10))
                .addGap(9, 9, 9)
                .addGroup(datatypeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(charPool, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel11))
                .addGap(9, 9, 9)
                .addGroup(datatypeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(stringPool, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel12))
                .addContainerGap(59, Short.MAX_VALUE))
        );

        thirdStep.addTab("Data Pools", datatype);

        StepsPanel.addTab("", new javax.swing.ImageIcon(getClass().getResource("/com/mtso/blazer/red03.png")), thirdStep); // NOI18N
        thirdStep.getAccessibleContext().setAccessibleName("General Options");

        fourthStep.setName("fourthStep"); // NOI18N
        fourthStep.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                fourthStepFocusGained(evt);
            }
        });

        progress.setBackground(new java.awt.Color(255, 255, 255));
        progress.setFocusable(false);

        jPanel10.setBackground(new java.awt.Color(255, 255, 255));
        jPanel10.setFocusable(false);

        jLabel102.setText("# Method Signatures:");
        jLabel102.setFocusable(false);

        jLabel103.setText("# AMF Requests:");
        jLabel103.setFocusable(false);

        methodSignatures.setFont(new java.awt.Font("DejaVu Sans", 1, 12)); // NOI18N
        methodSignatures.setText("0");
        methodSignatures.setFocusable(false);

        AMFReqSent.setFont(new java.awt.Font("DejaVu Sans", 1, 12)); // NOI18N
        AMFReqSent.setText("0");
        AMFReqSent.setFocusable(false);

        jLabel106.setText("Average Speed (reqs/sec):");
        jLabel106.setFocusable(false);

        avgT.setFont(new java.awt.Font("DejaVu Sans", 1, 12)); // NOI18N
        avgT.setText("0");
        avgT.setFocusable(false);

        finishTLabel.setText("Time to Finish (sec):");
        finishTLabel.setFocusable(false);

        totTLabel.setText("Overall Time (sec):");
        totTLabel.setFocusable(false);

        finishT.setFont(new java.awt.Font("DejaVu Sans", 1, 12)); // NOI18N
        finishT.setText("0");
        finishT.setFocusable(false);

        totT.setFont(new java.awt.Font("DejaVu Sans", 1, 12)); // NOI18N
        totT.setText("0");
        totT.setFocusable(false);

        StopButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/com/mtso/blazer/stop.png"))); // NOI18N
        StopButton.setText("Stop");
        StopButton.setEnabled(false);
        StopButton.setFocusable(false);
        StopButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                StopButtonActionPerformed(evt);
            }
        });

        StartButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/com/mtso/blazer/play.png"))); // NOI18N
        StartButton.setText("Start");
        StartButton.setFocusable(false);
        StartButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                StartButtonActionPerformed(evt);
            }
        });

        progressBar.setFocusable(false);

        jLabel110.setText("Current Status:");
        jLabel110.setFocusable(false);

        status.setFont(new java.awt.Font("DejaVu Sans", 1, 12)); // NOI18N
        status.setText("STOPPED");
        status.setFocusable(false);

        jLabel104.setText("# Attack Vectors:");
        jLabel104.setFocusable(false);

        attackVectors.setFont(new java.awt.Font("DejaVu Sans", 1, 12)); // NOI18N
        attackVectors.setText("0");
        attackVectors.setFocusable(false);

        jLabel111.setText("Current Task:");
        jLabel111.setFocusable(false);

        statusTask.setFont(new java.awt.Font("DejaVu Sans", 1, 12)); // NOI18N
        statusTask.setText("GENERATION");
        statusTask.setFocusable(false);

        AMFReq3.setFont(new java.awt.Font("DejaVu Sans", 1, 12)); // NOI18N
        AMFReq3.setText("0");
        AMFReq3.setFocusable(false);

        jLabel105.setText("# Requests Sent (task):");
        jLabel105.setFocusable(false);

        javax.swing.GroupLayout jPanel10Layout = new javax.swing.GroupLayout(jPanel10);
        jPanel10.setLayout(jPanel10Layout);
        jPanel10Layout.setHorizontalGroup(
            jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel10Layout.createSequentialGroup()
                .addGap(94, 94, 94)
                .addComponent(StartButton, javax.swing.GroupLayout.PREFERRED_SIZE, 126, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 154, Short.MAX_VALUE)
                .addComponent(StopButton, javax.swing.GroupLayout.PREFERRED_SIZE, 126, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(128, 128, 128))
            .addGroup(jPanel10Layout.createSequentialGroup()
                .addGap(37, 37, 37)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel10Layout.createSequentialGroup()
                                .addComponent(jLabel103)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(AMFReq3, javax.swing.GroupLayout.PREFERRED_SIZE, 257, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(jPanel10Layout.createSequentialGroup()
                                .addComponent(jLabel102)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(methodSignatures, javax.swing.GroupLayout.PREFERRED_SIZE, 109, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(jPanel10Layout.createSequentialGroup()
                                .addComponent(jLabel104)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(attackVectors, javax.swing.GroupLayout.PREFERRED_SIZE, 109, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jSeparator14, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addContainerGap())
                    .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(jPanel10Layout.createSequentialGroup()
                            .addComponent(jLabel105)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                            .addComponent(AMFReqSent, javax.swing.GroupLayout.DEFAULT_SIZE, 44, Short.MAX_VALUE)
                            .addGap(384, 384, 384))
                        .addGroup(jPanel10Layout.createSequentialGroup()
                            .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(progressBar, javax.swing.GroupLayout.PREFERRED_SIZE, 504, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGroup(jPanel10Layout.createSequentialGroup()
                                    .addComponent(finishTLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 137, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                    .addComponent(finishT, javax.swing.GroupLayout.PREFERRED_SIZE, 115, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGroup(jPanel10Layout.createSequentialGroup()
                                    .addComponent(totTLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 125, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                    .addComponent(totT, javax.swing.GroupLayout.PREFERRED_SIZE, 93, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGroup(jPanel10Layout.createSequentialGroup()
                                    .addComponent(jLabel111)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                    .addComponent(statusTask, javax.swing.GroupLayout.PREFERRED_SIZE, 417, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGroup(jPanel10Layout.createSequentialGroup()
                                    .addComponent(jLabel110)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                    .addComponent(status, javax.swing.GroupLayout.PREFERRED_SIZE, 417, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGroup(jPanel10Layout.createSequentialGroup()
                                    .addComponent(jLabel106)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                    .addComponent(avgT, javax.swing.GroupLayout.PREFERRED_SIZE, 177, javax.swing.GroupLayout.PREFERRED_SIZE)))
                            .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))))
        );
        jPanel10Layout.setVerticalGroup(
            jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel10Layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel10Layout.createSequentialGroup()
                        .addComponent(jSeparator14, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(97, 97, 97))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel10Layout.createSequentialGroup()
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel102)
                            .addComponent(methodSignatures))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel104)
                            .addComponent(attackVectors))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel103)
                            .addComponent(AMFReq3))
                        .addGap(25, 25, 25)
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel105)
                            .addComponent(AMFReqSent))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)))
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel106)
                    .addComponent(avgT))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(finishTLabel)
                    .addComponent(finishT))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(totTLabel)
                    .addComponent(totT))
                .addGap(19, 19, 19)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel111)
                    .addComponent(statusTask))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel110)
                    .addComponent(status))
                .addGap(18, 18, 18)
                .addComponent(progressBar, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(27, 27, 27)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(StartButton, javax.swing.GroupLayout.PREFERRED_SIZE, 44, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(StopButton, javax.swing.GroupLayout.PREFERRED_SIZE, 44, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        javax.swing.GroupLayout progressLayout = new javax.swing.GroupLayout(progress);
        progress.setLayout(progressLayout);
        progressLayout.setHorizontalGroup(
            progressLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, progressLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jPanel10, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(21, 21, 21))
        );
        progressLayout.setVerticalGroup(
            progressLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(progressLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel10, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(19, Short.MAX_VALUE))
        );

        fourthStep.addTab("Status", progress);

        StepsPanel.addTab("", new javax.swing.ImageIcon(getClass().getResource("/com/mtso/blazer/orange04.png")), fourthStep); // NOI18N

        fifthStep.setName("fifthStep"); // NOI18N
        fifthStep.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                fifthStepFocusGained(evt);
            }
        });

        beanshell.setBackground(new java.awt.Color(255, 255, 255));
        beanshell.setFocusable(false);

        javax.swing.GroupLayout beanshellLayout = new javax.swing.GroupLayout(beanshell);
        beanshell.setLayout(beanshellLayout);
        beanshellLayout.setHorizontalGroup(
            beanshellLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 576, Short.MAX_VALUE)
        );
        beanshellLayout.setVerticalGroup(
            beanshellLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 391, Short.MAX_VALUE)
        );

        fifthStep.addTab("BeanShell", beanshell);

        StepsPanel.addTab("", new javax.swing.ImageIcon(getClass().getResource("/com/mtso/blazer/terminal.png")), fifthStep); // NOI18N

        sixthStep.setName("sixthStep"); // NOI18N

        jButtonExport.setText("Export");
        jButtonExport.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonExportActionPerformed(evt);
            }
        });

        reqCheckBox.setSelected(true);
        reqCheckBox.setText("AMF Request");

        respCheckBox.setText("AMF Response");

        jLabel3.setText("Include:");

        buttonGroup1.add(radioConsole);
        radioConsole.setSelected(true);
        radioConsole.setText("Console");

        jLabel13.setText("Output:");

        buttonGroup1.add(radioFile);
        radioFile.setText("File");

        javax.swing.GroupLayout exportLayout = new javax.swing.GroupLayout(export);
        export.setLayout(exportLayout);
        exportLayout.setHorizontalGroup(
            exportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(exportLayout.createSequentialGroup()
                .addGap(24, 24, 24)
                .addGroup(exportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jButtonExport, javax.swing.GroupLayout.PREFERRED_SIZE, 114, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(exportLayout.createSequentialGroup()
                        .addGroup(exportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel3)
                            .addComponent(reqCheckBox)
                            .addComponent(respCheckBox))
                        .addGap(110, 110, 110)
                        .addGroup(exportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(radioFile)
                            .addComponent(radioConsole)
                            .addComponent(jLabel13))))
                .addContainerGap(253, Short.MAX_VALUE))
        );
        exportLayout.setVerticalGroup(
            exportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(exportLayout.createSequentialGroup()
                .addGap(42, 42, 42)
                .addGroup(exportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(jLabel13))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(exportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(reqCheckBox)
                    .addComponent(radioConsole))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(exportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(respCheckBox)
                    .addComponent(radioFile))
                .addGap(28, 28, 28)
                .addComponent(jButtonExport)
                .addContainerGap(223, Short.MAX_VALUE))
        );

        sixthStep.addTab("Export", export);

        StepsPanel.addTab("", new javax.swing.ImageIcon(getClass().getResource("/com/mtso/blazer/export.png")), sixthStep); // NOI18N
        sixthStep.getAccessibleContext().setAccessibleName("Export");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(StepsPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 600, Short.MAX_VALUE)
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(StepsPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );

        StepsPanel.getAccessibleContext().setAccessibleName("");

        add(jPanel1, java.awt.BorderLayout.CENTER);

        pack();
    }// </editor-fold>//GEN-END:initComponents

    /**
     * Exit the Application
     */
    private void exitForm(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_exitForm
        this.dispose();
    }//GEN-LAST:event_exitForm

    private void SelectAllButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SelectAllButtonActionPerformed
        secondStep.setTitleAt(secondStep.getSelectedIndex(), "Loading...");

        Thread t = new Thread() {
            @Override
            public void run() {
                SwingUtilities.invokeLater(new Runnable() {
                    //This is called later by the event dispatch thread
                    //See http://www.javamex.com/tutorials/threads/invokelater.shtml
                    public void run() {
                        DefaultTableModel model = (DefaultTableModel) jTable1.getModel();
                        for (int i = 0; i < model.getRowCount(); i++) {
                            model.setValueAt(new Boolean(true), i, 0);
                        }
                        ((DefaultTableModel) jTable1.getModel()).fireTableDataChanged();
                        secondStep.setTitleAt(secondStep.getSelectedIndex(), "Remote Method Signatures");
                    }
                });
            }
        };
        t.start();
}//GEN-LAST:event_SelectAllButtonActionPerformed

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        jFileChooser1.setVisible(true);
        int showOpenDialog = jFileChooser1.showOpenDialog(this);
}//GEN-LAST:event_jButton3ActionPerformed

    private void jFileChooser1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jFileChooser1ActionPerformed

        //Discover JARs, Java, Class files recursively in all directories
        List<File> allLibs = new ArrayList<File>();

        File[] selectedFiles = jFileChooser1.getSelectedFiles();

        if (selectedFiles != null && selectedFiles.length > 1) {
            for (int i = 0; i < selectedFiles.length; i++) {
                JavaUtil.findAllLibs(selectedFiles[i], allLibs);
            }
        } else {
            File selectedFile = jFileChooser1.getSelectedFile();
            if (selectedFile != null) {
                JavaUtil.findAllLibs(selectedFile, allLibs);
            }
        }

        //Import resources in Blazer
        Iterator allListIt = allLibs.iterator();
        while (allListIt.hasNext()) {
            File resFile = (File) allListIt.next();
            manager.getTask().setLibraries(resFile);
        }

        //Display resources in Blazer
        jTree4.setModel(null);
        DefaultTreeModel myModel = new DefaultTreeModel(null);
        DefaultMutableTreeNode treeNodeRoot = new DefaultMutableTreeNode("");
        myModel.setRoot(treeNodeRoot);

        Iterator listRes = manager.getTask().getLibraries().iterator();
        if (listRes.hasNext()) {
            while (listRes.hasNext()) {
                File itemRes = (File) listRes.next();
                try {
                    //Display files
                    treeNodeRoot.add(new DefaultMutableTreeNode(itemRes.getCanonicalPath()));
                } catch (IOException iex) {
                    manager.getStdErr().println("[!] LoadTreeNode IOException: " + iex.toString().trim());
                }
            }
            myModel.setRoot(treeNodeRoot);
            jTree4.setModel(myModel);
        }
}//GEN-LAST:event_jFileChooser1ActionPerformed

    private void DeselectAllButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DeselectAllButtonActionPerformed
        secondStep.setTitleAt(secondStep.getSelectedIndex(), "Loading...");

        Thread t = new Thread() {
            @Override
            public void run() {
                SwingUtilities.invokeLater(new Runnable() {
                    //This is called later by the event dispatch thread
                    //See http://www.javamex.com/tutorials/threads/invokelater.shtml
                    public void run() {
                        DefaultTableModel model = (DefaultTableModel) jTable1.getModel();
                        for (int i = 0; i < model.getRowCount(); i++) {
                            model.setValueAt(new Boolean(false), i, 0);
                        }
                        ((DefaultTableModel) jTable1.getModel()).fireTableDataChanged();
                        secondStep.setTitleAt(secondStep.getSelectedIndex(), "Remote Method Signatures");
                    }
                });
            }
        };
        t.start();
    }//GEN-LAST:event_DeselectAllButtonActionPerformed

    private void secondStepFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_secondStepFocusGained
        DefaultTableModel model = (DefaultTableModel) jTable1.getModel();
        displayAllSignaturesThread();
    }//GEN-LAST:event_secondStepFocusGained

    private void remotingIncludeOnlyItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_remotingIncludeOnlyItemStateChanged
        if (remotingIncludeOnly.isSelected()) {
            secondStep.setTitleAt(secondStep.getSelectedIndex(), "Loading...");

            Thread t = new Thread() {
                @Override
                public void run() {
                    SwingUtilities.invokeLater(new Runnable() {
                        //This is called later by the event dispatch thread
                        //See http://www.javamex.com/tutorials/threads/invokelater.shtml
                        public void run() {
                            for (int i = ((DefaultTableModel) jTable1.getModel()).getRowCount() - 1; i >= 0; i = i - 1) {
                                String annotations = (String) ((DefaultTableModel) jTable1.getModel()).getValueAt(i, 6);
                                if (annotations == null || !annotations.contains("RemotingInclude")) {
                                    ((DefaultTableModel) jTable1.getModel()).removeRow(i);
                                }
                            }
                            ((DefaultTableModel) jTable1.getModel()).fireTableDataChanged();
                            secondStep.setTitleAt(secondStep.getSelectedIndex(), "Remote Method Signatures");
                        }
                    });
                }
            };
            t.start();
        } else {
            displayAllSignaturesThread();
        }
    }//GEN-LAST:event_remotingIncludeOnlyItemStateChanged

    private void interfaceOnlyItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_interfaceOnlyItemStateChanged
        if (interfaceOnly.isSelected()) {
            secondStep.setTitleAt(secondStep.getSelectedIndex(), "Loading...");

            Thread t = new Thread() {
                @Override
                public void run() {
                    SwingUtilities.invokeLater(new Runnable() {
                        //This is called later by the event dispatch thread
                        //See http://www.javamex.com/tutorials/threads/invokelater.shtml
                        public void run() {
                            for (int i = ((DefaultTableModel) jTable1.getModel()).getRowCount() - 1; i >= 0; i = i - 1) {
                                String type = (String) ((DefaultTableModel) jTable1.getModel()).getValueAt(i, 2);
                                if (type == null || !type.contains("Interface")) {
                                    ((DefaultTableModel) jTable1.getModel()).removeRow(i);
                                }
                            }
                            ((DefaultTableModel) jTable1.getModel()).fireTableDataChanged();
                            secondStep.setTitleAt(secondStep.getSelectedIndex(), "Remote Method Signatures");
                        }
                    });
                }
            };
            t.start();
        } else {
            displayAllSignaturesThread();
        }
    }//GEN-LAST:event_interfaceOnlyItemStateChanged

    private void threadsStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_threadsStateChanged
        manager.getTask().setThreads(threads.getValue());
    }//GEN-LAST:event_threadsStateChanged

    private void permutationsStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_permutationsStateChanged
        manager.getTask().setPermutations(permutations.getValue());
    }//GEN-LAST:event_permutationsStateChanged

    private void jCheckBox3StateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_jCheckBox3StateChanged
        if (jCheckBox3.isSelected()) {
            fuzzingLabel1.setEnabled(true);
            fuzzingLabel2.setEnabled(true);
            vectorsLikelihood.setEnabled(true);
            vectorsList.setEnabled(true);
            fuzzingButton.setEnabled(true);

            //Also, set fuzzing flag to true
            manager.getTask().setFuzzing(true);

        } else {
            fuzzingLabel1.setEnabled(false);
            fuzzingLabel2.setEnabled(false);
            vectorsLikelihood.setEnabled(false);
            vectorsList.setEnabled(false);
            fuzzingButton.setEnabled(false);

            //Also, set fuzzing flag to false
            manager.getTask().setFuzzing(false);
            manager.getTask().resetVectors();
        }
    }//GEN-LAST:event_jCheckBox3StateChanged

    private void vectorsLikelihoodStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_vectorsLikelihoodStateChanged
        manager.getTask().setVectorsLikehood(vectorsLikelihood.getValue());
    }//GEN-LAST:event_vectorsLikelihoodStateChanged

    private void fuzzingButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_fuzzingButtonActionPerformed
        jFileChooser2.setVisible(true);
        int showOpenDialog = jFileChooser2.showOpenDialog(this);
    }//GEN-LAST:event_fuzzingButtonActionPerformed

    private void jFileChooser2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jFileChooser2ActionPerformed
        if (jFileChooser2.getSelectedFile() != null) {
            File selectedFile = jFileChooser2.getSelectedFile();
            String[] wordlist = GenericUtil.retrieveWordlist(selectedFile, manager.getStdOut(), manager.getStdErr());
            StringBuilder buffer = new StringBuilder();
            for (int i = 0; i < wordlist.length; i++) {
                buffer.append(wordlist[i]);
                if (i < wordlist.length - 1) {
                    buffer.append("\n");
                }
            }
            vectorsList.setText(buffer.toString());
        }
    }//GEN-LAST:event_jFileChooser2ActionPerformed

    private void StartButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_StartButtonActionPerformed

        if (manager.getTask().getStatus() == TaskSpecification.STOPPED) {
            if (manager.isReady()) {

                //Block tabs to prevent configuration changes
                StepsPanel.setEnabledAt(0, false);
                StepsPanel.setEnabledAt(1, false);
                StepsPanel.setEnabledAt(2, false);

                //Start a new task
                StartButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/com/mtso/blazer/pause.png")));
                StartButton.setText("Pause");
                StopButton.setEnabled(true);
                status.setText("RUNNING");

                Thread t = new Thread() {
                    @Override
                    public void run() {
                        try {
                            manager.startCurrentTask();
                        } catch (InterruptedException ex) {
                            manager.getStdErr().println("[!] InterruptedError: " + ex.toString().trim());
                        }
                    }
                };
                t.start();
            } else {
                status.setText("PLEASE CHECK YOUR CONFIGURATION");
            }
        } else if (manager.getTask().getStatus() == TaskSpecification.PAUSED) {
            //Resume a paused task
            StartButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/com/mtso/blazer/pause.png")));
            StartButton.setText("Pause");
            status.setText("RUNNING");

            Thread t = new Thread() {
                @Override
                public void run() {
                    manager.resumeCurrentTask();
                }
            };
            t.start();

        } else if (manager.getTask().getStatus() == TaskSpecification.STARTED) {
            //Pause a running task
            StartButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/com/mtso/blazer/play.png")));
            StartButton.setText("Resume");
            status.setText("PAUSED");

            Thread t = new Thread() {
                @Override
                public void run() {
                    manager.pauseCurrentTask();
                }
            };
            t.start();
        }

    }//GEN-LAST:event_StartButtonActionPerformed

    private void StopButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_StopButtonActionPerformed
        if (manager.getTask().getStatus() == TaskSpecification.STARTED || manager.getTask().getStatus() == TaskSpecification.PAUSED) {

            //Re-enable tabs
            StepsPanel.setEnabledAt(0, true);
            StepsPanel.setEnabledAt(1, true);
            StepsPanel.setEnabledAt(2, true);

            //Stop and reset a task
            Thread t = new Thread() {
                @Override
                public void run() {
                    manager.stopCurrentTask();
                }
            };
            t.start();
        }
    }//GEN-LAST:event_StopButtonActionPerformed

    private void restoreGUIAfterStop() {
        StartButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/com/mtso/blazer/play.png")));
        StartButton.setText("Start");
        StopButton.setEnabled(false);
        status.setText("DONE");
        avgT.setText("0");
        finishT.setText("0");
        totT.setText("0");
        progressBar.setValue(0);
        AMFReqSent.setText("0");

        //Re-enable tabs
        StepsPanel.setEnabledAt(0, true);
        StepsPanel.setEnabledAt(1, true);
        StepsPanel.setEnabledAt(2, true);

    }
    private void fourthStepFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_fourthStepFocusGained

        methodSignatures.setText(String.valueOf(manager.getSignaturesSelectedCounter()));

        //This is probably redundant, however it may fix FocusGained/FocusLost bugs on some JVMs
        manager.getTask().setThreads(threads.getValue());
        manager.getTask().setPermutations(permutations.getValue());
        manager.getTask().setProxyHost(proxyHost.getText());
        manager.getTask().setProxyPort(proxyPort.getText());
        manager.getTask().setBytePool(buildPoolArray(bytePool.getText(), "byte"));
        manager.getTask().setShortPool(buildPoolArray(shortPool.getText(), "short"));
        manager.getTask().setIntPool(buildPoolArray(intPool.getText(), "int"));
        manager.getTask().setLongPool(buildPoolArray(longPool.getText(), "long"));
        manager.getTask().setFloatPool(buildPoolArray(floatPool.getText(), "float"));
        manager.getTask().setDoublePool(buildPoolArray(doublePool.getText(), "double"));
        manager.getTask().setBooleanPool(buildPoolArray(booleanPool.getText(), "boolean"));
        manager.getTask().setCharPool(buildPoolArray(charPool.getText(), "char"));
        manager.getTask().setStringPool(buildPoolArray(stringPool.getText(), "string"));

        if (manager.getTask().doFuzzing()) {
            //This is probably redundant, however it may fix FocusGained/FocusLost bugs on some JVMs
            manager.getTask().setVectorsLikehood(vectorsLikelihood.getValue());
            String[] vectorStr = vectorsList.getText().split("\\\n");
            ArrayList vectors = new ArrayList(Arrays.asList(vectorStr));
            manager.getTask().setVectors(vectors);

            statusTask.setText("FUZZING");
            attackVectors.setText(String.valueOf(manager.getTask().getVectors().size()));
        } else {
            statusTask.setText("GENERATION");
            attackVectors.setText(String.valueOf(0));
        }

        AMFReq3.setText(Integer.toString(manager.getRequestsTot()));
    }//GEN-LAST:event_fourthStepFocusGained

    //PropertyChange Trigger
    public void propertyChange(PropertyChangeEvent evt) {

        //Runtime GUI updates for progress status
        if ("requestsDone".equals(evt.getPropertyName()) && manager.getTask().getStatus() == TaskSpecification.STARTED) {

            AMFReqSent.setText(Integer.toString(manager.getRequestsDone()));
            avgT.setText(Float.toString(manager.getAverageSpeed()));

            if (Math.round(manager.getTimeToFinish()) > 180) {
                finishTLabel.setText("Time to Finish (min):");
                finishT.setText(Integer.toString(Math.round(manager.getTimeToFinish() / 60)));
            } else {
                finishTLabel.setText("Time to Finish (sec):");
                finishT.setText(Integer.toString(Math.round(manager.getTimeToFinish())));
            }

            if (Math.round(manager.getOverallTime()) > 180) {
                totTLabel.setText("Overall Time (min):");
                totT.setText(Integer.toString(Math.round(manager.getOverallTime() / 60)));
            } else {
                totTLabel.setText("Overall Time (sec):");
                totT.setText(Integer.toString(Math.round(manager.getOverallTime())));
            }

            //Update the progress bar
            int progressPr = ((100 * manager.getRequestsDone()) / manager.getRequestsTot());
            progressBar.setValue(Math.min(progressPr, 100));
        }

        //Runtime end of task notification
        if ("taskStopped".equals(evt.getPropertyName())) {
            restoreGUIAfterStop();
        }
    }

    private void jButton4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton4ActionPerformed
        //Remove all JAR,Java,Class files thus remove libraries and signatures
        manager.getTask().resetLibraries();
        manager.getTask().resetSignatures();
        jTree4.setModel(new javax.swing.tree.DefaultTreeModel(new javax.swing.tree.DefaultMutableTreeNode("No Libs")));

        //Update the signatures table
        Thread t = new Thread() {
            @Override
            public void run() {
                SwingUtilities.invokeLater(new Runnable() {
                    //This is called later by the event dispatch thread
                    //See http://www.javamex.com/tutorials/threads/invokelater.shtml
                    public void run() {
                        for (int i = ((DefaultTableModel) jTable1.getModel()).getRowCount() - 1; i >= 0; i = i - 1) {
                            ((DefaultTableModel) jTable1.getModel()).removeRow(i);
                        }
                    }
                });
            }
        };
        t.start();
    }//GEN-LAST:event_jButton4ActionPerformed

    private void fifthStepFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_fifthStepFocusGained

        final JConsole console = new JConsole();
        console.setVisible(true);
        console.repaint();
        console.setSize(600, 426);
        console.setLocation(0, 0);
        beanshell.add(console);
        Interpreter interpreter = new Interpreter(console);
        try {
            /*
             * Load application libraries at runtime
             * BeanShell ClassLoader seems to accept .JAR or directories
             */
            Object[] applicationLibs = manager.getTask().getLibraries().toArray();
            for (int lCont = 0; lCont < applicationLibs.length; lCont++) {

                String absoluteVodka = ((File) applicationLibs[lCont]).getCanonicalPath();
                if (absoluteVodka.endsWith(".jar")) {
                    if (!File.separator.equalsIgnoreCase("/")) { 
                        //On Win, duplicates backslashes
                        absoluteVodka = absoluteVodka.replaceAll(Pattern.quote("\\"), "\\\\\\\\");
                    }
                    interpreter.eval("addClassPath(\"" + absoluteVodka + "\")");
                } else if (absoluteVodka.endsWith(".class")) {
                    String classPathName = JavaUtil.retrieveCanonicalNameFromClass(((File) applicationLibs[lCont]));
                    if (File.separator.equalsIgnoreCase("/")) {
                        classPathName = classPathName.replaceAll("\\.", "/") + ".class";
                    } else {
                        classPathName = classPathName.replaceAll("\\.", "\\\\\\\\") + ".class";
                        //On Win, duplicates backslashes
                        absoluteVodka = absoluteVodka.replaceAll(Pattern.quote("\\"), "\\\\\\\\");
                    }
                    absoluteVodka = absoluteVodka.replaceAll(Pattern.quote(classPathName), "");
                    interpreter.eval("addClassPath(\"" + absoluteVodka + "\")");
                }
            }
            interpreter.eval("import com.mtso.blazer.*");
            interpreter.eval("import *");
        } catch (EvalError ex) {
            manager.getStdErr().println("[!] BeanShell EvalErrorException: " + ex.toString().trim());
        } catch (IOException iex) {
            manager.getStdErr().println("[!] BeanShell IOException: " + iex.toString().trim());
        }

        //Catch exceptions in the BeanShell thread
        Thread.UncaughtExceptionHandler h = new Thread.UncaughtExceptionHandler() {
            public void uncaughtException(Thread th, Throwable ex) {
                manager.getStdErr().println("[!] BeanShell Exception: " + ex.toString().trim());
                manager.getStdErr().println("[!] Blazer will try to re-open the tab...");
                beanshell.remove(console);
                fifthStep.setSelectedIndex(0);
                fifthStep.setFocusable(true);
            }
        };

        Thread t = new Thread(interpreter);
        t.setUncaughtExceptionHandler(h);
        t.start();
    }//GEN-LAST:event_fifthStepFocusGained

    private void bytePoolFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_bytePoolFocusLost
        manager.getTask().setBytePool(buildPoolArray(bytePool.getText(), "byte"));
    }//GEN-LAST:event_bytePoolFocusLost

    private void shortPoolFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_shortPoolFocusLost
        manager.getTask().setShortPool(buildPoolArray(shortPool.getText(), "short"));
    }//GEN-LAST:event_shortPoolFocusLost

    private void intPoolFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_intPoolFocusLost
        manager.getTask().setIntPool(buildPoolArray(intPool.getText(), "int"));
    }//GEN-LAST:event_intPoolFocusLost

    private void longPoolFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_longPoolFocusLost
        manager.getTask().setLongPool(buildPoolArray(longPool.getText(), "long"));
    }//GEN-LAST:event_longPoolFocusLost

    private void floatPoolFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_floatPoolFocusLost
        manager.getTask().setFloatPool(buildPoolArray(floatPool.getText(), "float"));
    }//GEN-LAST:event_floatPoolFocusLost

    private void doublePoolFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_doublePoolFocusLost
        manager.getTask().setDoublePool(buildPoolArray(doublePool.getText(), "double"));
    }//GEN-LAST:event_doublePoolFocusLost

    private void booleanPoolFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_booleanPoolFocusLost
        manager.getTask().setBooleanPool(buildPoolArray(booleanPool.getText(), "boolean"));
    }//GEN-LAST:event_booleanPoolFocusLost

    private void charPoolFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_charPoolFocusLost
        manager.getTask().setCharPool(buildPoolArray(charPool.getText(), "char"));
    }//GEN-LAST:event_charPoolFocusLost

    private void stringPoolFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_stringPoolFocusLost
        manager.getTask().setStringPool(buildPoolArray(stringPool.getText(), "string"));
    }//GEN-LAST:event_stringPoolFocusLost

    private void proxyHostFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_proxyHostFocusLost
        manager.getTask().setProxyHost(proxyHost.getText());
    }//GEN-LAST:event_proxyHostFocusLost

    private void proxyPortFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_proxyPortFocusLost
        manager.getTask().setProxyPort(proxyPort.getText());
    }//GEN-LAST:event_proxyPortFocusLost

    private void jButtonExportActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonExportActionPerformed

        Exporter exporter = null;

        try {
            if (radioFile.isSelected()) {
                JFileChooser exportFileChooser = new javax.swing.JFileChooser();
                int returnVal = exportFileChooser.showSaveDialog(this);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    exporter = new Exporter(manager, reqCheckBox.isSelected(), respCheckBox.isSelected(), exportFileChooser.getSelectedFile());
                } else {
                    //user closed the FileChooser window or cancelled the selection, thus revert to console export
                    exporter = new Exporter(manager, reqCheckBox.isSelected(), respCheckBox.isSelected(), null);
                }
            } else {
                exporter = new Exporter(manager, reqCheckBox.isSelected(), respCheckBox.isSelected(), null);
            }

            //Export HTTP requests/responses (note: user may have selected multiple items) 
            exporter.export(manager.getItemsUserSelection());

        } catch (Exception ex) {
            manager.getStdErr().println("[!] AMF2XML Exporter GUI Exception:" + ex.toString().trim());
        }

    }//GEN-LAST:event_jButtonExportActionPerformed

    private void StepsPanelFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_StepsPanelFocusGained
        int tabFocus = StepsPanel.getSelectedIndex();
        switch (tabFocus) {
            case 0:
                firstStep.setSelectedIndex(0);
                break;
            case 1:
                secondStep.setSelectedIndex(0);
                break;
            case 2:
                thirdStep.setSelectedIndex(0);
                break;
            case 3:
                fourthStep.setSelectedIndex(0);
                break;
            case 4:
                fifthStep.setSelectedIndex(0);
                break;
            case 5:
                sixthStep.setSelectedIndex(0);
                break;
        }
    }//GEN-LAST:event_StepsPanelFocusGained

    private void vectorsListFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_vectorsListFocusLost
        String[] vectorStr = vectorsList.getText().split("\\\n");
        ArrayList vectors = new ArrayList(Arrays.asList(vectorStr));
        manager.getTask().setVectors(vectors);
    }//GEN-LAST:event_vectorsListFocusLost

    private void StepsPanelFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_StepsPanelFocusLost
        int tabFocus = StepsPanel.getSelectedIndex();
        switch (tabFocus) {
            case 0:
                firstStep.setSelectedIndex(0);
                break;
            case 1:
                secondStep.setSelectedIndex(0);
                break;
            case 2:
                thirdStep.setSelectedIndex(0);
                break;
            case 3:
                fourthStep.setSelectedIndex(0);
                break;
            case 4:
                fifthStep.setSelectedIndex(0);
                break;
            case 5:
                sixthStep.setSelectedIndex(0);
                break;
        }
    }//GEN-LAST:event_StepsPanelFocusLost
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel AMFReq3;
    private javax.swing.JLabel AMFReqSent;
    private javax.swing.JButton DeselectAllButton;
    private javax.swing.JButton SelectAllButton;
    private javax.swing.JButton StartButton;
    private javax.swing.JTabbedPane StepsPanel;
    private javax.swing.JButton StopButton;
    private javax.swing.JLabel attackVectors;
    private javax.swing.JLabel avgT;
    private javax.swing.JPanel beanshell;
    private javax.swing.JTextField booleanPool;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JTextField bytePool;
    private javax.swing.JTextField charPool;
    private javax.swing.JPanel datatype;
    private javax.swing.JTextField doublePool;
    private javax.swing.JPanel export;
    private javax.swing.JTabbedPane fifthStep;
    private javax.swing.JLabel finishT;
    private javax.swing.JLabel finishTLabel;
    private javax.swing.JTabbedPane firstStep;
    private javax.swing.JTextField floatPool;
    private javax.swing.JTabbedPane fourthStep;
    private javax.swing.JButton fuzzingButton;
    private javax.swing.JLabel fuzzingLabel1;
    private javax.swing.JLabel fuzzingLabel2;
    private javax.swing.JTextField intPool;
    private javax.swing.JCheckBox interfaceOnly;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton4;
    private javax.swing.JButton jButtonExport;
    private javax.swing.JCheckBox jCheckBox3;
    private javax.swing.JFileChooser jFileChooser1;
    private javax.swing.JFileChooser jFileChooser2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel102;
    private javax.swing.JLabel jLabel103;
    private javax.swing.JLabel jLabel104;
    private javax.swing.JLabel jLabel105;
    private javax.swing.JLabel jLabel106;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel110;
    private javax.swing.JLabel jLabel111;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel13;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel15;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel10;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JSeparator jSeparator14;
    private javax.swing.JTable jTable1;
    private javax.swing.JTree jTree4;
    private javax.swing.JPanel libraries;
    private javax.swing.JTextField longPool;
    private javax.swing.JLabel methodSignatures;
    private javax.swing.JPanel options;
    private javax.swing.JSlider permutations;
    private javax.swing.JPanel progress;
    private javax.swing.JProgressBar progressBar;
    private javax.swing.JTextField proxyHost;
    private javax.swing.JTextField proxyPort;
    private javax.swing.JRadioButton radioConsole;
    private javax.swing.JRadioButton radioFile;
    private javax.swing.JCheckBox remotingIncludeOnly;
    private javax.swing.JCheckBox reqCheckBox;
    private javax.swing.JCheckBox respCheckBox;
    private javax.swing.JTabbedPane secondStep;
    private javax.swing.JTextField shortPool;
    private javax.swing.JPanel signatures;
    private javax.swing.JTabbedPane sixthStep;
    private javax.swing.JLabel status;
    private javax.swing.JLabel statusTask;
    private javax.swing.JTextField stringPool;
    private javax.swing.JTabbedPane thirdStep;
    private javax.swing.JSlider threads;
    private javax.swing.JLabel totT;
    private javax.swing.JLabel totTLabel;
    private javax.swing.JSlider vectorsLikelihood;
    private javax.swing.JTextArea vectorsList;
    // End of variables declaration//GEN-END:variables

    private ArrayList buildPoolArray(String textPool, String type) {
        ArrayList objectPool = new ArrayList();
        String[] strPool = textPool.split(",");
        for (int i = 0; i < strPool.length; i++) {
            strPool[i] = strPool[i].trim();
            if (type.equalsIgnoreCase("byte")) {
                objectPool.add(Byte.parseByte(strPool[i]));
            } else if (type.equalsIgnoreCase("short")) {
                objectPool.add(Short.parseShort(strPool[i]));
            } else if (type.equalsIgnoreCase("int")) {
                objectPool.add(Integer.parseInt(strPool[i]));
            } else if (type.equalsIgnoreCase("long")) {
                objectPool.add(Long.parseLong(strPool[i]));
            } else if (type.equalsIgnoreCase("float")) {
                objectPool.add(Float.parseFloat(strPool[i]));
            } else if (type.equalsIgnoreCase("double")) {
                objectPool.add(Double.parseDouble(strPool[i]));
            } else if (type.equalsIgnoreCase("boolean")) {
                objectPool.add(Boolean.parseBoolean(strPool[i]));
            } else if (type.equalsIgnoreCase("char")) {
                objectPool.add(strPool[i].charAt(0));
            } else if (type.equalsIgnoreCase("string")) {
                objectPool.add(strPool[i]);
            }
        }
        return objectPool;
    }

    private void displayAllSignaturesThread() {

        remotingIncludeOnly.setSelected(false);
        interfaceOnly.setSelected(false);
        // It may take several seconds. Adding a new Thread
        secondStep.setTitleAt(secondStep.getSelectedIndex(), "Loading...");

        Thread t = new Thread() {
            @Override
            public void run() {
                displayAllSignatures();
            }
        };
        t.start();
    }

    private void displayAllSignatures() {

        ArrayList allSign = manager.getTask().getSignatures();
        if (allSign != null) {
            final Iterator listSign = allSign.iterator();

            SwingUtilities.invokeLater(new Runnable() {
                //This is called later by the event dispatch thread
                //See http://www.javamex.com/tutorials/threads/invokelater.shtml
                public void run() {
                    SelectAllButton.setEnabled(false);
                    DeselectAllButton.setEnabled(false);
                    remotingIncludeOnly.setEnabled(false);
                    interfaceOnly.setEnabled(false);

                    ((DefaultTableModel) jTable1.getModel()).getDataVector().removeAllElements();

                    while (listSign.hasNext()) {
                        Object[] row = (Object[]) listSign.next();
                        ((DefaultTableModel) jTable1.getModel()).addRow(row);
                    }
                    ((DefaultTableModel) jTable1.getModel()).fireTableDataChanged();
                    SelectAllButton.setEnabled(true);
                    DeselectAllButton.setEnabled(true);
                    remotingIncludeOnly.setEnabled(true);
                    interfaceOnly.setEnabled(true);
                    secondStep.setTitleAt(secondStep.getSelectedIndex(), "Remote Method Signatures");
                }
            });
        }
    }
}

class JARClassesSourceFileFilter extends FileFilter {

    public boolean accept(File pathname) {
        if (pathname.isDirectory() || pathname.getName().endsWith(".jar") || pathname.getName().endsWith(".class") || pathname.getName().endsWith(".java")) {
            return true;
        }
        return false;
    }

    public String getDescription() {
        return "JAR/Java/Class files";
    }
}

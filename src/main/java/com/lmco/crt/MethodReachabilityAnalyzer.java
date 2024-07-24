package com.lmco.crt;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

public class MethodReachabilityAnalyzer {

    private final Map<String, Set<String>> callGraph = new HashMap<>();
    private final Set<String> reachableMethods = new HashSet<>();
    private final Set<String> allMethods = new HashSet<>();

    public static void main(String[] args) throws IOException {

        File jarFile = new File("jars\\crt-service-all-1.0-SNAPSHOT.jar");
        MethodReachabilityAnalyzer analyzer = new MethodReachabilityAnalyzer();
        analyzer.analyzeJar(jarFile);
        analyzer.writeResultsToFile("ReachableMethods", "NonReachableMethods");
        //analyzer.printResults();
    }

    public void analyzeJar(File jarFile) throws IOException {
        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".class") && !entry.getName().contains("META-INF/")) {
                    try {
                        analyzeClass(jar, entry);
                    } catch (SecurityException | IOException e) {
                        System.err.println("Skipping entry due to error: " + entry.getName() + " - " + e.getMessage());
                    }
                }
            }
        }
        findReachableMethods();
    }

    private void analyzeClass(JarFile jar, JarEntry entry) throws IOException {
        try (InputStream inputStream = jar.getInputStream(entry)) {
            ClassReader classReader = new ClassReader(inputStream);
            ClassNode classNode = new ClassNode();
            classReader.accept(classNode, 0);

            for (MethodNode method : classNode.methods) {
                String methodName = classNode.name + "." + method.name + method.desc;
                allMethods.add(methodName);
                Set<String> calledMethods = new HashSet<>();
                if (method.instructions != null) {
                    for (AbstractInsnNode insn : method.instructions) {
                        if (insn.getType() == AbstractInsnNode.METHOD_INSN) {
                            MethodInsnNode methodInsn = (MethodInsnNode) insn;
                            calledMethods.add(methodInsn.owner + "." + methodInsn.name + methodInsn.desc);
                        }
                    }
                }
                callGraph.put(methodName, calledMethods);
            }
        }
    }

    private void findReachableMethods() {
        // Assuming the entry points are public static void main(String[] args) methods
        for (String method : callGraph.keySet()) {
            if (method.endsWith("main([Ljava/lang/String;)V")) {
                traverseCallGraph(method);
            }
        }
    }

    private void traverseCallGraph(String method) {
        if (reachableMethods.contains(method)) {
            return;
        }
        reachableMethods.add(method);
        Set<String> calledMethods = callGraph.get(method);
        if (calledMethods != null) {
            for (String calledMethod : calledMethods) {
                traverseCallGraph(calledMethod);
            }
        }
    }

    private void writeResultsToFile(String reachableFileName, String nonReachableFileName) throws IOException {
        try (FileWriter reachableWriter = new FileWriter(reachableFileName);
             FileWriter nonReachableWriter = new FileWriter(nonReachableFileName)) {

            reachableWriter.write("Reachable Methods:\n");
            for (String method : reachableMethods) {
                reachableWriter.write(method + "\n");
            }

            nonReachableWriter.write("Non-Reachable Methods:\n");
            for (String method : allMethods) {
                if (!reachableMethods.contains(method)) {
                    nonReachableWriter.write(method + "\n");
                }
            }
        }
    }

    private void printResults() {
        System.out.println("Reachable Methods:");
        for (String method : reachableMethods) {
            System.out.println(method);
        }

//        System.out.println("\nNon-Reachable Methods:");
//        for (String method : allMethods) {
//            if (!reachableMethods.contains(method)) {
//                System.out.println(method);
//            }
//        }
    }
}

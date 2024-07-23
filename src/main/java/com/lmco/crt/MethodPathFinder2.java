package com.lmco.crt;

import com.lmco.crt.util.Utilities;
import org.apache.commons.compress.archivers.jar.JarArchiveEntry;
import org.apache.commons.compress.archivers.jar.JarArchiveInputStream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class MethodPathFinder2 {
    private static final Map<String, List<String>> TARGET_MAP = Utilities.readCsvFromResources("VulnerableCode.csv");

    static class ClassInfo {
        boolean isAbstract;
        String superClass;
        ClassNode classNode;

        ClassInfo(boolean isAbstract, String superClass, ClassNode classNode) {
            this.isAbstract = isAbstract;
            this.superClass = superClass;
            this.classNode = classNode;
        }
    }

    public static void main(String[] args) throws IOException {

        String jarPath = "jars\\crt-service-all-1.0-SNAPSHOT.jar";

        Map<String, ClassInfo> classInfoMap = extractClassesFromJar(jarPath);
        Map<String, List<String>> methodCallGraph = buildMethodCallGraph(classInfoMap);
        Map<String, Map<String, List<List<String>>>> vulnerableCodePathsMap = new HashMap<>();
        Map<String, List<List<String>>> methodPathsMap = null;
        for (Map.Entry<String, List<String>> vulnerableCodeMapping : TARGET_MAP.entrySet()) {
            methodPathsMap = new HashMap<>();
            String vulnerabilityId = vulnerableCodeMapping.getKey();
            List<String> vulnerableCodeList = vulnerableCodeMapping.getValue();
            for (String vulnerableCodeSource : vulnerableCodeList) {
                TreeNode<String> root = new TreeNode<>(vulnerableCodeSource);
                // Vulnerable code is for an entire class and not a specific method
                if (!vulnerableCodeSource.contains(".")) {
                    List<String> classMethods = collectClassMethods(methodCallGraph, vulnerableCodeSource);
                    for (String classMethod : classMethods) {
                        createMethodCallTree(classInfoMap, methodCallGraph, classMethod, root);
                    }
                }
                else {
                    createMethodCallTree(classInfoMap, methodCallGraph, vulnerableCodeSource, root);
                }
                //createMethodCallTree(classInfoMap, methodCallGraph, vulnerableCodeSource, root);
                List<List<String>> allMethodPaths = getAllMethodPaths(root);
                methodPathsMap.put(root.data, allMethodPaths);
                vulnerableCodePathsMap.put(vulnerabilityId, methodPathsMap);
            }
        }
//        for (Map.Entry<String, Map<String, List<List<String>>>> vulnPathMapping : vulnerableCodePathsMap.entrySet()) {
//            String vulnId = vulnPathMapping.getKey();
//            Map<String, List<List<String>>> vulnPathSubMap = vulnPathMapping.getValue();
//            for (Map.Entry<String, List<List<String>>> vulnerableCodePaths : vulnPathSubMap.entrySet()) {
//                String vulnerableCode = vulnerableCodePaths.getKey();
//                List<List<String>> codeExecutionPaths = vulnerableCodePaths.getValue();
//                for (List<String> codeExecutionPath : codeExecutionPaths) {
//                    Collections.reverse(codeExecutionPath);
//                    System.out.println("VulnId:" + vulnId + ", " + "VulnerableCode: " + vulnerableCode + ", " + "Execution Path: " + codeExecutionPath.toString());
//                }
//            }
//        }
        System.out.println("breakpoint");

        assert methodPathsMap != null;
        writePathsToFile(vulnerableCodePathsMap);
    }

    private static Map<String, ClassInfo> extractClassesFromJar(String jarPath) throws IOException {
        Map<String, ClassInfo> classInfoMap = new HashMap<>();
        try (JarArchiveInputStream jarInputStream = new JarArchiveInputStream(Files.newInputStream(Paths.get(jarPath)))) {
            JarArchiveEntry entry;
            while ((entry = jarInputStream.getNextJarEntry()) != null) {
                if (entry.getName().endsWith(".class") && !entry.getName().contains("META-INF/")) {
                    ClassReader classReader = new ClassReader(jarInputStream);
                    ClassNode classNode = new ClassNode();
                    classReader.accept(classNode, 0);
                    boolean isAbstract = (classNode.access & Opcodes.ACC_ABSTRACT) != 0;
                    String superClass = classNode.superName;
                    classInfoMap.put(classNode.name, new ClassInfo(isAbstract, superClass, classNode));
                }
            }
        }
        return classInfoMap;
    }

    private static Map<String, List<String>> buildMethodCallGraph(Map<String, ClassInfo> classInfoMap) {
        Map<String, List<String>> methodCallGraph = new HashMap<>();
        for (ClassInfo classInfo : classInfoMap.values()) {
            ClassNode classNode = classInfo.classNode;
            for (MethodNode method : classNode.methods) {
                String methodName = classNode.name + "." + method.name;
                methodCallGraph.putIfAbsent(methodName, new ArrayList<>());
                InsnList instructions = method.instructions;
                for (AbstractInsnNode insn : instructions) {
                    if (insn.getType() == AbstractInsnNode.METHOD_INSN) {
                        MethodInsnNode methodInsn = (MethodInsnNode) insn;
                        String calledMethodName = methodInsn.owner + "." + methodInsn.name;
                        methodCallGraph.get(methodName).add(calledMethodName);
                    }
                }
            }
        }
        return methodCallGraph;
    }

    private static void createMethodCallTree(Map<String, ClassInfo> classInfoMap, Map<String, List<String>> methodCallGraph,
                                             String targetMethodFullName, TreeNode<String> node) {
        for (Map.Entry<String, List<String>> methodCallEntry : methodCallGraph.entrySet()) {
            String callingMethodFullName = methodCallEntry.getKey();
            if (methodCallEntry.getValue().contains(targetMethodFullName)) {
                String callingMethodClass = callingMethodFullName.substring(0, callingMethodFullName.lastIndexOf('.'));
                boolean isAbstract = isDerivedFromAbstractClass(classInfoMap, callingMethodClass);
                TreeNode<String> child = node.addChild(callingMethodFullName);
                if (!isAbstract) {
                    createMethodCallTree(classInfoMap, methodCallGraph, callingMethodFullName, child);
                }
            }
        }
    }

    private static List<String> collectClassMethods(Map<String, List<String>> methodCallGraph, String vulnerableCodeSource) {
        List<String> classMethods = new ArrayList<>();
        for (Map.Entry<String, List<String>> methodCallEntry : methodCallGraph.entrySet()) {
            if (methodCallEntry.getKey().contains(vulnerableCodeSource)) {
                classMethods.add(methodCallEntry.getKey());
            }
        }

        return classMethods;
    }

    public static List<List<String>> getAllMethodPaths(TreeNode<String> root) {
        List<List<String>> result = new ArrayList<>();
        if (root == null) {
            return result;
        }

        List<String> currentPath = new ArrayList<>();
        depthFirstSearch(root, currentPath, result);
        return result;
    }

    private static void depthFirstSearch(TreeNode<String> node, List<String> currentPath, List<List<String>> result) {
        if (node == null) {
            return;
        }

        currentPath.add(node.data);

        if (node.children.isEmpty()) {
            result.add(new ArrayList<>(currentPath));
        } else {
            for (TreeNode<String> child : node.children) {
                depthFirstSearch(child, currentPath, result);
            }
        }

        currentPath.remove(currentPath.size() - 1);
    }

    private static boolean isDerivedFromAbstractClass(Map<String, ClassInfo> classInfoMap, String className) {
        ClassInfo classInfo = classInfoMap.get(className);
        while (classInfo != null) {
            if (classInfo.isAbstract) {
                return true;
            }
            classInfo = classInfoMap.get(classInfo.superClass);
        }
        return false;
    }

    private static void writePathsToFile(Map<String, Map<String, List<List<String>>>> vulnerableCodePathsMap) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("output3.txt"))) {
            for (Map.Entry<String, Map<String, List<List<String>>>> vulnPathMapping : vulnerableCodePathsMap.entrySet()) {
                String vulnId = vulnPathMapping.getKey();
                writer.write("Vulnerability ID: " + vulnId + "\n");
                Map<String, List<List<String>>> vulnPathSubMap = vulnPathMapping.getValue();
                for (Map.Entry<String, List<List<String>>> vulnerableCodePaths : vulnPathSubMap.entrySet()) {
                    String vulnerableCode = vulnerableCodePaths.getKey();
                    writer.write("  Vulnerable Code: " + vulnerableCode + "\n");
                    List<List<String>> codeExecutionPaths = vulnerableCodePaths.getValue();
                    for (List<String> codeExecutionPath : codeExecutionPaths) {
                        Collections.reverse(codeExecutionPath);
                        writer.write("      Execution Path: " + codeExecutionPath + "\n");
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}


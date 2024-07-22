package com.lmco.crt;

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

public class MethodPathFinder {
    private static final List<String> TARGETS = ReadFileToList.readFileFromResources("VulnerableMethods.txt");

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

        String jarPath = "jars\\jackson-databind-2.18.0-SNAPSHOT-with-dependencies.jar";

        Map<String, ClassInfo> classInfoMap = extractClassesFromJar(jarPath);
        Map<String, List<String>> methodCallGraph = buildMethodCallGraph(classInfoMap);
        Map<String, List<List<String>>> allMethodPathsMap = new HashMap<>();
        for (String targetMethodFullName : TARGETS) {
            TreeNode<String> root = new TreeNode<>(targetMethodFullName);
            createMethodCallTree(classInfoMap, methodCallGraph, targetMethodFullName, root);
            List<List<String>> allMethodPaths = getAllMethodPaths(root);
            allMethodPathsMap.put(root.data, allMethodPaths);
            for (List<String> path : allMethodPaths) {
                System.out.println(path);
            }
            System.out.println("breakpoint");
        }

        writePathsToFile(allMethodPathsMap);
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
            for (MethodNode method : (List<MethodNode>) classNode.methods) {
                String methodName = classNode.name + "." + method.name;
                methodCallGraph.putIfAbsent(methodName, new ArrayList<>());
                InsnList instructions = method.instructions;
                for (Iterator<AbstractInsnNode> it = instructions.iterator(); it.hasNext(); ) {
                    AbstractInsnNode insn = it.next();
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

    private static void createMethodCallTree(Map<String, ClassInfo> classInfoMap, Map<String, List<String>> methodCallGraph, String targetMethodFullName, TreeNode<String> node) {
        for (Map.Entry<String, List<String>> methodCallEntry : methodCallGraph.entrySet()) {
            String callingMethodFullName = methodCallEntry.getKey();
            List<String> calledMethodFullNames = methodCallEntry.getValue();
            if (methodCallEntry.getValue().contains(targetMethodFullName)) {
                System.out.println("CallingMethod: " + callingMethodFullName);
                String callingMethodClass = callingMethodFullName.substring(0, callingMethodFullName.lastIndexOf('.'));
                boolean isAbstract = isDerivedFromAbstractClass(classInfoMap, callingMethodClass);
                TreeNode<String> child = node.addChild(callingMethodFullName);
                if (!isAbstract) {
                    createMethodCallTree(classInfoMap, methodCallGraph, callingMethodFullName, child);
                }
            }
        }
    }

    private static String createIndent(int depth) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            sb.append(' ');
        }
        return sb.toString();
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

    private static void writePathsToFile(Map<String, List<List<String>>> allMethodPathsMap) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("output.txt"))) {
            for (Map.Entry<String, List<List<String>>> entry : allMethodPathsMap.entrySet()) {
                writer.write("Vulnerable Method: " + entry.getKey() + "\n");
                for (List<String> list : entry.getValue()) {
                    writer.write("  Execution Path: " + list.toString() + "\n");
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}


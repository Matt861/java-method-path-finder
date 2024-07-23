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

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class MethodPathFinder3 {
    private static final String TARGET_CLASS = "com/fasterxml/jackson/core/JsonFactory";
    private static final String TARGET_METHOD = "streamReadConstraints";

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
        findPathsToTargetMethod(classInfoMap, methodCallGraph, TARGET_CLASS, TARGET_METHOD);
        findPathsToClassInitialization(classInfoMap, methodCallGraph, TARGET_CLASS);
    }

    private static Map<String, ClassInfo> extractClassesFromJar(String jarPath) throws IOException {
        Map<String, ClassInfo> classInfoMap = new HashMap<>();
        try (JarArchiveInputStream jarInputStream = new JarArchiveInputStream(new FileInputStream(jarPath))) {
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

    private static void findPathsToTargetMethod(Map<String, ClassInfo> classInfoMap, Map<String, List<String>> methodCallGraph, String targetClass, String targetMethod) {
        String targetMethodName = targetClass + "." + targetMethod;
        Set<String> globalVisited = new HashSet<>();
        for (String method : methodCallGraph.keySet()) {
            List<String> path = new ArrayList<>();
            findPaths(classInfoMap, methodCallGraph, method, targetMethodName, globalVisited, path, new HashSet<>());
        }
    }

    private static boolean findPaths(Map<String, ClassInfo> classInfoMap, Map<String, List<String>> methodCallGraph, String currentMethod, String targetMethod, Set<String> globalVisited, List<String> path, Set<String> currentPath) {
        if (globalVisited.contains(currentMethod) || currentPath.contains(currentMethod)) {
            return false;
        }
        globalVisited.add(currentMethod);
        currentPath.add(currentMethod);
        path.add(currentMethod);

        if (currentMethod.equals(targetMethod)) {
            System.out.println("Path found: " + path);
            path.remove(path.size() - 1);
            currentPath.remove(currentMethod);
            return true;
        }

        if (methodCallGraph.containsKey(currentMethod)) {
            for (String nextMethod : methodCallGraph.get(currentMethod)) {
                if (!currentPath.contains(nextMethod)) {
                    findPaths(classInfoMap, methodCallGraph, nextMethod, targetMethod, globalVisited, path, currentPath);
                }
            }
        }

        path.remove(path.size() - 1);
        currentPath.remove(currentMethod);
        return false;
    }

    private static void findPathsToClassInitialization(Map<String, ClassInfo> classInfoMap, Map<String, List<String>> methodCallGraph, String targetClass) {
        String clinitMethodName = targetClass + ".__clinit__";
        String initMethodName = targetClass + ".__init__";
        Set<String> globalVisited = new HashSet<>();
        for (String method : methodCallGraph.keySet()) {
            List<String> path = new ArrayList<>();
            findPaths(classInfoMap, methodCallGraph, method, clinitMethodName, globalVisited, path, new HashSet<>());
            findPaths(classInfoMap, methodCallGraph, method, initMethodName, globalVisited, path, new HashSet<>());
        }
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
}


package com.lmco.crt;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

public class MethodReachabilityAnalyzer4 {

    private final Map<String, Set<String>> callGraph = new HashMap<>();
    private final Set<String> reachableMethods = new HashSet<>();
    private final Set<String> allMethods = new HashSet<>();
    private final Map<String, List<List<String>>> pathsToMethods = new HashMap<>();
    private final Map<String, Set<String>> interfaceImplementations = new HashMap<>();

    public static void main(String[] args) throws IOException {

        File jarFile = new File("jars\\crt-service-all-1.0-SNAPSHOT.jar");
        String targetMethod = "com/fasterxml/jackson/databind/SerializerProvider.findTypedValueSerializer(Lcom/fasterxml/jackson/databind/JavaType;ZLcom/fasterxml/jackson/databind/BeanProperty;)Lcom/fasterxml/jackson/databind/JsonSerializer";
        MethodReachabilityAnalyzer4 analyzer = new MethodReachabilityAnalyzer4();
        analyzer.analyzeJar(jarFile);
        analyzer.writeResultsToFile("ReachableMethods", "NonReachableMethods");
        analyzer.printPathsToMethod(targetMethod);

        // Example usage of the new method
        String className = "com/fasterxml/jackson/databind/SerializerProvider";
        String methodName = "findTypedValueSerializer"; // or null/empty for all methods in the class
        List<String> matchingMethods = analyzer.findMethodsByClassAndName(className, methodName);
        System.out.println("Matching methods for class " + className + " and method " + methodName + ":");
        for (String method : matchingMethods) {
            System.out.println(method);
        }
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

            if ((classNode.access & Opcodes.ACC_INTERFACE) != 0) {
                // It's an interface, map its methods to the implementations
                for (String interfaceName : classNode.interfaces) {
                    interfaceImplementations.computeIfAbsent(interfaceName, k -> new HashSet<>()).add(classNode.name);
                }
            }

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
        // Start from main methods, constructors, and public methods
        for (String method : callGraph.keySet()) {
            if (isEntryPoint(method)) {
                traverseCallGraph(method, new ArrayList<>());
            }
        }
    }

    private boolean isEntryPoint(String method) {
        return method.endsWith("main([Ljava/lang/String;)V") ||
                method.contains("<init>") || // Constructors
                isPublicMethod(method); // Public methods
    }

    private boolean isPublicMethod(String method) {
        // Assuming method signatures are in the form of "className.methodName()desc"
        String[] parts = method.split("\\.");
        if (parts.length < 2) {
            return false;
        }

        String className = parts[0];
        String methodName = parts[1];

        // Logic to determine if the method is public can be enhanced based on the project requirements.
        // For simplicity, let's assume if it is not a private or protected method name, we treat it as public.
        return !methodName.startsWith("private") && !methodName.startsWith("protected");
    }

    private void traverseCallGraph(String method, List<String> path) {
        if (reachableMethods.contains(method)) {
            return;
        }
        reachableMethods.add(method);
        path.add(method);

        if (!pathsToMethods.containsKey(method)) {
            pathsToMethods.put(method, new ArrayList<>());
        }
        pathsToMethods.get(method).add(new ArrayList<>(path));

        Set<String> calledMethods = callGraph.get(method);
        if (calledMethods != null) {
            for (String calledMethod : calledMethods) {
                traverseCallGraph(calledMethod, path);
                // Also traverse implementations if it's an interface method
                String className = calledMethod.substring(0, calledMethod.indexOf('.'));
                if (interfaceImplementations.containsKey(className)) {
                    for (String implClass : interfaceImplementations.get(className)) {
                        String implMethod = implClass + calledMethod.substring(calledMethod.indexOf('.'));
                        traverseCallGraph(implMethod, path);
                    }
                }
            }
        }

        path.remove(path.size() - 1);
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

    private void printPathsToMethod(String targetMethod) {
        System.out.println("Paths to method " + targetMethod + ":");
        if (pathsToMethods.containsKey(targetMethod)) {
            for (List<String> path : pathsToMethods.get(targetMethod)) {
                System.out.println(String.join(" -> ", path));
            }
        } else {
            System.out.println("No paths found to the specified method.");
        }
    }

    // Updated method to find methods by class and optional method name
    public List<String> findMethodsByClassAndName(String className, String methodName) {
        return allMethods.stream()
                .filter(method -> method.startsWith(className + ".") &&
                        (methodName == null || methodName.isEmpty() || method.contains("." + methodName + "(")))
                .collect(Collectors.toList());
    }
}


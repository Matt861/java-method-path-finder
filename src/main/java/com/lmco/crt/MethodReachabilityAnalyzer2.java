package com.lmco.crt;

import com.lmco.crt.util.Utilities;
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

public class MethodReachabilityAnalyzer2 {

    private final Map<String, Set<String>> callGraph = new HashMap<>();
    private final Set<String> reachableMethods = new HashSet<>();
    private final Set<String> allMethods = new HashSet<>();
    private final Map<String, List<List<String>>> pathsToMethods = new HashMap<>();
    private static final Map<String, List<String>> TARGET_MAP = Utilities.readCsvFromResources("VulnerableCode.csv");

    public static void main(String[] args) throws IOException {

        File jarFile = new File("jars\\crt-service-all-1.0-SNAPSHOT.jar");
        String targetMethod = "kafka/utils/timer/TimerTask.kafka$utils$timer$TimerTask$$timerTaskEntry_$eq(Lkafka/utils/timer/TimerTaskEntry;)V";
        MethodReachabilityAnalyzer2 analyzer = new MethodReachabilityAnalyzer2();
        analyzer.analyzeJar(jarFile);
        analyzer.printPathsToMethod(targetMethod);
        //analyzer.writeResultsToFile("ReachableMethods.txt", "NonReachableMethods.txt");
        //analyzer.printPathsToMethods(TARGET_MAP);
        //analyzer.printPathsToMethod(targetMethod);
//        Map<String, List<String>> updatedTargetMap = new HashMap<>(TARGET_MAP);
//        analyzer.updateVulnerableMethods(updatedTargetMap);
//        String className = "com/fasterxml/jackson/databind/SerializerProvider";
//        String methodName = "findTypedValueSerializer";
//        List<String> matchingMethods = analyzer.findMethodsByClassAndName(className, methodName);
//        System.out.println("Matching methods for class " + className + " and method " + methodName + ":");
//        for (String method : matchingMethods) {
//            System.out.println(method);
//        }
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

    private void updateVulnerableMethods(Map<String, List<String>> updatedTargetMap) {
        for (Map.Entry<String, List<String>> targetMapEntry : updatedTargetMap.entrySet()) {
            List<String> updatedTargets = new ArrayList<>();
            String vulnId = targetMapEntry.getKey();
            List<String> targets = targetMapEntry.getValue();
            for (String target : targets) {
                List<String> newTargets = new ArrayList<>();
                // Target is a class and method
                if (target.contains(".")) {
                    String[] targetParts = target.split("\\.");
                    newTargets = findMethodsByClassAndName(targetParts[0], targetParts[1]);
                }
                else {
                    newTargets = findMethodsByClassAndName(target, null);
                }
                updatedTargets.addAll(newTargets);
            }
            updatedTargetMap.put(vulnId, updatedTargets);
        }
    }

    public List<String> findMethodsByClassAndName(String className, String methodName) {
        return allMethods.stream()
                .filter(method -> method.startsWith(className + ".") &&
                        (methodName == null || methodName.isEmpty() || method.contains("." + methodName + "(")))
                .collect(Collectors.toList());
    }

    private void findReachableMethods() {
        // Assuming the entry points are public static void main(String[] args) methods
        for (String method : callGraph.keySet()) {
            if (method.endsWith("main([Ljava/lang/String;)V")) {
                traverseCallGraph(method, new ArrayList<>());
            }
        }
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
            }
        }

        path.remove(path.size() - 1);
    }

    private void writeResultsToFile(String reachableFileName, String nonReachableFileName) throws IOException {
        try (FileWriter reachableWriter = new FileWriter("output\\" + reachableFileName);
             FileWriter nonReachableWriter = new FileWriter("output\\" + nonReachableFileName)) {

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

    private void printPathsToMethods(Map<String, List<String>> targetMap) {
        //System.out.println("Paths to method " + targetMethod + ":");
        for (Map.Entry<String, List<String>> targetMapEntry : targetMap.entrySet()) {
            String vulnId = targetMapEntry.getKey();
            List<String> targets = targetMapEntry.getValue();
            for (String target : targets) {
                if (pathsToMethods.containsKey(target)) {
                    for (List<String> path : pathsToMethods.get(target)) {
                        System.out.println(String.join(" -> ", path));
                    }
                } else {
                    System.out.println("No paths found to the specified method.");
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
}


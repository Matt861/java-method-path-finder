package com.lmco.crt;

import com.lmco.crt.util.Utilities;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

public class MethodReachabilityAnalyzer3 {

    private final Map<String, Set<String>> callGraph = new HashMap<>();
    private final Set<String> reachableMethods = new HashSet<>();
    private final Set<String> allMethods = new HashSet<>();
    private final Map<String, List<List<String>>> pathsToMethods = new HashMap<>();
    private static final Map<String, List<String>> TARGET_MAP = Utilities.readCsvFromResources("VulnerableCode.csv");
    private final Map<String, Set<String>> interfaceImplementations = new HashMap<>();

    public static void main(String[] args) throws IOException {
        File jarFile = new File("jars\\crt-service-all-1.0-SNAPSHOT.jar");
        MethodReachabilityAnalyzer3 analyzer = new MethodReachabilityAnalyzer3();
        analyzer.analyzeJar(jarFile);
        Map<String, List<String>> updatedTargetMap = analyzer.updateVulnerableMethods();
        Map<String, Map<String, List<List<String>>>> vulnerableCodePathsMap = analyzer.getMethodExecutionPaths2(updatedTargetMap);
        analyzer.writePathsToFile(vulnerableCodePathsMap);
        System.out.println("breakpoint");
    }

    private void writePathsToFile(Map<String, Map<String, List<List<String>>>> vulnerableCodePathsMap) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("output6.txt"))) {
            for (Map.Entry<String, Map<String, List<List<String>>>> vulnPathMapping : vulnerableCodePathsMap.entrySet()) {
                String vulnId = vulnPathMapping.getKey();
                writer.write("Vulnerability ID: " + vulnId + "\n");
                Map<String, List<List<String>>> vulnPathSubMap = vulnPathMapping.getValue();
                for (Map.Entry<String, List<List<String>>> vulnerableCodePaths : vulnPathSubMap.entrySet()) {
                    String vulnerableCode = vulnerableCodePaths.getKey();
                    writer.write("  Vulnerable Code: " + vulnerableCode + "\n");
                    List<List<String>> codeExecutionPaths = vulnerableCodePaths.getValue();
                    if (!codeExecutionPaths.isEmpty()) {
                        for (List<String> codeExecutionPath : codeExecutionPaths) {
                            writer.write("      Execution Path: \n");
                            StringBuilder sb = new StringBuilder("          ");
                            Collections.reverse(codeExecutionPath);
                            for (String path : codeExecutionPath) {
                                sb.append(" ");
                                writer.write(sb + "->" + path + "\n");
                            }
                        }
                    }
                    else {
                        writer.write("      Execution Path: N/A \n");
                    }

                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private Map<String, Map<String, List<List<String>>>> getMethodExecutionPaths2(Map<String, List<String>> updatedTargetMap) {
        Map<String, Map<String, List<List<String>>>> vulnerableCodePathsMap = new HashMap<>();
        for (Map.Entry<String, List<String>> targetMapEntry : updatedTargetMap.entrySet()) {
            Map<String, List<List<String>>> methodPathsMap = new HashMap<>();
            String vulnId = targetMapEntry.getKey();
            List<String> targets = targetMapEntry.getValue();
            for (String target : targets) {
                TreeNode<String> root = new TreeNode<>(target);
                findCallingMethods(root);
                System.out.println("breakpoint");
                List<List<String>> allMethodPaths = getAllMethodPaths(root);
                methodPathsMap.put(root.data, allMethodPaths);
            }
            vulnerableCodePathsMap.put(vulnId, methodPathsMap);
        }
        return vulnerableCodePathsMap;
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

    public void findCallingMethods(TreeNode<String> node) {
        for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
            String callingMethod = entry.getKey();
            if (entry.getValue().contains(node.data)) {
                TreeNode<String> child = node.addChild(callingMethod);
                findCallingMethods(child);
            }
        }
    }

    private Map<String, Map<String, List<List<String>>>> getMethodExecutionPaths(Map<String, List<String>> updatedTargetMap) {
        Map<String, Map<String, List<List<String>>>> vulnerableCodePathsMap = new HashMap<>();
        for (Map.Entry<String, List<String>> targetMapEntry : updatedTargetMap.entrySet()) {
            Map<String, List<List<String>>> methodPathsMap = new HashMap<>();
            List<List<String>> methodPaths = new ArrayList<>();
            String vulnId = targetMapEntry.getKey();
            List<String> targets = targetMapEntry.getValue();
            for (String target : targets) {
                if (pathsToMethods.containsKey(target)) {
                    for (List<String> path : pathsToMethods.get(target)) {
                        methodPaths.add(path);
                        System.out.println(String.join(" -> ", path));
                    }
                } else {
                    System.out.println("No paths found to the specified method.");
                }
                methodPathsMap.put(target, methodPaths);
            }
            vulnerableCodePathsMap.put(vulnId, methodPathsMap);
        }
        return vulnerableCodePathsMap;
    }

    private Map<String, List<String>> updateVulnerableMethods() {
        Map<String, List<String>> updatedTargetMap = new HashMap<>(TARGET_MAP);
        for (Map.Entry<String, List<String>> targetMapEntry : updatedTargetMap.entrySet()) {
            List<String> updatedTargets = new ArrayList<>();
            String vulnId = targetMapEntry.getKey();
            List<String> targets = targetMapEntry.getValue();
            for (String target : targets) {
                List<String> newTargets;
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

        return updatedTargetMap;
    }

    public List<String> findMethodsByClassAndName(String className, String methodName) {
        return allMethods.stream()
                .filter(method -> method.startsWith(className + ".") &&
                        (methodName == null || methodName.isEmpty() || method.contains("." + methodName + "(")))
                .collect(Collectors.toList());
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
        // Assuming the entry points are public static void main(String[] args) methods
        for (String method : callGraph.keySet()) {
            //traverseCallGraph(method, new ArrayList<>());
            if (isEntryPoint(method)) {
                traverseCallGraph(method, new ArrayList<>());
            }

//            if (method.endsWith("main([Ljava/lang/String;)V")) {
//
//                traverseCallGraph(method, new ArrayList<>());
//            }
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
}

package com.lmco.crt.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;

public class Utilities {

    public static Map<String, List<String>> readCsvFromResources(String csvFilePath) {

        String line;
        String csvSplitBy = ",";

        Map<String, List<String>> vulnerableCodeMap = new HashMap<>();

        // Use the class loader to get the resource
        ClassLoader classLoader = Utilities.class.getClassLoader();
        try (InputStream is = classLoader.getResourceAsStream(csvFilePath);
             BufferedReader br = new BufferedReader(new InputStreamReader(is))) {

            // This check is still useful for robustness despite IDE warning
            if (is == null) {
                throw new IllegalArgumentException("File not found! " + csvFilePath);
            }

            // Read and discard the first line (header)
            br.readLine();

            while ((line = br.readLine()) != null) {
                // use comma as separator
                String[] columns = line.split(csvSplitBy);
                String key = columns[0].replace(" ", "");
                // Vulnerable class/method defined
                if (columns.length == 3) {
                    // Combine class/method name columns and remove whitespaces
                    String value = (columns[1] + "." + columns[2]).replace(" ", "");
                    // Check if the key already exists
                    if (vulnerableCodeMap.containsKey(key)) {
                        // If the key exists, add the new values to the existing list
                        vulnerableCodeMap.get(key).add(value);
                    } else {
                        // If the key doesn't exist, create a new entry
                        vulnerableCodeMap.put(key, new ArrayList<>(Collections.singleton(value)));
                    }
                }
                // Only vulnerable class is defined
                else if (columns.length == 2) {
                    String value = columns[1].replace(" ", "");
                    // Check if the key already exists
                    if (vulnerableCodeMap.containsKey(key)) {
                        // If the key exists, add the new values to the existing list
                        vulnerableCodeMap.get(key).add(value);
                    } else {
                        // If the key doesn't exist, create a new entry
                        vulnerableCodeMap.put(key, new ArrayList<>(Collections.singleton(value)));
                    }
                }
                else {
                    System.out.println("Invalid line: " + line);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Print the map
//        for (Map.Entry<String, List<String>> entry : vulnerableCodeMap.entrySet()) {
//            System.out.println("Key: " + entry.getKey() + " , Value: " + entry.getValue());
//        }

        return vulnerableCodeMap;
    }
}

package com.lmco.crt;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.*;

public class CSVToMap {

    public static void main(String[] args) {
        // Assuming the CSV file is located at src/main/resources/VulnerableCode.csv
        String csvFile = "VulnerableCode.csv";
        String line;
        String csvSplitBy = ",";

        Map<String, List<String>> map = new HashMap<>();

        // Use the class loader to get the resource
        ClassLoader classLoader = CSVToMap.class.getClassLoader();
        try (InputStream is = classLoader.getResourceAsStream(csvFile);
             BufferedReader br = new BufferedReader(new InputStreamReader(is))) {

            // This check is still useful for robustness despite IDE warning
            if (is == null) {
                throw new IllegalArgumentException("File not found! " + csvFile);
            }

            // Read and discard the first line (header)
            br.readLine();

            while ((line = br.readLine()) != null) {
                // use comma as separator
                String[] columns = line.split(csvSplitBy);
                String key = columns[0];
                if (columns.length == 3) {
                    // Combine class/method name columns and remove whitespaces
                    String value = (columns[1] + "." + columns[2]).replace(" ", "");
                    // Check if the key already exists
                    if (map.containsKey(key)) {
                        // If the key exists, add the new values to the existing list
                        map.get(key).add(value);
                    } else {
                        // If the key doesn't exist, create a new entry
                        map.put(key, new ArrayList<>(Collections.singleton(value)));
                    }
                }
                else if (columns.length == 2) {
                    // Check if the key already exists
                    if (map.containsKey(key)) {
                        // If the key exists, add the new values to the existing list
                        map.get(key).add(columns[1]);
                    } else {
                        // If the key doesn't exist, create a new entry
                        map.put(key, new ArrayList<>(Collections.singleton(columns[1])));
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
//        for (Map.Entry<String, List<String>> entry : map.entrySet()) {
//            System.out.println("Key: " + entry.getKey() + " , Value: " + entry.getValue());
//        }
    }
}



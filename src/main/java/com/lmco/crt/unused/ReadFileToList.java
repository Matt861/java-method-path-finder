package com.lmco.crt.unused;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class ReadFileToList {

    public static List<String> readFileToList(String filePath) {
        List<String> lines = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                lines.add(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return lines;
    }

    public static List<String> readFileFromResources(String fileName) {
        List<String> lines = new ArrayList<>();
        ClassLoader classLoader = ReadFileToList.class.getClassLoader();

        try (InputStream inputStream = classLoader.getResourceAsStream(fileName)) {
            assert inputStream != null;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {

                String line;
                while ((line = reader.readLine()) != null) {
                    lines.add(line);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return lines;
    }
}
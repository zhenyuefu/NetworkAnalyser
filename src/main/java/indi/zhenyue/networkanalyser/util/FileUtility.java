package indi.zhenyue.networkanalyser.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class FileUtility {

    public static String readFile(File f) {
        String readString = "";

        char[] readIn = new char[(Long.valueOf(f.length())).intValue()];

        try (BufferedReader in = new BufferedReader(new FileReader(f))) {

            in.read(readIn);
            readString = new String(readIn);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return readString;
    }
}

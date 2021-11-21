package indi.zhenyue.networkanalyser.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class FileUtility {

    public static String readFile(File f) {
        String readString = "";
        byte[] readIn = new byte[(Long.valueOf(f.length())).intValue()];
        try (FileInputStream in = new FileInputStream(f)) {
            in.read(readIn);
            readString = new String(readIn);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return readString;
    }
}

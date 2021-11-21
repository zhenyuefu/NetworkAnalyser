package indi.zhenyue.networkanalyser.util;

import java.util.List;

public class ArrayHelper {

    public static int extractInteger(List<Byte> bytes, int pos, int cnt) {
        int value = 0;
        for (int i = 0; i < cnt; i++) {
            try {
                value |= ((bytes.get(pos + cnt - i - 1) & 0xff) << 8 * i);
            } catch (IndexOutOfBoundsException ignored) {

            }
        }
        return value;
    }
}

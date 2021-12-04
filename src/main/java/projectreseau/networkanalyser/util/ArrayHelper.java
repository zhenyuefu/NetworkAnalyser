package projectreseau.networkanalyser.util;

import java.util.List;

public class ArrayHelper {

    public static int extractInteger(byte[] bytes, int pos, int cnt) {
        int value = 0;
        for (int i = 0; i < cnt; i++) {
            value |= ((bytes[pos + cnt - i - 1] & 0xff) << 8 * i);
        }
        return value;
    }

    public static long extractIntegerLong(byte[] bytes, int pos, int cnt) {
        long value = 0;
        for (int i = 0; i < cnt; i++) {
            value |= ((long) (bytes[pos + cnt - i - 1] & 0xff) << 8 * i);
        }
        return value;
    }

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

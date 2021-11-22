package indi.zhenyue.networkanalyser.util;

public class HexUtils {
    public static String byteToHexString(Byte src) {
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null) {
            return null;
        }

        int v = src & 0xFF;
        String hv = Integer.toHexString(v);
        if (hv.length() < 2) {
            stringBuilder.append(0);
        }
        stringBuilder.append(hv);

        return stringBuilder.toString();
    }

    public static String bytesToHexString(byte[] src, int pos, int cnt){
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null || src.length <= pos+cnt) {
            return null;
        }
        for (int i = pos; i < pos+cnt; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }
}

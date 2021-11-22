package indi.zhenyue.networkanalyser.packet;

import indi.zhenyue.networkanalyser.util.HexUtils;

public class MACAddress {

    public static String extract(byte[] bytes, int pos) {
        StringBuilder sb = new StringBuilder();
        sb.append(HexUtils.byteToHexString(bytes[pos]));
        for (int i = 1; i < 6; i++) {
            sb.append(":");
            sb.append(HexUtils.byteToHexString(bytes[pos + i]));
        }
        return sb.toString();
    }


}

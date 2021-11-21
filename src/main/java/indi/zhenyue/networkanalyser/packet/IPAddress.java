package indi.zhenyue.networkanalyser.packet;

public class IPAddress {

    public static String toString(int address) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            sb.append(0xff & address >> 24);
            address <<= 8;
            if (i != 3) {
                sb.append(".");
            }
        }
        return sb.toString();
    }

}

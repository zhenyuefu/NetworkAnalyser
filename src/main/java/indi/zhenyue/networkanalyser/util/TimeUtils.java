package indi.zhenyue.networkanalyser.util;

public class TimeUtils {

    public static String secondToTime(int second) {
        StringBuilder sb = new StringBuilder();
        if (second / 86400 > 0) {
            sb.append(second / 86400).append(" day");
            if (second / 86400 > 1)
                sb.append("s");
            sb.append(", ");
            second = second % 86400;
        }
        if (second / 3600 > 0) {
            sb.append(second / 3600).append(" hour");
            if (second / 3600 > 1)
                sb.append("s");
            sb.append(", ");
            second = second % 3600;
        }
        if (second / 60 > 0) {
            sb.append(second / 60).append(" minute");
            if (second / 60 > 1)
                sb.append("s");
            sb.append(", ");
            second = second % 60;
        }
        if (second > 0) {
            sb.append(second).append(" second");
            if (second > 1)
                sb.append("s");
            sb.append(", ");
        }
        sb.deleteCharAt(sb.length() - 2);
        return sb.toString();
    }

}

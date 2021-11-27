package indi.zhenyue.networkanalyser.packet;

import indi.zhenyue.networkanalyser.util.ArrayHelper;
import indi.zhenyue.networkanalyser.util.HexUtils;

import java.util.Objects;

public class DNSPacket extends UDPPacket {

    private int nameLength;
    private int labelCount;

    public DNSPacket(byte[] bytes) {
        super(bytes);
    }

    public String getTransactionID() {
        return String.format("0x%04x", ArrayHelper.extractInteger(bytes, udpOffset, 2));
    }

    public int getIntFlags() {
        return ArrayHelper.extractInteger(bytes, udpOffset + 2, 2);
    }

    public boolean getFlagsResponse() {
        return (getIntFlags() >> 15 == 1);
    }

    public int getQuestions() {
        return ArrayHelper.extractInteger(bytes, udpOffset + 4, 2);
    }

    public int getAnswerRRs() {
        return ArrayHelper.extractInteger(bytes, udpOffset + 6, 2);
    }

    public int getAuthorityRRs() {
        return ArrayHelper.extractInteger(bytes, udpOffset + 8, 2);
    }

    public int getAdditionalRRs() {
        return ArrayHelper.extractInteger(bytes, udpOffset + 10, 2);
    }

    public String getName() {
        StringBuilder sb = new StringBuilder();
        int i = udpOffset + 12;
        labelCount = 0;
        while (bytes[i] != 0) {
            int cnt = ArrayHelper.extractInteger(bytes, i, 1);
            sb.append(HexUtils.toStringHex(Objects.requireNonNull(HexUtils.bytesToHexString(bytes, i + 1, cnt)))).append(".");
            i += 1 + cnt;
            labelCount++;
        }
        sb.deleteCharAt(sb.length() - 1);
        nameLength = sb.length();
        return sb.toString();
    }

    public int getNameLength() {
        return nameLength;
    }

    public int getLabelCount() {
        return labelCount;
    }

    public String getType() {
        return switch (getIntType()) {
            case 12 -> "PTR";
            default -> "";
        };
    }

    public int getIntType() {
        return (ArrayHelper.extractInteger(bytes, udpOffset + 12 + nameLength + 2, 2));
    }

    public String getQueriesClass() {
        return switch (getIntQueriesClass()) {
            case 1 -> "IN";
            default -> "";
        };
    }

    public int getIntQueriesClass() {
        return (ArrayHelper.extractInteger(bytes, udpOffset + 12 + nameLength + 4, 2));
    }
}

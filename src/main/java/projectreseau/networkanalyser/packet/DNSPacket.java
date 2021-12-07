package projectreseau.networkanalyser.packet;

import javafx.scene.control.TreeItem;
import projectreseau.networkanalyser.util.ArrayHelper;
import projectreseau.networkanalyser.util.HexUtils;
import projectreseau.networkanalyser.util.TimeUtils;

import java.util.List;
import java.util.Objects;

public class DNSPacket extends UDPPacket {

    private int nameLength = 0;
    private int labelCount = 0;
    private int nameByteLength = 0;
    private int index = 12;

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

    public String getQueriesName() {
        return getName(12);
    }

    public String getName(int index) {
        StringBuilder sb = new StringBuilder();
        int i = udpOffset + index;
        while (bytes[i] != 0) {
            System.out.println(bytes[i]);
            if ((bytes[i] & 0xf0) == 0xc0) {
                sb.append(getName(((ArrayHelper.extractInteger(bytes, i, 1) & 0x0f) << 8) | ArrayHelper.extractInteger(bytes, i + 1, 1))).append(".");
                i = i + 1;
                break;
            } else {
                int cnt = ArrayHelper.extractInteger(bytes, i, 1);
                sb.append(HexUtils.toStringHex(Objects.requireNonNull(HexUtils.bytesToHexString(bytes, i + 1, cnt)))).append(".");
                i += 1 + cnt;
                labelCount++;
            }
        }
        i = i + 1;
        if (sb.length() > 0)
            sb.deleteCharAt(sb.length() - 1);
        nameLength = sb.length();
        nameByteLength = i - udpOffset - index;
        return sb.toString();
    }

    public String getName(int index, boolean b) {
        StringBuilder sb = new StringBuilder();
        int i = udpOffset + index;
        while (bytes[i] != 0) {
            if ((bytes[i] & 0xf0) == 0xc0) {
                sb.append(getName(((ArrayHelper.extractInteger(bytes, i, 1) & 0x0f) << 8) | ArrayHelper.extractInteger(bytes, i + 1, 1), b)).append(".");
                break;
            } else {
                int cnt = ArrayHelper.extractInteger(bytes, i, 1);
                sb.append(HexUtils.toStringHex(Objects.requireNonNull(HexUtils.bytesToHexString(bytes, i + 1, cnt)))).append(".");
                i += 1 + cnt;
                labelCount++;
            }
        }
        if (sb.length() > 0)
            sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    public int getNameLength() {
        return nameLength;
    }

    public int getNameByteLength() {
        return nameByteLength;
    }

    public int getLabelCount() {
        return labelCount;
    }

    public String getType(int index) {
        return switch (getIntType(index)) {
            case 1 -> "A";
            case 2 -> "NS";
            case 5 -> "CNAME";
            case 6 -> "SOA";
            case 12 -> "PTR";
            case 16 -> "TXT";
            case 0xfb -> "IXFR";
            default -> "" + getIntType(index);
        };
    }

    public int getIntType(int index) {
        return (ArrayHelper.extractInteger(bytes, udpOffset + index + nameByteLength, 2));
    }

    public String getQueriesClass(int index) {
        return switch (getIntQueriesClass(index)) {
            case 1 -> "IN";
            case -1 -> "Invalid";
            default -> "" + getIntQueriesClass(index);
        };
    }

    public int getIntQueriesClass(int index) {
        return (ArrayHelper.extractInteger(bytes, udpOffset + index + nameByteLength + 2, 2));
    }

    public int getTimeToLive(int index) {
        return ArrayHelper.extractInteger(bytes, udpOffset + index + nameByteLength + 4, 4);
    }

    public int getDataLength(int index) {
        return ArrayHelper.extractInteger(bytes, udpOffset + index + nameByteLength + 8, 2);
    }

    public String getData(int index) {
        return switch (getIntType(index)) {
            case 1 -> "Address: " + IPAddress.toString(ArrayHelper.extractInteger(bytes, udpOffset + index + nameByteLength + 10, getDataLength(index)));
            case 2 -> "Name Server: " + getName(index + nameByteLength + 10, false);
            case 5 -> "CNAME: " + getName(index + nameByteLength + 10, false);
            case 6 -> "SOA";
            case 16 -> "TXT Length: "+ArrayHelper.extractInteger(bytes, udpOffset + index + nameByteLength + 10, 1)+" TXT: "+ HexUtils.toStringHex(Objects.requireNonNull(HexUtils.bytesToHexString(bytes, udpOffset + index + nameByteLength + 11, ArrayHelper.extractInteger(bytes, udpOffset + index + nameByteLength + 10, 1))));
            default -> "Value: " + HexUtils.bytesToHexString(bytes,udpOffset + index + nameByteLength + 10, getDataLength(index));
        };
    }


    public void generateQueries(List<TreeItem<String>> sousItemsList) {
        sousItemsList.add(new TreeItem<>("Queries"));
        for (int i = 0; i < getQuestions(); i++) {
            TreeItem<String> sousItem = new TreeItem<>(String.format("%s: type: %s, class %s",getName(index), getType(index), getQueriesClass(index)));
            sousItemsList.get(sousItemsList.size() - 1).getChildren().add(sousItem);
            labelCount = 0;
            sousItem.getChildren().add(new TreeItem<>("Name: " + getName(index)));
            sousItem.getChildren().add(new TreeItem<>(String.format("[Name Length: %d]", getNameLength())));
            sousItem.getChildren().add(new TreeItem<>(String.format("[Label Count: %d]", getLabelCount())));
            sousItem.getChildren().add(new TreeItem<>(String.format("Type: %s (%d)", getType(index), getIntType(index))));
            sousItem.getChildren().add(new TreeItem<>(String.format("Class: %s (0x%04x)", getQueriesClass(index), getIntQueriesClass(index))));
            index += getNameByteLength() + 4;
        }
    }

    public void generateAnswers(List<TreeItem<String>> sousItemsList) {
        sousItemsList.add(new TreeItem<>("Answers"));
        for (int i = 0; i < getAnswerRRs(); i++) {
            generateResponse(sousItemsList);
        }
    }

    public void generateAuthority(List<TreeItem<String>> sousItemsList) {
        sousItemsList.add(new TreeItem<>("Authoritative nameservers "));
        for (int i = 0; i < getAuthorityRRs(); i++) {
            generateResponse(sousItemsList);
        }
    }

    public void generateAdditional(List<TreeItem<String>> sousItemsList) {
        sousItemsList.add(new TreeItem<>("Additional records "));
        for (int i = 0; i < getAdditionalRRs(); i++) {
            generateResponse(sousItemsList);
        }
    }

    private void generateResponse(List<TreeItem<String>> sousItemsList) {
        TreeItem<String> sousItem = new TreeItem<>(String.format("%s: type: %s, class %s, %s",getName(index), getType(index), getQueriesClass(index), getData(index)));
        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(sousItem);
        sousItem.getChildren().add(new TreeItem<>("Name: " + getName(index)));
        sousItem.getChildren().add(new TreeItem<>(String.format("Type: %s (%d)", getType(index), getIntType(index))));
        sousItem.getChildren().add(new TreeItem<>(String.format("Class: %s (0x%04x)", getQueriesClass(index), getIntQueriesClass(index))));
        sousItem.getChildren().add(new TreeItem<>(String.format("Time to live: %d (%s)", getTimeToLive(index), TimeUtils.secondToTime(getTimeToLive(index)))));
        sousItem.getChildren().add(new TreeItem<>(String.format("Data Length: %d", getDataLength(index))));
        sousItem.getChildren().add(new TreeItem<>(getData(index)));
        index += getNameByteLength() + 10 + getDataLength(index);
    }
}

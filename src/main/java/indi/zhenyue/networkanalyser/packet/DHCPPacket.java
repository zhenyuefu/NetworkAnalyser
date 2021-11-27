package indi.zhenyue.networkanalyser.packet;

import indi.zhenyue.networkanalyser.util.ArrayHelper;
import indi.zhenyue.networkanalyser.util.HexUtils;
import indi.zhenyue.networkanalyser.util.TimeUtils;
import javafx.scene.control.TreeItem;

import java.util.List;
import java.util.Objects;

public class DHCPPacket extends UDPPacket {
    public DHCPPacket(byte[] bytes) {
        super(bytes);
    }

    private int messageType;
    private String dhcpMessageType;

    public String getDhcpMessageType() {
        return dhcpMessageType;
    }

    public int getIntMessageType() {
        messageType = bytes[udpOffset]; //ArrayHelper.extractInteger(bytes, ipOffset+6, 2);
        return messageType;
    }

    public String getMessageType() {
        messageType = getIntMessageType();
        return switch (messageType) {
            case 1 -> "Boot Request (1)";
            case 2 -> "Boot Reply (2)";
            default -> "";
        };
    }

    public int getIntHardwareType() {
        return bytes[udpOffset + 1];
    }

    public String getHardwareType(int hardwareType) {
        return switch (hardwareType) {
            case 1 -> "Ethernet (0x01)";
            default -> "";
        };
    }

    public int getHardwareAddressLength() {
        return bytes[udpOffset + 2];
    }

    public int getHops() {
        return bytes[udpOffset + 3];
    }

    public int getTransactionID() {
        return ArrayHelper.extractInteger(bytes, udpOffset + 4, 4);
    }

    public int getSecondsElapsed() {
        return ArrayHelper.extractInteger(bytes, udpOffset + 8, 2);
    }

    private int bootpFlags;

    public int getBootpFlags() {
        bootpFlags = ArrayHelper.extractInteger(bytes, udpOffset + 10, 2);
        return bootpFlags;
    }

    public String getBroadcastFlag() {
        return (bootpFlags >> 15) + "... .... .... .... = Broadcast flag: " + getBroadcast();

    }

    public String getBroadcast() {
        return switch (bootpFlags >> 15) {
            case 0 -> "Unicast";
            case 1 -> "Broadcast";
            default -> null;
        };
    }

    private int reservedFlags;

    public int getIntReservedFlags() {
        reservedFlags = bootpFlags & 0x7fff;
        return reservedFlags;
    }

    public String getReservedFlags() {
        reservedFlags = getIntReservedFlags();
        return String.format(".%03d %04d %04d %04d = Reserved flags: 0x%04x",
                Integer.parseInt(Integer.toBinaryString(reservedFlags >> 12)),
                Integer.parseInt(Integer.toBinaryString((reservedFlags >> 8) & 0xf)),
                Integer.parseInt(Integer.toBinaryString((reservedFlags >> 4) & 0xf)),
                Integer.parseInt(Integer.toBinaryString(reservedFlags & 0xf)),
                reservedFlags);
    }

    private String clientIPAddress;

    public String getClientIPAddress() {
        if (clientIPAddress == null)
            clientIPAddress = IPAddress.toString(ArrayHelper.extractInteger(bytes, udpOffset + 12, 4));
        return clientIPAddress;
    }

    private String yourIPAddress;

    public String getYourIPAddress() {
        if (yourIPAddress == null)
            yourIPAddress = IPAddress.toString(ArrayHelper.extractInteger(bytes, udpOffset + 16, 4));
        return yourIPAddress;
    }

    private String nextServerIPAddress;

    public String getNextServerIPAddress() {
        if (nextServerIPAddress == null)
            nextServerIPAddress = IPAddress.toString(ArrayHelper.extractInteger(bytes, udpOffset + 20, 4));
        return nextServerIPAddress;
    }

    private String relayAgentIPAddress;

    public String getRelayAgentIPAddress() {
        if (relayAgentIPAddress == null)
            relayAgentIPAddress = IPAddress.toString(ArrayHelper.extractInteger(bytes, udpOffset + 24, 4));
        return relayAgentIPAddress;
    }

    private String clientMACAddress;

    public String getClientMACAddress() {
        if (clientMACAddress == null)
            clientMACAddress = MACAddress.extract(bytes, udpOffset + 28);
        return clientMACAddress;
    }

    public String getClientHardwareAddressPadding() {
        return String.format("%020x", ArrayHelper.extractInteger(bytes, udpOffset + 34, 10));
    }

    public int getServerHostName() {
        return ArrayHelper.extractInteger(bytes, udpOffset + 44, 64);
    }

    public int getBootFileName() {
        return ArrayHelper.extractInteger(bytes, udpOffset + 108, 16 * 8);
    }

    public int getIntMagicCookie() {
        return ArrayHelper.extractInteger(bytes, udpOffset + 236, 4);
    }

    public String getMagicCookie() {
        if (getIntMagicCookie() == 0x63825363)
            return "DHCP";
        return "";
    }

    public void generateOption(List<TreeItem<String>> sousItemsList) {
        int i = udpOffset + 240;
        int option;
        int length;
        try {
            while (bytes[i] != -1) {
                option = ArrayHelper.extractInteger(bytes, i, 1);
                length = bytes[i + 1];
                switch (option) {
                    case 1 -> {
                        String ip = IPAddress.toString(ArrayHelper.extractInteger(bytes, i + 2, 4));
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) Subnet Mask (%s)", option, ip)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Subnet Mask: " + ip));
                    }
                    case 2 -> {
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) Time Offset", option)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        int second = ArrayHelper.extractInteger(bytes, i + 2, length);
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>(String.format("Time Offset: (%ds) %s", second, TimeUtils.secondToTime(second))));
                    }
                    case 3 -> {
                        String ip = IPAddress.toString(ArrayHelper.extractInteger(bytes, i + 2, 4));
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) Router", option)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Router: " + ip));
                    }
                    case 6 -> {
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) Domain Name Server", option)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        for (int j = 0; j < length / 4; j++) {
                            String ip = IPAddress.toString(ArrayHelper.extractInteger(bytes, i + 2 + j, 4));
                            sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Domain Name Server: " + ip));
                        }
                    }
                    case 12 -> {
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) Host Name", option)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Host Name: " + HexUtils.toStringHex(Objects.requireNonNull(HexUtils.bytesToHexString(bytes, i + 2, length)))));
                    }
                    case 50 -> {
                        String ip = IPAddress.toString(ArrayHelper.extractInteger(bytes, i + 2, 4));
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) Requested IP Address (%s)", option, ip)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Requested IP Address: " + ip));
                    }
                    case 51 -> {
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) IP Address Lease Time", option)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        int second = ArrayHelper.extractInteger(bytes, i + 2, length);
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>(String.format("IP Address Lease Time: (%ds) %s", second, TimeUtils.secondToTime(second))));
                    }
                    case 53 -> {
                        dhcpMessageType = switch (bytes[i + 2]) {
                            case 3 -> "Request";
                            case 5 -> "ACK";
                            default -> "";
                        };
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) DHCP Message Type (%s)", option, dhcpMessageType)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>(String.format("DHCP: %s (%d)", dhcpMessageType, length)));
                    }
                    case 54 -> {
                        String ip = IPAddress.toString(ArrayHelper.extractInteger(bytes, i + 2, 4));
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) DHCP Server Identifier (%s)", option, ip)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("DHCP Server Identifier: " + ip));
                    }
                    case 55 -> {
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) Parameter Request List", option)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        for (int j = i + 2; j < i + length + 2; j++) {
                            String parameterRequestListItem = switch (ArrayHelper.extractInteger(bytes, j, 1)) {
                                case 1 -> "(1) Subnet Mask";
                                case 121 -> "(121) Classless Static Route";
                                case 3 -> "(3) Router";
                                case 6 -> "(6) Domain Name Server";
                                case 15 -> "(15) Domain Name";
                                case 119 -> "(119) Domain Search";
                                case 252 -> "(252) Private/Proxy autodiscovery";
                                case 95 -> "(95) LDAP";
                                case 44 -> "(44) NetBIOS over TCP/IP Name Server";
                                case 46 -> "(46) NetBIOS over TCP/IP Node Type";
                                default -> "";
                            };
                            sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Parameter Request List Item: " + parameterRequestListItem));
                        }
                    }
                    case 57 -> {
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) Maximum DHCP Message Size", option)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Maximum DHCP Message Size: " + ArrayHelper.extractInteger(bytes, i + 2, length)));
                    }
                    case 58 -> {
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) Renewal Time Value", option)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        int second = ArrayHelper.extractInteger(bytes, i + 2, length);
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>(String.format("Renewal Time Value: (%ds) %s", second, TimeUtils.secondToTime(second))));
                    }
                    case 59 -> {
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) Rebinding Time Value", option)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        int second = ArrayHelper.extractInteger(bytes, i + 2, length);
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>(String.format("Rebinding Time Value: (%ds) %s", second, TimeUtils.secondToTime(second))));
                    }
                    case 61 -> {
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) Client identifier", option)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        String hardwareType = getHardwareType(ArrayHelper.extractInteger(bytes, i + 2, 1));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>(String.format("Hardware type: %s (0x%02x)", hardwareType, ArrayHelper.extractInteger(bytes, i + 2, 1))));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Client MAC address: " + MACAddress.extract(bytes, i + 3)));
                    }
                    case 224 -> {
                        sousItemsList.add(new TreeItem<>(String.format("Option: (%d) Private", option)));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Length: " + length));
                        sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Value: " + HexUtils.bytesToHexString(bytes, i + 2, length)));
                    }
                }
                i = i + 2 + length;
            }
        } finally {
            option = 255;
            sousItemsList.add(new TreeItem<>(String.format("Option: (%d) End", option)));
            sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>("Option End: " + option));
            i++;
            if (i < bytes.length) {
                int cnt = bytes.length - i;
                sousItemsList.add(new TreeItem<>("Padding: " + String.format("%0" + 2 * cnt + "x", ArrayHelper.extractInteger(bytes, i, cnt))));
            }
        }

    }

}

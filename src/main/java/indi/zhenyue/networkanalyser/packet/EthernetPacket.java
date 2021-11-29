package indi.zhenyue.networkanalyser.packet;

import indi.zhenyue.networkanalyser.util.ArrayHelper;

public class EthernetPacket extends Packet implements EthernetProtocol {

    protected int ethOffset;
    protected String macAddressSource;
    protected String macAddressDestination;
    private final int protocol;

    public EthernetPacket(byte[] bytes) {
        super(bytes);
        this.ethOffset = 14;
        this.protocol = ArrayHelper.extractInteger(bytes, 12, 2);
    }

    public String getMacAddressSource() {
        if (macAddressSource == null)
            macAddressSource = MACAddress.extract(bytes, 6);
        return macAddressSource;
    }

    public String getMacAddressDestination() {
        if (macAddressDestination == null)
            macAddressDestination = MACAddress.extract(bytes, 0);
        return macAddressDestination;
    }

    public long getIntMacAddressSource() {
        return ArrayHelper.extractIntegerLong(bytes, 6, 6);
    }

    public long getIntMacAddressDestination() {
        return ArrayHelper.extractIntegerLong(bytes, 0, 6);
    }

    public String getLGBit(long address) {
        return switch (getNumBinaryAt(address, 7)) {
            case 0 -> ".... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)";
            case 1 -> ".... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)";
            default -> null;
        };
    }

    public String getIGBit(long address) {
        return switch (getNumBinaryAt(address, 8)) {
            case 0 -> ".... ...0 .... .... .... .... = IG bit: Individual address (unicast)";
            case 1 -> ".... ...1 .... .... .... .... = IG bit: Group address (multicast/broadcast)";
            default -> null;
        };
    }

    public int getNumBinaryAt(long address, int num) {
        address = address >> (48 - num);
        return (int) address & 0b1;
    }

    public int getProtocol() {
        return protocol;
    }

    public String getType() {
        return switch (protocol) {
            case IP -> "IPv4";
            case ARP -> "ARP";
            case IPV6 -> "IPv6";
            case MASK -> "MASK";
            default -> "";
        };
    }


}

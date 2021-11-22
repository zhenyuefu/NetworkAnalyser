package indi.zhenyue.networkanalyser.packet;

import indi.zhenyue.networkanalyser.util.ArrayHelper;

public class EthernetPacket extends Packet {

    protected int ethOffset;
    protected String macAddressSource;
    protected String macAddressDestination;
    private int protocol;

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

    public String getLGBit(int address) {
        return switch (getNumBinaryAt(address, 7)) {
            case 0 -> ".... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)";
            case 1 -> ".... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)";
            default -> null;
        };
    }

    public String getIGBit(int address) {
        return switch (getNumBinaryAt(address, 8)) {
            case 0 -> ".... ...0 .... .... .... .... = IG bit: Individual address (unicast)";
            case 1 -> ".... ...1 .... .... .... .... = IG bit: Group address (multicast/broadcast)";
            default -> null;
        };
    }

    public int getNumBinaryAt(int address, int num) {
        address = address >> (24 - num);
        return address & 0b1;
    }

    public int getProtocol() {
        return protocol;
    }


}

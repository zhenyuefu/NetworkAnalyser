package indi.zhenyue.networkanalyser.packet;

import indi.zhenyue.networkanalyser.util.ArrayHelper;
import indi.zhenyue.networkanalyser.util.HexUtils;

public class IPPacket extends EthernetPacket implements IPProtocol {

    protected int ipOffset;
    protected int ipHeaderLength;
    protected String ipAddressSource;
    protected String ipAddressDestination;

    public IPPacket(byte[] bytes) {
        super(bytes);
        this.ipHeaderLength = (ArrayHelper.extractInteger(bytes, ethOffset, 1) & 0xf) * 4;
        this.ipOffset = ethOffset + ipHeaderLength;
    }

    public String getIpAddressSource() {
        if (ipAddressSource == null)
            ipAddressSource = IPAddress.toString(ArrayHelper.extractInteger(bytes, ethOffset + 12, 4));
        return ipAddressSource;
    }

    public String getIpAddressDestination() {
        if (ipAddressDestination == null)
            ipAddressDestination = IPAddress.toString(ArrayHelper.extractInteger(bytes, ethOffset + 16, 4));
        return ipAddressDestination;
    }

    private int version;
    private boolean versionSet = false;

    public int getVersion() {
        if (!versionSet) {
            version = (ArrayHelper.extractInteger(bytes, ethOffset, 1) >> 4) & 0xf;
            versionSet = true;
        }
        return version;
    }

    public int getHeaderLength() {
        return ipHeaderLength;
    }

    private String differentiatedServices;

    public String getDifferentiatedServices() {
        if (differentiatedServices == null)
            differentiatedServices = "0x" + HexUtils.byteToHexString(bytes[ethOffset + 1]);
        return differentiatedServices;
    }

    private int totalLength = -1;

    public int getTotalLength() {
        if (totalLength == -1)
            totalLength = ArrayHelper.extractInteger(bytes, ethOffset + 2, 2);
        return totalLength;
    }

    private int identification = -1;

    public int getIdentification() {
        if (identification == -1)
            identification = ArrayHelper.extractInteger(bytes, ethOffset + 4, 2);
        return identification;
    }

    private int flag;

    public int getFlag() {
        flag = ArrayHelper.extractInteger(bytes, ethOffset + 6, 1);
        return flag;
    }

    public String getFlagReservedBit() {
        flag = getFlag();
        int bit = (flag >> 7) & 0b1;
        return switch (bit) {
            case 0 -> "0... .... = Reserved bit: Not set";
            case 1 -> "1... .... = Reserved bit: Set";
            default -> "";
        };
    }

    public String getFlagDontFragment() {
        flag = getFlag();
        int bit = (flag >> 6) & 0b1;
        return switch (bit) {
            case 0 -> ".0.. .... = Don't fragment: Not set";
            case 1 -> ".1.. .... = Don't fragment: Set";
            default -> "";
        };
    }

    public String getFlagMoreFragments() {
        flag = getFlag();
        int bit = (flag >> 5) & 0b1;
        return switch (bit) {
            case 0 -> "..0. .... = More fragments: Not set";
            case 1 -> "..1. .... = More fragments: Set";
            default -> "";
        };
    }

    private int fragmentOffset = -1;

    public int getFragmentOffset() {
        if (fragmentOffset == -1)
            fragmentOffset = ArrayHelper.extractInteger(bytes, ethOffset + 7, 1);
        return fragmentOffset;
    }

    private int timeToLive = -1;

    public int getTimeToLive() {
        if (timeToLive == -1)
            timeToLive = ArrayHelper.extractInteger(bytes, ethOffset + 8, 1);
        return timeToLive;
    }

    private int protocolIP;

    public int getIntProtocolIP() {
        protocolIP = ArrayHelper.extractInteger(bytes, ethOffset + 9, 1);
        return protocolIP;
    }

    public String getProtocolIP() {
        protocolIP = getIntProtocolIP();
        return switch (protocolIP) {
            case IPProtocol.IP -> "IPv4";
            case IPProtocol.ICMP -> "ICMP";
            case IPProtocol.TCP -> "TCP";
            case IPProtocol.UDP -> "UDP";
            case IPProtocol.IPV6 -> "IPv6";
            case IPProtocol.MASK -> "Mask";
            case IPProtocol.INVALID -> "Invalid";
            default -> "";
        };
    }

    private int headerChecksum = -1;

    public int getHeaderChecksum() {
        if (headerChecksum == -1)
            headerChecksum = ArrayHelper.extractInteger(bytes, ethOffset + 10, 2);
        return headerChecksum;
    }


}

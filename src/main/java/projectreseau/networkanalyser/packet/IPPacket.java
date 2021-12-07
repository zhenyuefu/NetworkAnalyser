package projectreseau.networkanalyser.packet;

import projectreseau.networkanalyser.util.ArrayHelper;
import projectreseau.networkanalyser.util.HexUtils;

public class IPPacket extends EthernetPacket implements IPProtocol {

    protected int ipOffset;
    protected int ipHeaderLength;
    protected String ipAddressSource;
    protected String ipAddressDestination;
    private int version;
    private boolean versionSet = false;
    private String differentiatedServices;
    private int totalLength = -1;
    private int identification = -1;
    private int flag;
    private int fragmentOffset = -1;
    private int timeToLive = -1;
    private int protocolIP;
    private int headerChecksum = -1;

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

    public String getDifferentiatedServices() {
        if (differentiatedServices == null)
            differentiatedServices = "0x" + HexUtils.byteToHexString(bytes[ethOffset + 1]);
        return differentiatedServices;
    }

    public int getTotalLength() {
        if (totalLength == -1)
            totalLength = ArrayHelper.extractInteger(bytes, ethOffset + 2, 2);
        return totalLength;
    }

    public int getIdentification() {
        if (identification == -1)
            identification = ArrayHelper.extractInteger(bytes, ethOffset + 4, 2);
        return identification;
    }

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

    public int getFragmentOffset() {
        if (fragmentOffset == -1)
            fragmentOffset = ArrayHelper.extractInteger(bytes, ethOffset + 7, 1);
        return fragmentOffset;
    }

    public int getTimeToLive() {
        if (timeToLive == -1)
            timeToLive = ArrayHelper.extractInteger(bytes, ethOffset + 8, 1);
        return timeToLive;
    }

    public int getIntProtocolIP() {
        protocolIP = ArrayHelper.extractInteger(bytes, ethOffset + 9, 1);
        return protocolIP;
    }

    public String getProtocolIP() {
        protocolIP = getIntProtocolIP();
        return switch (protocolIP) {
            case IPProtocol.IP -> "IPv4";
            case ICMP -> "ICMP";
            case TCP -> "TCP";
            case UDP -> "UDP";
            case IPProtocol.IPV6 -> "IPv6";
            case IPProtocol.MASK -> "Mask";
            case INVALID -> "Invalid";
            default -> "";
        };
    }

    public int getHeaderChecksum() {
        if (headerChecksum == -1)
            headerChecksum = ArrayHelper.extractInteger(bytes, ethOffset + 10, 2);
        return headerChecksum;
    }


}

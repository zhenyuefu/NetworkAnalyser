package indi.zhenyue.networkanalyser.packet;

import indi.zhenyue.networkanalyser.util.ArrayHelper;
import indi.zhenyue.networkanalyser.util.HexUtils;

public class IPPacket extends EthernetPacket {

    protected int ipOffset;
    protected int ipHeaderLength;
    protected String ipAddressSource;
    protected String ipAddressDestination;
    protected int version;
    private boolean versionSet = false;

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
            ipAddressDestination = IPAddress.toString(ArrayHelper.extractInteger(bytes, ethOffset + 8, 4));
        return ipAddressDestination;
    }

    public int getVersion() {
        if (!versionSet) {
            version = (ArrayHelper.extractInteger(bytes, ethOffset, 1) >> 4) & 0xf;
            versionSet = true;
        }
        return version;
    }

    private String differentiatedServices;
    public String getDifferentiatedServices() {
        if (differentiatedServices == null)
            differentiatedServices = "0x" + HexUtils.byteToHexString(bytes[ethOffset + 1]);
        return differentiatedServices;
    }

    private int totalLength;
    public int getTotalLength() {
        totalLength = ArrayHelper.extractInteger(bytes, ethOffset+2, 2);
        return totalLength;
    }


}

package projectreseau.networkanalyser.packet;

import projectreseau.networkanalyser.util.ArrayHelper;

public class UDPPacket extends IPPacket {

    protected int udpOffset;
    private int sourcePort;
    private int destinationPort;
    private int length;
    private int checkSum;
    private int udpPayload;

    public UDPPacket(byte[] bytes) {
        super(bytes);
        udpOffset = ipOffset + 8;
    }

    public int getSourcePort() {
        sourcePort = ArrayHelper.extractInteger(bytes, ipOffset, 2);
        return sourcePort;
    }

    public int getDestinationPort() {
        destinationPort = ArrayHelper.extractInteger(bytes, ipOffset + 2, 2);
        return destinationPort;
    }

    public int getLength() {
        length = ArrayHelper.extractInteger(bytes, ipOffset + 4, 2);
        return length;
    }

    public int getCheckSum() {
        checkSum = ArrayHelper.extractInteger(bytes, ipOffset + 6, 2);
        return checkSum;
    }

    public int getUdpPayload() {
        udpPayload = bytes.length - ipOffset - 8;
        return udpPayload;
    }

}

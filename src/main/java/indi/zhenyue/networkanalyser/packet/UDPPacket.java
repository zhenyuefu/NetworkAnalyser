package indi.zhenyue.networkanalyser.packet;

import indi.zhenyue.networkanalyser.util.ArrayHelper;

public class UDPPacket extends IPPacket {

    protected int udpOffset;

    public UDPPacket(byte[] bytes) {
        super(bytes);
        udpOffset = ipOffset+8;
    }

    private int sourcePort;
    public int getSourcePort(){
        sourcePort = ArrayHelper.extractInteger(bytes, ipOffset, 2);
        return sourcePort;
    }

    private int destinationPort;
    public int getDestinationPort(){
        destinationPort = ArrayHelper.extractInteger(bytes, ipOffset+2, 2);
        return destinationPort;
    }

    private int length;
    public int getLength(){
        length = ArrayHelper.extractInteger(bytes, ipOffset+4, 2);
        return length;
    }

    private int checkSum;
    public int getCheckSum(){
        checkSum = ArrayHelper.extractInteger(bytes, ipOffset+6, 2);
        return checkSum;
    }

    private int udpPayload;
    public int getUdpPayload(){
        udpPayload = bytes.length-ipOffset-8;
        return udpPayload;
    }


}

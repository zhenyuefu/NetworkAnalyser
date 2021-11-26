package indi.zhenyue.networkanalyser.packet;

import indi.zhenyue.networkanalyser.util.ArrayHelper;

public class DHCPPacket extends UDPPacket {
    public DHCPPacket(byte[] bytes) {
        super(bytes);
    }

    private int messageType;
    public int getIntMessageType(){
        messageType = bytes[udpOffset]; //ArrayHelper.extractInteger(bytes, ipOffset+6, 2);
        return messageType;
    }

    public String getMessageType(){
        messageType = getIntMessageType();
        return switch (messageType){
            case 1 -> "Boot Request (1)";
            case 2 -> "Boot Reply (2)";
            default -> "";
        };
    }

    public int getIntHardwareType(){
        return bytes[udpOffset+1];
    }

    public String getHardwareType(){
        int hardwareType = getIntHardwareType();
        return switch (hardwareType){
            case 1 -> "Ethernet (0x01)";
            default -> "";
        };
    }

    public int getHardwareAddressLength(){
        return bytes[udpOffset+2];
    }

    public int getHops(){
        return bytes[udpOffset+3];
    }

    public int getTransactionID(){
        return ArrayHelper.extractInteger(bytes, udpOffset+4, 4);
    }

    public int getSecondsElapsed(){
        return ArrayHelper.extractInteger(bytes, udpOffset+8, 2);
    }

    private int bootpFlags;
    public int getBootpFlags(){
        bootpFlags = ArrayHelper.extractInteger(bytes, udpOffset+10, 2);
        return bootpFlags;
    }

    public String getBroadcastFlag(){
        return switch (bootpFlags>>15){
            case 0 -> "0... .... .... .... = Broadcast flag: Unicast";
            case 1 -> "1... .... .... .... = Broadcast flag: Broadcast";
            default -> null;
        };
    }

    private int reservedFlags;
    public int getReservedFlags(){
        reservedFlags = bootpFlags & 0x7fff;
        return reservedFlags;
    }

    private String clientIPAddress;
    public String getClientIPAddress(){
        if (clientIPAddress==null)
        clientIPAddress = IPAddress.toString(ArrayHelper.extractInteger(bytes, udpOffset + 12, 4));
        return clientIPAddress;
    }

    private String yourIPAddress;
    public String getYourIPAddress(){
        if (yourIPAddress==null)
        yourIPAddress = IPAddress.toString(ArrayHelper.extractInteger(bytes, udpOffset + 16, 4));
        return yourIPAddress;
    }

    private String nextServerIPAddress;
    public String getNextServerIPAddress(){
        if (nextServerIPAddress==null)
        nextServerIPAddress = IPAddress.toString(ArrayHelper.extractInteger(bytes, udpOffset + 20, 4));
        return nextServerIPAddress;
    }

    private String relayAgentIPAddress;
    public String getRelayAgentIPAddress(){
        if (relayAgentIPAddress==null)
        relayAgentIPAddress = IPAddress.toString(ArrayHelper.extractInteger(bytes, udpOffset + 24, 4));
        return relayAgentIPAddress;
    }

    private String clientMACAddress;
    public String getClientMACAddress(){
        if (clientMACAddress==null)
            clientMACAddress = MACAddress.extract(bytes,udpOffset+28);
        return clientMACAddress;
    }

    public String getClientHardwareAddressPadding(){
        return String.format("%020x",ArrayHelper.extractInteger(bytes,udpOffset+34,10));
    }

    public int getServerHostName(){
        return ArrayHelper.extractInteger(bytes,udpOffset+44,64);
    }

    public int getBootFileName(){
        return ArrayHelper.extractInteger(bytes,udpOffset+108,16*8);
    }

    public int getMagicCookie(){
        return ArrayHelper.extractInteger(bytes,udpOffset+236,4);
    }

    private int option;





}

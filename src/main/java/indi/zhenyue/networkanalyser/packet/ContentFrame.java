package indi.zhenyue.networkanalyser.packet;

import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;

import java.util.ArrayList;
import java.util.List;

public class ContentFrame {

    private final TreeView<String> treeView;
    private final Frame frame;
    private final byte[] bytes;
    private final List<TreeItem<String>> treeItems;

    public ContentFrame(TreeView<String> treeView, Frame frame, Packet packet) {
        this.treeView = treeView;
        this.frame = frame;
        this.bytes = packet.getBytes();
        this.treeItems = new ArrayList<>();
        analyserContent();
    }

    public void analyserContent() {
        TreeItem<String> sousItem;
        TreeItem<String>[] sousItemsList;

        TreeItem<String> treeItemRoot = new TreeItem<>();
        treeItems.add(treeItemRoot);

        // Frame
        treeItems.add(new TreeItem<>("Frame " + frame.getId() + ": " + frame.getLength() + " bytes on wire (" + Integer.parseInt(frame.getLength()) * 8 + " bits), " + frame.getLength() + " bytes captured (" + Integer.parseInt(frame.getLength()) * 8 + " bits) on interface unknown, id 0"));
        sousItem = new TreeItem<>("Interface id: 0 (known)");
        sousItem.getChildren().add(new TreeItem<>("Interface name: unknown"));
        treeItems.get(1).getChildren().add(sousItem);

        // Ethernet
        EthernetPacket ethernetPacket = new EthernetPacket(bytes);
        treeItems.add(new TreeItem<>("Ethernet II, Src: " + ethernetPacket.getMacAddressSource() + ", Dest: " + ethernetPacket.getMacAddressDestination()));
        sousItemsList = new TreeItem[3];
        sousItemsList[0] = new TreeItem<>("Destination: " + ethernetPacket.getMacAddressDestination());
        sousItemsList[0].getChildren().add(new TreeItem<>("Address: " + ethernetPacket.getMacAddressDestination()));
        sousItemsList[0].getChildren().add(new TreeItem<>(ethernetPacket.getLGBit(ethernetPacket.getIntMacAddressDestination())));
        sousItemsList[0].getChildren().add(new TreeItem<>(ethernetPacket.getIGBit(ethernetPacket.getIntMacAddressDestination())));
        sousItemsList[1] = new TreeItem<>("Source: " + ethernetPacket.getMacAddressSource());
        sousItemsList[1].getChildren().add(new TreeItem<>("Address: " + ethernetPacket.getMacAddressSource()));
        sousItemsList[1].getChildren().add(new TreeItem<>(ethernetPacket.getLGBit(ethernetPacket.getIntMacAddressSource())));
        sousItemsList[1].getChildren().add(new TreeItem<>(ethernetPacket.getIGBit(ethernetPacket.getIntMacAddressSource())));
        sousItemsList[2] = new TreeItem<>("Type: "+ethernetPacket.getType()+" (0x"+String.format("%04x",ethernetPacket.getProtocol())+")");
        treeItems.get(2).getChildren().addAll(sousItemsList);

        // IPv4
        if (ethernetPacket.getProtocol() == 0x0800) {
            IPPacket ipPacket = new IPPacket(bytes);
            treeItems.add(new TreeItem<>("Internet Protocol Version 4, Src: "+ipPacket.getIpAddressSource()+", Dst: "+ipPacket.getIpAddressDestination()));
            sousItemsList = new TreeItem[12];
            sousItemsList[0] = new TreeItem<>("Version: "+ipPacket.getVersion());
            sousItemsList[1] = new TreeItem<>("Header Length: "+ipPacket.getHeaderLength());
            sousItemsList[2] = new TreeItem<>("Differentiated Services Field: "+ipPacket.getDifferentiatedServices());
            sousItemsList[3] = new TreeItem<>("Total Length: "+ipPacket.getTotalLength());
            sousItemsList[4] = new TreeItem<>("Identification: 0x"+String.format("%04x",ipPacket.getIdentification())+" ("+ipPacket.getIdentification()+")");
            sousItemsList[5] = new TreeItem<>("Flags: 0x"+String.format("%02x",ipPacket.getFlag()));
            sousItemsList[5].getChildren().add(new TreeItem<>(ipPacket.getFlagReservedBit()));
            sousItemsList[5].getChildren().add(new TreeItem<>(ipPacket.getFlagDontFragment()));
            sousItemsList[5].getChildren().add(new TreeItem<>(ipPacket.getFlagMoreFragments()));
            sousItemsList[6] = new TreeItem<>("Fragment Offset: "+ipPacket.getFragmentOffset());
            sousItemsList[7] = new TreeItem<>("Time to Live: "+ipPacket.getTimeToLive());
            sousItemsList[8] = new TreeItem<>("Protocol: "+ipPacket.getProtocolIP()+" ("+ipPacket.getIntProtocolIP()+")");
            sousItemsList[9] = new TreeItem<>("Header Checksum: 0x"+String.format("%04x",ipPacket.getHeaderChecksum()));
            sousItemsList[10] = new TreeItem<>("Source Address: "+ipPacket.getIpAddressSource());
            sousItemsList[11] = new TreeItem<>("Destination Address: "+ipPacket.getIpAddressDestination());
            treeItems.get(3).getChildren().addAll(sousItemsList);

            // UDP
            if (ipPacket.getIntProtocolIP() == 17) {
                UDPPacket udpPacket = new UDPPacket(bytes);
                treeItems.add(new TreeItem<>("User Datagram Protocol, Src Port: "+udpPacket.getSourcePort()+", Dst Port: "+udpPacket.getDestinationPort()));
                sousItemsList = new TreeItem[5];
                sousItemsList[0] = new TreeItem<>("Source Port: "+udpPacket.getSourcePort());
                sousItemsList[1] = new TreeItem<>("Destination Port: "+udpPacket.getDestinationPort());
                sousItemsList[2] = new TreeItem<>("Length: "+udpPacket.getLength());
                sousItemsList[3] = new TreeItem<>("Checksum: 0x"+String.format("%04x",udpPacket.getCheckSum()));
                sousItemsList[4] = new TreeItem<>("UDP payload ("+udpPacket.getUdpPayload()+" bytes)");
                treeItems.get(4).getChildren().addAll(sousItemsList);

                int sourcePort = udpPacket.getSourcePort();
                int destinationPort = udpPacket.getDestinationPort();
                // DHCP
                if ((sourcePort == 67 && destinationPort == 68) || (destinationPort == 67 && sourcePort == 68)) {
                    DHCPPacket dhcpPacket = new DHCPPacket(bytes);
                    treeItems.add(new TreeItem<>("Dynamic Host Configuration Protocol (ACK)"));
                    sousItemsList = new TreeItem[20];
                    sousItemsList[0] = new TreeItem<>("Message type: "+dhcpPacket.getMessageType());
                    sousItemsList[1] = new TreeItem<>("Hardware type: "+dhcpPacket.getHardwareType());
                    sousItemsList[2] = new TreeItem<>("Hardware address length: "+dhcpPacket.getHardwareAddressLength());
                    sousItemsList[3] = new TreeItem<>("Hops: "+dhcpPacket.getHops());
                    sousItemsList[4] = new TreeItem<>("Transaction ID: "+String.format("0x%08x",dhcpPacket.getTransactionID()));
                    sousItemsList[5] = new TreeItem<>("Seconds elapsed: "+dhcpPacket.getSecondsElapsed());
                    sousItemsList[6] = new TreeItem<>("Bootp flags: "+String.format("0x%04x",dhcpPacket.getBootpFlags()));
                    sousItemsList[6].getChildren().add(new TreeItem<>(dhcpPacket.getBroadcastFlag()));
                    sousItemsList[7] = new TreeItem<>("Client IP address: "+dhcpPacket.getClientIPAddress());
                    sousItemsList[8] = new TreeItem<>("Your (client) IP address: "+dhcpPacket.getYourIPAddress());
                    sousItemsList[9] = new TreeItem<>("Next server IP address: "+dhcpPacket.getNextServerIPAddress());
                    sousItemsList[10] = new TreeItem<>("Relay agent IP address: "+dhcpPacket.getRelayAgentIPAddress());
                    sousItemsList[11] = new TreeItem<>("Client MAC address: "+dhcpPacket.getClientMACAddress());
                    sousItemsList[12] = new TreeItem<>("Client hardware address padding: "+dhcpPacket.getClientHardwareAddressPadding());
                    sousItemsList[13] = new TreeItem<>();

                    treeItems.get(5).getChildren().addAll(sousItemsList);
                }




                /**
                 *     Transaction ID: 0xf37500d3
                 *     Seconds elapsed: 0
                 *     Bootp flags: 0x0000 (Unicast)
                 *     Client IP address: 0.0.0.0
                 *     Your (client) IP address: 10.64.23.157
                 *     Next server IP address: 0.0.0.0
                 *     Relay agent IP address: 0.0.0.0
                 *     Client MAC address: Apple_26:21:c5 (8c:85:90:26:21:c5)
                 *     Client hardware address padding: 00000000000000000000
                 *     Server host name not given
                 *     Boot file name not given
                 *     Magic cookie: DHCP
                 *     Option: (53) DHCP Message Type (ACK)
                 *     Option: (54) DHCP Server Identifier (10.64.63.254)
                 *     Option: (51) IP Address Lease Time
                 *     Option: (1) Subnet Mask (255.255.192.0)
                 *     Option: (3) Router
                 *     Option: (6) Domain Name Server
                 *     Option: (58) Renewal Time Value
                 *     Option: (59) Rebinding Time Value
                 *     Option: (2) Time Offset
                 *     Option: (224) Private
                 *     Option: (255) End
                 */

                //DNS
                if (sourcePort == 53 || destinationPort == 53) {
                    DNSPacket dnsPacket = new DNSPacket(bytes);
                }
            }
        }



        for (int i = 1; i < treeItems.size(); i++) {
            treeItemRoot.getChildren().add(treeItems.get(i));
        }
        treeItemRoot.setExpanded(true);
        treeView.setShowRoot(false);
        treeView.setRoot(treeItemRoot);


    }


}

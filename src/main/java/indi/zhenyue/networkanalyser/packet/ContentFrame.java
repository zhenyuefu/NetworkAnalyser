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

    private String protocol;
    private String info;

    public ContentFrame(Packet packet) {
        this.treeView = new TreeView<>();
        this.frame = null;
        this.bytes = packet.getBytes();
        this.treeItems = new ArrayList<>();
        analyserContent();
    }

    public ContentFrame(TreeView<String> treeView, Frame frame, Packet packet) {
        this.treeView = treeView;
        this.frame = frame;
        this.bytes = packet.getBytes();
        this.treeItems = new ArrayList<>();
        analyserContent();
    }

    public void analyserContent() {
        TreeItem<String> sousItem;
        List<TreeItem<String>> sousItemsList;

        TreeItem<String> treeItemRoot = new TreeItem<>();
        treeItems.add(treeItemRoot);

        // Frame
        if (frame != null) {
            treeItems.add(new TreeItem<>("Frame " + frame.getId() + ": " + frame.getLength() + " bytes on wire (" + Integer.parseInt(frame.getLength()) * 8 + " bits), " + frame.getLength() + " bytes captured (" + Integer.parseInt(frame.getLength()) * 8 + " bits) on interface unknown, id 0"));
            sousItem = new TreeItem<>("Interface id: 0 (known)");
            sousItem.getChildren().add(new TreeItem<>("Interface name: unknown"));
            treeItems.get(1).getChildren().add(sousItem);
        } else {
            treeItems.add(new TreeItem<>("Frame "));
        }

        // Ethernet
        EthernetPacket ethernetPacket = new EthernetPacket(bytes);
        treeItems.add(new TreeItem<>("Ethernet II, Src: " + ethernetPacket.getMacAddressSource() + ", Dest: " + ethernetPacket.getMacAddressDestination()));
        sousItemsList = new ArrayList<>();
        sousItemsList.add(new TreeItem<>("Destination: " + ethernetPacket.getMacAddressDestination()));
        sousItemsList.get(0).getChildren().add(new TreeItem<>("Address: " + ethernetPacket.getMacAddressDestination()));
        sousItemsList.get(0).getChildren().add(new TreeItem<>(ethernetPacket.getLGBit(ethernetPacket.getIntMacAddressDestination())));
        sousItemsList.get(0).getChildren().add(new TreeItem<>(ethernetPacket.getIGBit(ethernetPacket.getIntMacAddressDestination())));
        sousItemsList.add(new TreeItem<>("Source: " + ethernetPacket.getMacAddressSource()));
        sousItemsList.get(1).getChildren().add(new TreeItem<>("Address: " + ethernetPacket.getMacAddressSource()));
        sousItemsList.get(1).getChildren().add(new TreeItem<>(ethernetPacket.getLGBit(ethernetPacket.getIntMacAddressSource())));
        sousItemsList.get(1).getChildren().add(new TreeItem<>(ethernetPacket.getIGBit(ethernetPacket.getIntMacAddressSource())));
        sousItemsList.add(new TreeItem<>("Type: " + ethernetPacket.getType() + " (0x" + String.format("%04x", ethernetPacket.getProtocol()) + ")"));
        treeItems.get(2).getChildren().addAll(sousItemsList);

        // IPv4
        if (ethernetPacket.getProtocol() == 0x0800) {
            IPPacket ipPacket = new IPPacket(bytes);
            treeItems.add(new TreeItem<>("Internet Protocol Version 4, Src: " + ipPacket.getIpAddressSource() + ", Dst: " + ipPacket.getIpAddressDestination()));
            sousItemsList = new ArrayList<>();
            sousItemsList.add(new TreeItem<>("Version: " + ipPacket.getVersion()));
            sousItemsList.add(new TreeItem<>("Header Length: " + ipPacket.getHeaderLength()));
            sousItemsList.add(new TreeItem<>("Differentiated Services Field: " + ipPacket.getDifferentiatedServices()));
            sousItemsList.add(new TreeItem<>("Total Length: " + ipPacket.getTotalLength()));
            sousItemsList.add(new TreeItem<>("Identification: 0x" + String.format("%04x", ipPacket.getIdentification()) + " (" + ipPacket.getIdentification() + ")"));
            sousItemsList.add(new TreeItem<>("Flags: 0x" + String.format("%02x", ipPacket.getFlag())));
            sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>(ipPacket.getFlagReservedBit()));
            sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>(ipPacket.getFlagDontFragment()));
            sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>(ipPacket.getFlagMoreFragments()));
            sousItemsList.add(new TreeItem<>("Fragment Offset: " + ipPacket.getFragmentOffset()));
            sousItemsList.add(new TreeItem<>("Time to Live: " + ipPacket.getTimeToLive()));
            sousItemsList.add(new TreeItem<>("Protocol: " + ipPacket.getProtocolIP() + " (" + ipPacket.getIntProtocolIP() + ")"));
            sousItemsList.add(new TreeItem<>("Header Checksum: 0x" + String.format("%04x", ipPacket.getHeaderChecksum())));
            sousItemsList.add(new TreeItem<>("Source Address: " + ipPacket.getIpAddressSource()));
            sousItemsList.add(new TreeItem<>("Destination Address: " + ipPacket.getIpAddressDestination()));
            treeItems.get(3).getChildren().addAll(sousItemsList);

            // UDP
            if (ipPacket.getIntProtocolIP() == 17) {
                UDPPacket udpPacket = new UDPPacket(bytes);
                treeItems.add(new TreeItem<>("User Datagram Protocol, Src Port: " + udpPacket.getSourcePort() + ", Dst Port: " + udpPacket.getDestinationPort()));
                sousItemsList = new ArrayList<>();
                sousItemsList.add(new TreeItem<>("Source Port: " + udpPacket.getSourcePort()));
                sousItemsList.add(new TreeItem<>("Destination Port: " + udpPacket.getDestinationPort()));
                sousItemsList.add(new TreeItem<>("Length: " + udpPacket.getLength()));
                sousItemsList.add(new TreeItem<>("Checksum: 0x" + String.format("%04x", udpPacket.getCheckSum())));
                sousItemsList.add(new TreeItem<>("UDP payload (" + udpPacket.getUdpPayload() + " bytes)"));
                treeItems.get(4).getChildren().addAll(sousItemsList);

                int sourcePort = udpPacket.getSourcePort();
                int destinationPort = udpPacket.getDestinationPort();
                // DHCP
                if ((sourcePort == 67 && destinationPort == 68) || (destinationPort == 67 && sourcePort == 68)) {
                    DHCPPacket dhcpPacket = new DHCPPacket(bytes);
                    treeItems.add(new TreeItem<>("Dynamic Host Configuration Protocol"));
                    sousItemsList = new ArrayList<>();
                    sousItemsList.add(new TreeItem<>("Message type: " + dhcpPacket.getMessageType()));
                    sousItemsList.add(new TreeItem<>("Hardware type: " + dhcpPacket.getHardwareType(dhcpPacket.getIntHardwareType())));
                    sousItemsList.add(new TreeItem<>("Hardware address length: " + dhcpPacket.getHardwareAddressLength()));
                    sousItemsList.add(new TreeItem<>("Hops: " + dhcpPacket.getHops()));
                    sousItemsList.add(new TreeItem<>("Transaction ID: " + String.format("0x%08x", dhcpPacket.getTransactionID())));
                    sousItemsList.add(new TreeItem<>("Seconds elapsed: " + dhcpPacket.getSecondsElapsed()));
                    sousItemsList.add(new TreeItem<>("Bootp flags: " + String.format("0x%04x", dhcpPacket.getBootpFlags()) + " (" + dhcpPacket.getBroadcast() + ")"));
                    sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>(dhcpPacket.getBroadcastFlag()));
                    sousItemsList.get(sousItemsList.size() - 1).getChildren().add(new TreeItem<>(dhcpPacket.getReservedFlags()));
                    sousItemsList.add(new TreeItem<>("Client IP address: " + dhcpPacket.getClientIPAddress()));
                    sousItemsList.add(new TreeItem<>("Your (client) IP address: " + dhcpPacket.getYourIPAddress()));
                    sousItemsList.add(new TreeItem<>("Next server IP address: " + dhcpPacket.getNextServerIPAddress()));
                    sousItemsList.add(new TreeItem<>("Relay agent IP address: " + dhcpPacket.getRelayAgentIPAddress()));
                    sousItemsList.add(new TreeItem<>("Client MAC address: " + dhcpPacket.getClientMACAddress()));
                    sousItemsList.add(new TreeItem<>("Client hardware address padding: " + dhcpPacket.getClientHardwareAddressPadding()));
                    sousItemsList.add(new TreeItem<>("Server host name: " + dhcpPacket.getServerHostName()));
                    sousItemsList.add(new TreeItem<>("Boot file name: " + dhcpPacket.getBootFileName()));
                    sousItemsList.add(new TreeItem<>("Magic cookie: " + dhcpPacket.getMagicCookie()));
                    dhcpPacket.generateOption(sousItemsList);
                    treeItems.get(5).getChildren().addAll(sousItemsList);
                    protocol = "DHCP";
                    info = "DHCP " + dhcpPacket.getDhcpMessageType() + " - Transaction ID: " + String.format("0x%08x", dhcpPacket.getTransactionID());
                }

                //DNS
                if (sourcePort == 53 || destinationPort == 53) {
                    DNSPacket dnsPacket = new DNSPacket(bytes);
                    treeItems.add(new TreeItem<>(String.format("Domain Name System (%s)", dnsPacket.getFlagsResponse() ? "response" : "query")));
                    sousItemsList = new ArrayList<>();
                    sousItemsList.add(new TreeItem<>("Transaction ID: " + dnsPacket.getTransactionID()));
                    sousItemsList.add(new TreeItem<>(String.format("Flags: 0x%04x Standard query %s", dnsPacket.getIntFlags(), dnsPacket.getFlagsResponse() ? "response" : "")));
                    sousItemsList.add(new TreeItem<>("Questions: " + dnsPacket.getQuestions()));
                    sousItemsList.add(new TreeItem<>("Answer RRs: " + dnsPacket.getAnswerRRs()));
                    sousItemsList.add(new TreeItem<>("Authority RRs: " + dnsPacket.getAuthorityRRs()));
                    sousItemsList.add(new TreeItem<>("Additional RRs: " + dnsPacket.getAdditionalRRs()));
                    sousItemsList.add(new TreeItem<>("Queries"));
                    sousItem = new TreeItem<>(dnsPacket.getName());
                    sousItemsList.get(sousItemsList.size() - 1).getChildren().add(sousItem);
                    sousItem.getChildren().add(new TreeItem<>("Name: " + dnsPacket.getName()));
                    sousItem.getChildren().add(new TreeItem<>(String.format("[Name Length: %d]", dnsPacket.getNameLength())));
                    sousItem.getChildren().add(new TreeItem<>(String.format("[Label Count: %d]", dnsPacket.getLabelCount())));
                    sousItem.getChildren().add(new TreeItem<>(String.format("Type: %s (%d)", dnsPacket.getType(), dnsPacket.getIntType())));
                    sousItem.getChildren().add(new TreeItem<>(String.format("Class: %s (0x%04x)", dnsPacket.getQueriesClass(), dnsPacket.getIntQueriesClass())));
                    treeItems.get(5).getChildren().addAll(sousItemsList);

                    /**
                     *     Flags: 0x0100 Standard query
                     *         0... .... .... .... = Response: Message is a query
                     *         .000 0... .... .... = Opcode: Standard query (0)
                     *         .... ..0. .... .... = Truncated: Message is not truncated
                     *         .... ...1 .... .... = Recursion desired: Do query recursively
                     *         .... .... .0.. .... = Z: reserved (0)
                     *         .... .... ...0 .... = Non-authenticated data: Unacceptable
                     *         db._dns-sd._udp.0.0.64.10.in-addr.arpa: type PTR, class IN
                     *             Name: db._dns-sd._udp.0.0.64.10.in-addr.arpa
                     *             [Name Length: 38]
                     *             [Label Count: 9]
                     *             Type: PTR (domain name PoinTeR) (12)
                     *             Class: IN (0x0001)
                     *     [Response In: 5]
                     */

                    protocol = "DNS";
                    info = String.format("Standard query %s %s %s %s", dnsPacket.getFlagsResponse() ? "response " : "", dnsPacket.getTransactionID(), dnsPacket.getType(), dnsPacket.getName());
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

    public String getProtocol() {
        return protocol;
    }

    public String getInfo() {
        return info;
    }


}

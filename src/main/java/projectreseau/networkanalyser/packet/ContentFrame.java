package projectreseau.networkanalyser.packet;

import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;

import java.util.ArrayList;
import java.util.List;

public class ContentFrame {

    private final TreeView<String> treeView;
    private int frame_id;
    private final byte[] bytes;
    private final List<TreeItem<String>> treeItems;
    private TreeItem<String> treeItemRoot;
    private String protocol;
    private String info;

    public ContentFrame(Packet packet) {
        this.treeView = new TreeView<>();
        this.bytes = packet.getBytes();
        this.treeItems = new ArrayList<>();
        analyserContent();
    }

    public ContentFrame(int frame_id, Packet packet) {
        this.treeView = new TreeView<>();
        this.bytes = packet.getBytes();
        this.treeItems = new ArrayList<>();
        this.frame_id = frame_id;
        analyserContent();
    }

    public ContentFrame(TreeView<String> treeView, int frame_id, Packet packet) {
        this.treeView = treeView;
        this.bytes = packet.getBytes();
        this.treeItems = new ArrayList<>();
        this.frame_id = frame_id;
        analyserContent();
    }

    public void analyserContent() {
        TreeItem<String> sousItem;
        List<TreeItem<String>> sousItemsList;

        treeItemRoot = new TreeItem<>();
        treeItems.add(treeItemRoot);

        // Frame
        treeItems.add(new TreeItem<>(String.format("%s %d: %d bytes on wire (%d bits), %d bytes captured (%d bits) on interface unknown, id 0", "Frame ", frame_id, bytes.length, bytes.length * 8, bytes.length, bytes.length * 8)));
        sousItem = new TreeItem<>("Interface id: 0 (known)");
        sousItem.getChildren().add(new TreeItem<>("Interface name: unknown"));
        treeItems.get(1).getChildren().add(sousItem);

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
        if (ethernetPacket.getProtocol() == EthernetProtocol.IP) {
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
            if (ipPacket.getIntProtocolIP() == IPProtocol.UDP) {
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

                    if (dnsPacket.getQuestions() > 0)
                        sousItemsList.add(new TreeItem<>("Queries"));
                    sousItem = new TreeItem<>(dnsPacket.getQueriesName());
                    sousItemsList.get(sousItemsList.size() - 1).getChildren().add(sousItem);
                    sousItem.getChildren().add(new TreeItem<>("Name: " + dnsPacket.getQueriesName()));
                    sousItem.getChildren().add(new TreeItem<>(String.format("[Name Length: %d]", dnsPacket.getNameLength())));
                    sousItem.getChildren().add(new TreeItem<>(String.format("[Label Count: %d]", dnsPacket.getLabelCount())));
                    sousItem.getChildren().add(new TreeItem<>(String.format("Type: %s (%d)", dnsPacket.getType(), dnsPacket.getIntType())));
                    sousItem.getChildren().add(new TreeItem<>(String.format("Class: %s (0x%04x)", dnsPacket.getQueriesClass(), dnsPacket.getIntQueriesClass())));

                    treeItems.get(5).getChildren().addAll(sousItemsList);
                    protocol = "DNS";
                    info = String.format("Standard query %s %s %s %s", dnsPacket.getFlagsResponse() ? "response " : "", dnsPacket.getTransactionID(), dnsPacket.getType(), dnsPacket.getQueriesName());
                }
            }

            // TCP
            if (ipPacket.getIntProtocolIP() == IPProtocol.TCP) {
                protocol = "TCP";
                info = " ";
            }

            // ICMP
            if (ipPacket.getIntProtocolIP() == IPProtocol.ICMP) {
                protocol = "ICMP";
                info = " ";
            }
        }

        // ARP
        if (ethernetPacket.getProtocol() == EthernetProtocol.ARP) {
            protocol = "ARP";
            info = " ";
        }

        for (int i = 1; i < treeItems.size(); i++) {
            treeItemRoot.getChildren().add(treeItems.get(i));
        }
        treeItemRoot.setExpanded(true);
        treeView.setShowRoot(false);
        treeView.setRoot(treeItemRoot);
    }

    public TreeItem<String> getTreeItemRoot() {
        return treeItemRoot;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getInfo() {
        return info;
    }


}

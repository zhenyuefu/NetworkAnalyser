package indi.zhenyue.networkanalyser.packet;

import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;

import java.util.ArrayList;
import java.util.List;

public class ContentFrame {

    private final TreeView<String> treeView;
    private final Frame frame;
    private final List<Byte> bytes;
    private final List<TreeItem<String>> treeItems;

    public ContentFrame(TreeView<String> treeView, Frame frame) {
        this.treeView = treeView;
        this.frame = frame;
        this.bytes = new ArrayList<>();
        this.bytes.addAll(frame.getbytes());
        this.treeItems = new ArrayList<>();
        analyserContent();
    }

    public void analyserContent() {
        TreeItem<String> treeItemRoot = new TreeItem<>();
        TreeItem<String> sousItem;
        TreeItem<String>[] sousItemsList;
        treeItems.add(treeItemRoot);
        treeItems.add(new TreeItem<>("Frame " + frame.getId() + ": " + frame.getLength() + " bytes on wire (" + Integer.parseInt(frame.getLength()) * 8 + " bits), " + frame.getLength() + " bytes captured (" + Integer.parseInt(frame.getLength()) * 8 + " bits) on interface unknown, id 0"));
        sousItem = new TreeItem<>("Interface id: 0 (known)");
        sousItem.getChildren().add(new TreeItem<>("Interface name: unknown"));
        treeItems.get(1).getChildren().add(sousItem);


        treeItems.add(new TreeItem<>("Ethernet II, Src: " + macAddress(6) + ", Dest: " + macAddress(0)));
        sousItemsList = new TreeItem[3];
        sousItemsList[0] = new TreeItem<>("Destination: " + macAddress(0));
        sousItemsList[0].getChildren().add(new TreeItem<>("Address: " + macAddress(0)));
        sousItemsList[0].getChildren().add(new TreeItem<>(".... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)"));
        sousItemsList[0].getChildren().add(new TreeItem<>(".... ...0 .... .... .... .... = IG bit: Individual address (unicast)"));
        sousItemsList[1] = new TreeItem<>("Source: " + macAddress(6));
        sousItemsList[1].getChildren().add(new TreeItem<>("Address: " + macAddress(6)));
        sousItemsList[1].getChildren().add(new TreeItem<>(".... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)"));
        sousItemsList[1].getChildren().add(new TreeItem<>(".... ...0 .... .... .... .... = IG bit: Individual address (unicast)"));

        String protocol = bytesToHexString(bytes.get(12))+bytesToHexString(bytes.get(13));
        switch (protocol){
            case "0800":
                sousItemsList[2] = new TreeItem<>("Type IPv4 (0x0800)");
                treeItems.add(new TreeItem<>("Internet Protocol Version 4, Src: " + frame.getSrc() + ", Dst: " + frame.getDest()));

                break;
            case "0806":
                sousItemsList[2] = new TreeItem<>("Type ARP (0x0806)");
                treeItems.add(new TreeItem<>("Address Resolution Protocol (reply/gratuitous ARP)"));

                break;
            case "86dd":
                sousItemsList[2] = new TreeItem<>("Type: IPv6 (0x86dd)");

                break;

            default:
                sousItemsList[2] = new TreeItem<>("Type unknown");
        }

        treeItems.get(2).getChildren().addAll(sousItemsList);



        for (int i = 1; i < treeItems.size(); i++) {
            treeItemRoot.getChildren().add(treeItems.get(i));
        }
        treeItemRoot.setExpanded(true);
        treeView.setShowRoot(false);
        treeView.setRoot(treeItemRoot);
    }

    public String macAddress(int pos) {
        StringBuilder sb = new StringBuilder();
        sb.append(bytesToHexString(bytes.get(pos)));
        for (int i = 1; i < 6; i++) {
            sb.append(":");
            sb.append(bytesToHexString(bytes.get(pos + i)));
        }
        return sb.toString();
    }

    public static String bytesToHexString(Byte src) {
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null) {
            return null;
        }

        int v = src & 0xFF;
        String hv = Integer.toHexString(v);
        if (hv.length() < 2) {
            stringBuilder.append(0);
        }
        stringBuilder.append(hv);

        return stringBuilder.toString();
    }


}

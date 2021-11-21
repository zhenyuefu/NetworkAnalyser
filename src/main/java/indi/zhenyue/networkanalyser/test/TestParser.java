package indi.zhenyue.networkanalyser.test;

import indi.zhenyue.networkanalyser.packet.Packet;
import indi.zhenyue.networkanalyser.packet.PacketAnalyser;
import indi.zhenyue.networkanalyser.util.FileUtility;

import java.io.File;
import java.util.List;

public class TestParser {
    public static void main(String[] args) {
        File f = new File("1.txt");
        String packets = FileUtility.readFile(f);
        PacketAnalyser pa = new PacketAnalyser();
        List<Packet> list = pa.parse(packets);
        for (Packet packet : list) {
            System.out.println(packet);
        }
    }
}

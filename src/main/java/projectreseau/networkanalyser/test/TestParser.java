package projectreseau.networkanalyser.test;

import projectreseau.networkanalyser.packet.Packet;
import projectreseau.networkanalyser.packet.PacketAnalyser;
import projectreseau.networkanalyser.util.FileUtility;

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

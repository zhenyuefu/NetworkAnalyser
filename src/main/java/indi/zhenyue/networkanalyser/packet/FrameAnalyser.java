package indi.zhenyue.networkanalyser.packet;

import indi.zhenyue.networkanalyser.util.ArrayHelper;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;

import java.util.ArrayList;
import java.util.List;

public class FrameAnalyser {

    public static int cpt = 0;
    private final TableView<Frame> tableViewFrame;
    private final ObservableList<Frame> data;
    private final TableColumn<Frame, String> numCol, timeCol, srcCol, destCol, protocolCol, lengthCol, infoCol;
    private final String dataFrame;
    private final List<Byte> bytes = new ArrayList<>();
    private final List<Packet> packets;
    private double timeBegin;

    public FrameAnalyser(String dataFrame, List<Packet> packets, TableView<Frame> tableViewFrame, TableColumn<Frame, String> numCol,
                         TableColumn<Frame, String> timeCol, TableColumn<Frame, String> srcCol, TableColumn<Frame, String> destCol,
                         TableColumn<Frame, String> protocolCol, TableColumn<Frame, String> lengthCol,
                         TableColumn<Frame, String> infoCol) {
        this.dataFrame = dataFrame;
        this.packets = packets;
        this.tableViewFrame = tableViewFrame;
        this.data = FXCollections.observableArrayList();
        this.numCol = numCol;
        this.timeCol = timeCol;
        this.srcCol = srcCol;
        this.destCol = destCol;
        this.protocolCol = protocolCol;
        this.lengthCol = lengthCol;
        this.infoCol = infoCol;
        Frame.cpt = 0;
        init();
        analyser();
    }

    public void init() {
        numCol.setCellValueFactory(new PropertyValueFactory<>("id"));
        timeCol.setCellValueFactory(new PropertyValueFactory<>("time"));
        srcCol.setCellValueFactory(new PropertyValueFactory<>("src"));
        destCol.setCellValueFactory(new PropertyValueFactory<>("dest"));
        protocolCol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        lengthCol.setCellValueFactory(new PropertyValueFactory<>("length"));
        infoCol.setCellValueFactory(new PropertyValueFactory<>("info"));
        timeBegin = System.nanoTime();
    }

    public void analyser() {
        String[] s = dataFrame.split("\n");
        for (int i = 0; i < s.length; i++) {
            String[] s2 = s[i].split("\\s+");
            if (i != 0 && s2[0].equals("0000")) {
                extractFrame();
                bytes.clear();
            }
            column:
            for (int j = 0; j < s2.length; j++) {
                if (s2[j].length() == 2) {
                    try {
                        bytes.add((byte) Integer.parseInt(s2[j], 16));
                    } catch (NumberFormatException e) {
                        while (i < s.length - 1) {
                            i++;
                            s2 = s[i].split("\\s+");
                            if (s2[0].equals("0000")) {
                                i--;
                                break column;
                            }
                        }
                    }
                }
            }
        }
        extractFrame();
        bytes.clear();
    }

    private void extractFrame() {
        ContentFrame cf = new ContentFrame(packets.get(cpt));
        cpt++;

        double timeCurrent = (System.nanoTime() - timeBegin) / 1000000000;
        String ipsrc = IPAddress.toString(ArrayHelper.extractInteger(bytes, 26, 4));
        String ipdest = IPAddress.toString(ArrayHelper.extractInteger(bytes, 30, 4));
        String protocol = cf.getProtocol();
        String len = "" + bytes.size();
        addFrame(new Frame(String.format("%.6f", timeCurrent), ipsrc, ipdest, protocol, len, "1", bytes));
    }

    public void addFrame(Frame f) {
        data.add(f);
        update();
    }

    public void update() {
        this.tableViewFrame.setItems(data);
    }

}

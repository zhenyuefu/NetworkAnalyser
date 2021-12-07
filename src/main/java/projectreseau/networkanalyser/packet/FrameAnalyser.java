package projectreseau.networkanalyser.packet;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import projectreseau.networkanalyser.util.ArrayHelper;

import java.util.List;

public class FrameAnalyser {

    private final TableView<Frame> tableViewFrame;
    private final ObservableList<Frame> data;
    private final TableColumn<Frame, String> numCol, timeCol, srcCol, destCol, protocolCol, lengthCol, infoCol;
    private final List<Packet> packets;
    private byte[] bytes;

    public FrameAnalyser(List<Packet> packets, TableView<Frame> tableViewFrame, TableColumn<Frame, String> numCol,
                         TableColumn<Frame, String> timeCol, TableColumn<Frame, String> srcCol, TableColumn<Frame, String> destCol,
                         TableColumn<Frame, String> protocolCol, TableColumn<Frame, String> lengthCol,
                         TableColumn<Frame, String> infoCol) {
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
    }

    public void analyser() {
        for (Packet packet : packets) {
            bytes = packet.getBytes();
            extractFrame();
        }
    }

    private void extractFrame() {
        ContentFrame cf = new ContentFrame(packets.get(Frame.cpt));
        String ipsrc = IPAddress.toString(ArrayHelper.extractInteger(bytes, 26, 4));
        String ipdest = IPAddress.toString(ArrayHelper.extractInteger(bytes, 30, 4));
        String protocol = cf.getProtocol();
        String len = "" + bytes.length;
        String info = cf.getInfo();
        addFrame(new Frame(String.format("%.6f", (float) Frame.cpt / 1000000), ipsrc, ipdest, protocol, len, info));
    }

    public void addFrame(Frame f) {
        data.add(f);
        update();
    }

    public void update() {
        this.tableViewFrame.setItems(data);
    }

}

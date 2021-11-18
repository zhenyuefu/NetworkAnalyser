package indi.zhenyue.networkanalyser.packet;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

public class FrameAnalyser {

    private final TableView<Frame> tableViewFrame;
    private final ObservableList<Frame> data;
    private final TableColumn numCol, timeCol, srcCol, destCol, protocolCol, lengthCol, infoCol;
    private String dataFrame;
    private List<Byte> bytes = new ArrayList<>();


    public FrameAnalyser(String dataFrame, TableView<Frame> tableViewFrame, TableColumn numCol, TableColumn timeCol, TableColumn srcCol, TableColumn destCol, TableColumn protocolCol, TableColumn lengthCol, TableColumn infoCol) {
        this.dataFrame = dataFrame;
        this.tableViewFrame = tableViewFrame;
        this.data = FXCollections.observableArrayList();
        this.numCol = numCol;
        this.timeCol = timeCol;
        this.srcCol = srcCol;
        this.destCol = destCol;
        this.protocolCol = protocolCol;
        this.lengthCol = lengthCol;
        this.infoCol = infoCol;
        init();
        analyser();
    }

    public void init() {
        numCol.setCellValueFactory(new PropertyValueFactory<Frame, String>("id"));
        timeCol.setCellValueFactory(new PropertyValueFactory<Frame, String>("time"));
        srcCol.setCellValueFactory(new PropertyValueFactory<Frame, String>("src"));
        destCol.setCellValueFactory(new PropertyValueFactory<Frame, String>("dest"));
        protocolCol.setCellValueFactory(new PropertyValueFactory<Frame, String>("protocol"));
        lengthCol.setCellValueFactory(new PropertyValueFactory<Frame, String>("length"));
        infoCol.setCellValueFactory(new PropertyValueFactory<Frame, String>("info"));
        update();
    }

    public void analyser() {

        String[] s = dataFrame.split("\n");
        for (int i = 0; i < s.length; i++) {
            String[] s2 = s[i].split("\\s+");
            for (int j = 0; j < s2.length; j++) {
                if (s2[j].length() == 2) {
                    try {
                        bytes.add((byte) Integer.parseInt(s2[j], 16));
                    } catch (NumberFormatException e) {
                    }
                }
            }
            if(i!=0&&s2[0].equals("0000")){
                extractFrame();
                bytes.clear();
            }
        }



    }

    private void extractFrame() {
        String ipsrc = IPAddress.tostring(extractInteger(bytes, 26, 4));
        String ipdest = IPAddress.tostring(extractInteger(bytes, 30, 4));
        String protocol = null;
        if(extractInteger(bytes,23,1)==6){
            protocol = "TCP";
        }
        String len = ""+extractInteger(bytes,16,2);


        addFrame(new Frame("1", ipsrc, ipdest, protocol, len, "1"));
    }

    public int extractInteger(List<Byte> bytes, int pos, int cnt) {
        int value = 0;
        for (int i = 0; i < cnt; i++) {
            value |= ((bytes.get(pos + cnt - i - 1) & 0xff) << 8 * i);
        }
        return value;
    }

    public void addFrame(Frame f) {
        data.add(f);
        update();
    }

    public void update() {
        this.tableViewFrame.setItems(data);
    }

    public static short getUnsignedByteValue(final byte x) {
        ByteBuffer tmpBuffer = ByteBuffer.allocate(2);
        tmpBuffer.put(new byte[]{0x00, x});
        tmpBuffer.flip();
        tmpBuffer.order(ByteOrder.BIG_ENDIAN);
        return tmpBuffer.getShort();
    }

}

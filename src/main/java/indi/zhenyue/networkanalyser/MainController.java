package indi.zhenyue.networkanalyser;

import indi.zhenyue.networkanalyser.packet.*;
import indi.zhenyue.networkanalyser.util.FileUtility;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;

/**
 * @author zhenyue
 */
public class MainController {
    private Stage stage;
    @FXML
    private Label networkPacketLabel;
    @FXML
    private MenuBar menuBar;
    @FXML
    private ScrollPane scrollPane;
    @FXML
    private TableView<Frame> tableViewFrame;
    @FXML
    private TableColumn<Frame, String> numCol, timeCol, srcCol, destCol, protocolCol, lengthCol, infoCol;
    @FXML
    private TreeView<String> treeView;

    public void setStage(Stage stage) {
        this.stage = stage;
    }

    public MenuBar getMenuBar() {
        return menuBar;
    }

    @FXML
    protected void menuOpenOnClick() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Network Frame File");
        fileChooser.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("txt", "*.txt"),
                new FileChooser.ExtensionFilter("All Files", "*.*"));
        File packetFile = fileChooser.showOpenDialog(stage);
        if (packetFile != null) {
            PacketAnalyser pa = new PacketAnalyser();
            List<Packet> listPackets = pa.parse(FileUtility.readFile(packetFile));
            FrameAnalyser fa = new FrameAnalyser(listPackets, tableViewFrame, numCol, timeCol, srcCol, destCol, protocolCol, lengthCol, infoCol);
            tableViewFrame.getSelectionModel().selectedItemProperty().addListener((observableValue, frame, newFrame) -> new ContentFrame(treeView, newFrame, listPackets.get(Integer.parseInt(newFrame.getId()) - 1)));
        }
    }

    @FXML
    protected void menuExitOnClick() {
        stage.close();
    }

    private String openFile(File file) {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
                sb.append("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return sb.toString();
    }
}
package indi.zhenyue.networkanalyser;

import indi.zhenyue.networkanalyser.packet.Frame;
import indi.zhenyue.networkanalyser.packet.FrameAnalyser;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

/**
 * @author zhenyue
 */
public class MainController {
    private Stage stage;
    @FXML private Label networkPacketLabel;
    @FXML private MenuBar menuBar;
    @FXML private ScrollPane scrollPane;
    @FXML private TableView<Frame> tableViewFrame;
    @FXML private TableColumn numCol, timeCol, srcCol, destCol, protocolCol, lengthCol, infoCol;

    public void setStage(Stage stage) {
        this.stage = stage;
    }

    public MenuBar getMenuBar() {
        return menuBar;
    }

    @FXML protected void menuOpenOnClick() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Network Frame File");
        fileChooser.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("txt", "*.txt"),
            new FileChooser.ExtensionFilter("All Files", "*.*"));
        File packetFile = fileChooser.showOpenDialog(stage);
        if (packetFile != null) {
            //networkPacketLabel.setText(openFile(packetFile));
            FrameAnalyser fa = new FrameAnalyser(openFile(packetFile), tableViewFrame,numCol, timeCol, srcCol, destCol, protocolCol, lengthCol, infoCol);
        }
    }

    @FXML protected void menuExitOnClick() {
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
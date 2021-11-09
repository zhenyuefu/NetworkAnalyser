package indi.zhenyue.networkanalyser;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.MenuBar;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.*;

/**
 * @author zhenyue
 */
public class MainController {
    private Stage stage;
    @FXML private Label networkPacketLabel;
    @FXML private MenuBar menuBar;

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
            networkPacketLabel.setText(openFile(packetFile));
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
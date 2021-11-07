package indi.zhenyue.networkanalyser;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class HelloController {
    private Stage stage;
    @FXML private Label networkFrameLabel;
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
        fileChooser.getExtensionFilters().addAll(
            new FileChooser.ExtensionFilter("txt", "*.txt"),
            new FileChooser.ExtensionFilter("All Files", "*.*")
        );
        fileChooser.showOpenDialog(stage);
    }

    @FXML protected void menuExitOnClick() {
        stage.close();
    }
}
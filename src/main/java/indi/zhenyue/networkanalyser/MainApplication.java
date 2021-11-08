package indi.zhenyue.networkanalyser;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.MenuBar;
import javafx.stage.Stage;

import java.io.IOException;

public class MainApplication extends Application {
    @Override public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(MainApplication.class.getResource("net.fxml"));
        Scene scene = new Scene(fxmlLoader.load());
        MainController controller = fxmlLoader.getController();
        controller.setStage(stage);
        MenuBar menuBar = controller.getMenuBar();
        menuBar.setUseSystemMenuBar(true);
        stage.setTitle("Network Packet Analyser");
        stage.setScene(scene);
        stage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}
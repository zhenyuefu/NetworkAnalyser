package projectreseau.networkanalyser;

import projectreseau.networkanalyser.packet.*;
import projectreseau.networkanalyser.util.FileUtility;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.*;
import java.util.ArrayList;
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
    private TableView<Frame> tableViewFrame;
    @FXML
    private TableColumn<Frame, String> numCol, timeCol, srcCol, destCol, protocolCol, lengthCol, infoCol;
    @FXML
    private TreeView<String> treeView;
    private final List<Packet> listPackets = new ArrayList<>();

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
            listPackets.clear();
            listPackets.addAll(pa.parse(FileUtility.readFile(packetFile)));
            FrameAnalyser fa = new FrameAnalyser(listPackets, tableViewFrame, numCol, timeCol, srcCol, destCol, protocolCol, lengthCol, infoCol);
            tableViewFrame.getSelectionModel().selectedItemProperty().addListener((observableValue, frame, newFrame) -> {
                try {
                    new ContentFrame(treeView, Integer.parseInt(newFrame.getId()), listPackets.get(Integer.parseInt(newFrame.getId()) - 1));
                } catch (NullPointerException ignored) {
                }
            });
        }
    }

    @FXML
    protected void menuExportOnClick() throws IOException {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Export...");
        fileChooser.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("txt", "*.txt"),
                new FileChooser.ExtensionFilter("All Files", "*.*"));
        File exportFile = fileChooser.showSaveDialog(stage);

        TreeItem<String> root = new TreeItem<>();
        ContentFrame cf;
        int i = 1;
        for (Packet packet : listPackets) {
            cf = new ContentFrame(i, packet);
            root.getChildren().add(cf.getTreeItemRoot());
            i++;
        }
        String treeString = treeToString(root);

        FileOutputStream fos = null;
        PrintWriter pw = null;
        try {
            if (!exportFile.exists() || exportFile.delete())
                if (exportFile.createNewFile()) {
                    fos = new FileOutputStream(exportFile);
                    pw = new PrintWriter(fos);
                    pw.println(treeString);
                    pw.flush();
                }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fos != null) {
                fos.close();
            }
            if (pw != null) {
                pw.close();
            }
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

    private String treeToString(TreeItem<String> root) {
        StringBuilder sb = new StringBuilder();

        for (var item1 : root.getChildren()) {
            for (var item2 : item1.getChildren()) {
                sb.append(item2.getValue()).append("\n");
                for (var item3 : item2.getChildren()) {
                    sb.append("\t").append(item3.getValue()).append("\n");
                    for (var item4 : item3.getChildren()) {
                        sb.append("\t\t").append(item4.getValue()).append("\n");
                        for (var item5 : item4.getChildren()) {
                            sb.append("\t\t\t").append(item5.getValue()).append("\n");
                        }
                    }
                }
            }
            sb.append("\n");
        }
        return sb.toString();
    }
}
module indi.zhenyue.networkanalyser {
    requires javafx.controls;
    requires javafx.fxml;

    opens indi.zhenyue.networkanalyser to javafx.fxml, javafx.controls;
    exports indi.zhenyue.networkanalyser;
}
module Networkanalyser {
    requires javafx.controls;
    requires javafx.fxml;

    opens projectreseau.networkanalyser.packet;
    opens projectreseau.networkanalyser to javafx.fxml, javafx.controls;
    exports projectreseau.networkanalyser;
}
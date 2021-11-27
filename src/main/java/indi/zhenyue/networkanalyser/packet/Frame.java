package indi.zhenyue.networkanalyser.packet;

import javafx.beans.property.SimpleStringProperty;

import java.util.ArrayList;
import java.util.List;

public class Frame {

    public static int cpt = 0;
    private final SimpleStringProperty id, time, src, dest, protocol, length, info;
    private final List<Byte> bytes;

    public Frame(String time, String src, String dest, String protocol, String length, String info, List<Byte> bytes) {
        this.id = new SimpleStringProperty(++cpt + "");
        this.time = new SimpleStringProperty(time);
        this.src = new SimpleStringProperty(src);
        this.dest = new SimpleStringProperty(dest);
        this.protocol = new SimpleStringProperty(protocol);
        this.length = new SimpleStringProperty(length);
        this.info = new SimpleStringProperty(info);
        this.bytes = new ArrayList<>();
        this.bytes.addAll(bytes);
    }

    public String getId() {
        return id.get();
    }

    public void setId(String id) {
        this.id.set(id);
    }

    public String getTime() {
        return time.get();
    }

    public void setTime(String time) {
        this.time.set(time);
    }

    public String getSrc() {
        return src.get();
    }

    public void setSrc(String src) {
        this.src.set(src);
    }

    public String getDest() {
        return dest.get();
    }

    public void setDest(String dest) {
        this.dest.set(dest);
    }

    public String getProtocol() {
        return protocol.get();
    }

    public void setProtocol(String protocol) {
        this.protocol.set(protocol);
    }

    public String getLength() {
        return length.get();
    }

    public void setLength(String length) {
        this.length.set(length);
    }

    public String getInfo() {
        return info.get();
    }

    public void setInfo(String info) {
        this.info.set(info);
    }

}

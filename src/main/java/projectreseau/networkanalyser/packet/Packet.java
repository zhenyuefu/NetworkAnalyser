package projectreseau.networkanalyser.packet;

import java.util.Arrays;

public class Packet {
    protected byte[] bytes;

    public Packet(byte[] bytes) {
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public void setBytes(byte[] bytes) {
        this.bytes = bytes;
    }

    @Override public String toString() {
        return "Packet{" + "bytes=" + Arrays.toString(bytes) + '}';
    }

}

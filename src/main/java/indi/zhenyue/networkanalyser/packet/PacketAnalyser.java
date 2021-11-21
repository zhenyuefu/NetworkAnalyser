package indi.zhenyue.networkanalyser.packet;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class PacketAnalyser {

    private static final int BASE = 16;
    private static final int MAX_PACKET_SIZE = 65535;
    private final List<Packet> packetsList;
    private ByteBuffer byteBuffer;
    private int curr_offset = 0;

    public PacketAnalyser() {
        packetsList = new ArrayList<>();
    }

    public List<Packet> parse(String packets) {
        PARSER_STATE state = PARSER_STATE.INIT;

        byteBuffer = ByteBuffer.allocate(MAX_PACKET_SIZE);

        String[] lines = packets.split("\\R+");
        loop_line:
        for (String line : lines) {
            String[] words = line.split("\\s+");
            if (state != PARSER_STATE.INIT) {
                state = PARSER_STATE.START_OF_LINE;
            }

            for (String word : words) {
                switch (state) {
                    case INIT:
                        try {
                            if (word.length() > 2) {
                                int value = Integer.parseInt(word, BASE);

                                if (value == 0) {
                                    start_new_packet();
                                    state = PARSER_STATE.READ_OFFSET;
                                    break;

                                }
                            }
                        } catch (NumberFormatException e) {
                            System.err.println(e.getMessage());
                        }
                        continue loop_line;

                    case START_OF_LINE:
                        try {
                            if (word.length() > 2) {
                                int num = Integer.parseInt(word, BASE);
                                if (num == 0) {
                                    start_new_packet();
                                    state = PARSER_STATE.READ_OFFSET;
                                    break;
                                } else if (num != curr_offset) {
                                    if (num < curr_offset) {
                                        byteBuffer.position(num);
                                        state = PARSER_STATE.READ_OFFSET;
                                    } else {
                                        /* bad offset, switch to INIT state */
                                        start_new_packet();
                                        state = PARSER_STATE.INIT;
                                    }
                                } else {
                                    state = PARSER_STATE.READ_OFFSET;
                                }
                                break;
                            }
                        } catch (NumberFormatException e) {
                            System.err.println(e.getMessage());
                        }
                        continue loop_line;

                        /* read offset */
                    case READ_OFFSET:
                        try {
                            if (word.length() == 2) {
                                int value = Integer.parseInt(word, BASE);
                                byteBuffer.put((byte)value);
                                curr_offset++;
                                state = PARSER_STATE.READ_BYTE;
                                break;
                            }
                        } catch (NumberFormatException e) {
                            System.err.println(e.getMessage());
                        }
                        state = PARSER_STATE.READ_TEXT;
                        break;

                    case READ_BYTE:
                        try {
                            if (word.length() == 2) {
                                int value = Integer.parseInt(word, BASE);
                                byteBuffer.put((byte)value);
                                curr_offset++;
                                break;
                            }
                        } catch (NumberFormatException e) {
                            System.err.println(e.getMessage());
                        }
                        state = PARSER_STATE.READ_TEXT;
                        break;

                    case READ_TEXT:
                        state = PARSER_STATE.START_OF_LINE;
                        continue loop_line;
                    default:
                        break;
                }

            }

        }
        start_new_packet();
        return packetsList;
    }

    private void start_new_packet() {
        if (curr_offset > 0) {
            byte[] bytes = new byte[byteBuffer.position()];
            byteBuffer.flip();
            byteBuffer.get(bytes);
            packetsList.add(new Packet(bytes));
            byteBuffer.clear();
            curr_offset = 0;
        }
    }

    private enum PARSER_STATE {
        INIT,             /* Waiting for start of new packet */
        START_OF_LINE,    /* Starting from beginning of line */
        READ_OFFSET,      /* Just read the offset */
        READ_BYTE,        /* Just read a byte */
        READ_TEXT         /* Just read text - ignore until EOL */
    }

}

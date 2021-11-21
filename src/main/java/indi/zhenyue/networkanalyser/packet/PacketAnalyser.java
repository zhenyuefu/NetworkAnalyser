package indi.zhenyue.networkanalyser.packet;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * This program parses the Ascii hexdump string into a list of packets
 *
 * @author zhenyue
 */
public class PacketAnalyser {

    private static final int BASE = 16;
    private static final int MAX_PACKET_SIZE = 65535;
    private final List<Packet> packetsList;
    private ByteBuffer byteBuffer;
    private int curr_offset = 0;

    public PacketAnalyser() {
        packetsList = new ArrayList<>();
    }

    /**
     * This utility converts an ASCII hexdump string of this common format:
     * <p>
     * 00000000  00 E0 1E A7 05 6F 00 10 5A A0 B9 12 08 00 46 00 .....o..Z.....F. <br>
     * 00000010  03 68 00 00 00 00 0A 2E EE 33 0F 19 08 7F 0F 19 .h.......3...... <br>
     * 00000020  03 80 94 04 00 00 10 01 16 A2 0A 00 03 50 00 0C .............P.. <br>
     * 00000030  01 01 0F 19 03 80 11 01 1E 61 00 0C 03 01 0F 19 .........a...... <br>
     * <p>
     * Each line consists of an offset, one or more bytes, and
     * text at the end. An offset is defined as a hex string of more than
     * two characters. A byte is defined as a hex string of exactly two
     * characters. The text at the end is ignored, as is any text before
     * the offset. Bytes read from a line are added to the
     * current packet only if all the following conditions are satisfied:
     * <p>
     * - No text appears between the offset and the bytes (any bytes appearing after
     * such text would be ignored)
     * <p>
     * - The offset must be arithmetically correct, i.e. if the offset is 00000020, then
     * exactly 32 bytes must have been read into this packet before this. If the offset
     * is wrong, the packet is immediately terminated
     * <p>
     * A packet start is signalled by a zero offset.
     * <p>
     * This converter cannot read a single packet greater than 64KiB-1. Packet
     * snaplength is automatically set to 64KiB-1.
     *
     * @param packets an ASCII hexdump string
     * @return List of the Packets
     */
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

    /**
     * Adds the bits currently saved in the buffer to the list and resets the buffer.
     */
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

package net.jpeelaer.hce.desfire;

import org.kevinvalk.hce.framework.apdu.CommandApdu;

import java.nio.ByteBuffer;

/**
 * Created by jekkos on 7/22/15.
 */
public class CommandApdus {

    public final static byte[] SELECT = {0, (byte) 0xa4, 0x04, 0, 0x07, (byte) 0xd2, 0x76, 0, 0, (byte) 0x85, 0x01, 0, 0};
    public final static byte[] VERSION = {(byte) 0x90, 0x60, 0x00, 0x00};
    public final static byte[] CONTINUE = {(byte) 0x90, (byte) 0xAF, 0x00, 0x00};

    public static CommandApdu parseApdu(String bytes) {
        return new CommandApdu(parseBytes(bytes).array());
    }

    public static ByteBuffer parseBytes(String bytes) {
        return parseBytes(bytes, bytes.split(" ").length);
    }

    public static ByteBuffer parseBytes(String bytes, int length) {
        String[] tokenizedBytes = bytes.split(" ");
        ByteBuffer buffer = ByteBuffer.allocate(length);
        for (String tokenizedByte : tokenizedBytes) {
            buffer.put(Short.valueOf(tokenizedByte, 16).byteValue());
        }
        return buffer;
    }
}

package net.jpeelaer.hce.desfire;

/**
 * Created by jekkos on 7/22/15.
 */
public class CommandApdus {

    public final static byte[] SELECT = {0, (byte) 0xa4, 0x04, 0, 0x07, (byte) 0xd2, 0x76, 0, 0, (byte) 0x85, 0x01, 0, 0};
    public final static byte[] VERSION = {(byte) 0x90, 0x60, 0x00, 0x00};
    public final static byte[] CONTINUE = {(byte) 0x90, (byte) 0xAF, 0x00, 0x00};

}

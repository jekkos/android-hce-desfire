package net.jpeelaer.hce.desfire;

import org.kevinvalk.hce.framework.Iso7816;
import org.kevinvalk.hce.framework.apdu.ResponseApdu;

public class ResponseApdus {

    public final static byte[] FRAME_CONTINUE = new byte[] {(byte) 0x91, (byte) 0xAF};
    public final static byte[] OPERATION_OK = new byte[] {(byte) 0x91, (byte) 0x00};

    public final static byte[] OK =  new ResponseApdu(Iso7816.SW_NO_ERROR).getBuffer();

    public final static byte[] INIT = new byte[0];

    public static final byte[] VERSION =  new byte[] {
        0x04, 0x01, 0x01, 0x01, 0x00, 0x1a, 0x05,
        0x04, 0x01, 0x01, 0x01, 0x03, 0x1a, 0x05,
        // 00  04  91  3a  29  93  26  80  00  00  00  00  00  39  08  91  00
        0x04, (byte) 0x91, 0x3a, 0x29, (byte) 0x93, 0x26, (byte) 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x39, 0x08
    };

    public static final byte[] VERSION_1 = Util.subByteArray(ResponseApdus.VERSION, (short) 0, (short) 6);
    public static final byte[] VERSION_2 = Util.subByteArray(ResponseApdus.VERSION, (short) 7, (short) 13);
    public static final byte[] VERSION_3 = Util.subByteArray(ResponseApdus.VERSION, (short) 14, (short) (VERSION.length - 1));

}

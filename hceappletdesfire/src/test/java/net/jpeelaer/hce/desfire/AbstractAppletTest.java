package net.jpeelaer.hce.desfire;

import org.kevinvalk.hce.framework.apdu.CommandApdu;
import org.kevinvalk.hce.framework.apdu.ResponseApdu;

import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Created by jekkos on 8/27/15.
 */
public class AbstractAppletTest {
    protected DesfireApplet applet;

    public AbstractAppletTest() throws NoSuchAlgorithmException, NoSuchPaddingException {
        applet = new DesfireApplet();
    }

    protected void createApplication () {
        // create directory
        {
            CommandApdu commandApdu = new CommandApdu(new byte[] {(byte) 0x90, (byte) 0xCA,
                    0x00, 0x00, 0x05, (byte) 0xF4,
                    (byte) 0x83, 0x40, 0x00, (byte) 0x8E, 0x00});
            ResponseApdu process = applet.process(commandApdu);
            byte[] operationOk = Util.shortToByteArray(Util.OPERATION_OK);
            Arrays.equals(process.getBuffer(), operationOk);
        }

        // create file
        {
            CommandApdu commandApdu = new CommandApdu(new byte[] {(byte) 0x90, (byte) 0xCD,
                    0, 0, 0x07, 0x00, 0x03, 0, 0, 0x10, 0});
            ResponseApdu process = applet.process(commandApdu);
            byte[] operationOk = Util.shortToByteArray(Util.OPERATION_OK);
            Arrays.equals(process.getBuffer(), operationOk);
        }

    }
}

package net.jpeelaer.hce.desfire;

import org.kevinvalk.hce.framework.apdu.CommandApdu;
import org.kevinvalk.hce.framework.apdu.ResponseApdu;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.internal.stubbing.answers.CallsRealMethods;
import org.mockito.stubbing.Answer;

import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Created by jekkos on 8/27/15.
 */
public class AbstractAppletTest {

    @Spy
    protected DesfireApplet applet;

    protected void createApplication (byte keyType) {
        // create directory
        {
            CommandApdu commandApdu = CommandApdus.parseApdu("90 CA 00 00 05 F4 83 40 00 8E 00");
            ResponseApdu process = applet.process(commandApdu);
            byte[] operationOk = Util.shortToByteArray(Util.OPERATION_OK);
            Arrays.equals(process.getBuffer(), operationOk);
        }

        // create file
        {
            CommandApdu commandApdu = CommandApdus.parseApdu("90 CD 00 00 07 00 03 00 00 10 00");
            ResponseApdu process = applet.process(commandApdu);
            byte[] operationOk = Util.shortToByteArray(Util.OPERATION_OK);
            Arrays.equals(process.getBuffer(), operationOk);
        }

        // select directory
        {
            CommandApdu commandApdu = CommandApdus.parseApdu("90 5A 00 00 03 F4 83 40");
            ResponseApdu process = applet.process(commandApdu);
            byte[] operationOk = Util.shortToByteArray(Util.OPERATION_OK);
            Arrays.equals(process.getBuffer(), operationOk);
        }
    }
}

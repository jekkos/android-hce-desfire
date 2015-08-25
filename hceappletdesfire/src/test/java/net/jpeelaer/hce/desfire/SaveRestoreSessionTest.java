package net.jpeelaer.hce.desfire;

import org.junit.Assert;
import org.junit.Test;
import org.kevinvalk.hce.framework.apdu.CommandApdu;
import org.kevinvalk.hce.framework.apdu.ResponseApdu;
import org.yaml.snakeyaml.Yaml;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Created by jekkos on 8/24/15.
 */
public class SaveRestoreSessionTest {

    private DesfireApplet applet;

    public SaveRestoreSessionTest() {
        try {
            applet = new DesfireApplet();
        } catch (NoSuchAlgorithmException e) {
            Assert.fail("Couldn't initialize applet, no such algorithm");
        } catch (NoSuchProviderException e) {
            Assert.fail("Couldn't initialize applet: no such cipher");
        } catch (NoSuchPaddingException e) {
            Assert.fail("Couldn't initialize applet: No such padding");
        } catch (InvalidKeyException e) {
            Assert.fail("Couldn't initialize applet: invalid key");
        } catch (InvalidKeySpecException e) {
            Assert.fail("Couldn't initialize applet: invalid key spec");
        }
    }

    @Test
    public void saveSession() {
        CommandApdu commandApdu = new CommandApdu(new byte[] {(byte) 0x90, (byte) 0xCA,
                0x00, 0x00, 0x05, (byte) 0xF4,
                (byte) 0x83, 0x40, 0x00, (byte) 0x8E, 0x00});
        ResponseApdu process = applet.process(commandApdu);
        byte[] operationOk = Util.shortToByteArray(Util.OPERATION_OK);
        Arrays.equals(process.getBuffer(), operationOk);

        Yaml yaml = new Yaml();
        String dump = yaml.dump(applet.masterFile);
        Object restoredDump = yaml.load(dump);

        Assert.assertTrue(restoredDump instanceof MasterFile);
        MasterFile masterFile = (MasterFile) restoredDump;
        Assert.assertEquals(masterFile.arrayDF.length, applet.masterFile.arrayDF.length);
    }
}

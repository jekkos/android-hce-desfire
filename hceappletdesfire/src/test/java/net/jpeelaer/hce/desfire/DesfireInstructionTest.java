package net.jpeelaer.hce.desfire;

import android.nfc.Tag;
import com.google.common.collect.Lists;
import junit.framework.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.kevinvalk.hce.framework.HceFramework;
import org.kevinvalk.hce.framework.TagWrapper;
import org.kevinvalk.hce.framework.apdu.CommandApdu;
import org.kevinvalk.hce.framework.apdu.ResponseApdu;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import static junit.framework.Assert.assertTrue;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class DesfireInstructionTest extends AbstractAppletTest {

    private final List<byte[]> commands = Lists.newArrayList(CommandApdus.SELECT, CommandApdus.VERSION,
            CommandApdus.CONTINUE, CommandApdus.CONTINUE, ResponseApdus.OK);

    private final List<byte[]> responses = Lists.newArrayList(ResponseApdus.INIT, ResponseApdus.OK,
            Util.concatByteArray(ResponseApdus.VERSION_1, ResponseApdus.FRAME_CONTINUE),
            Util.concatByteArray(ResponseApdus.VERSION_2, ResponseApdus.FRAME_CONTINUE),
            Util.concatByteArray(ResponseApdus.VERSION_3, ResponseApdus.OPERATION_OK));

    private int requestCounter = 0;

    @Test
    public void testDesfireLegacyAuthenticate() throws GeneralSecurityException {
        // first setup master file
        createApplication(Util.TKTDES);

        authenticate(8, "DESede", DesFireInstruction.AUTHENTICATE);

        // add 3 more keys to application
        // change master key .. 6..41 = enciphered new key? .. will need to follow (if authenticated it can be readily decrypted)
        CommandApdu commandApdu = new CommandApdu(new byte[] {(byte) 0x90, DesFireInstruction.CHANGE_KEY.toByte(), 0, 0, 41, 0});

    }

    private void authenticate(int keySize, String algorithm, DesFireInstruction instruction) throws GeneralSecurityException {
        // authenticate key 0 (old style)
        CommandApdu authenticateCommmand = new CommandApdu(new byte[] {(byte) 0x90, instruction.toByte(), 0, 0, 1, 0});
        ResponseApdu responseApdu = applet.process(authenticateCommmand);
        byte[] buffer = responseApdu.getBuffer();
        Assert.assertEquals(keySize + 2, buffer.length);
        byte[] encRndB = Util.subByteArray(buffer, (short) 0, (short) (buffer.length - 3));
        Assert.assertEquals(keySize, encRndB.length);
        byte[] rndB = new byte[keySize];
        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/NoPadding");
        Key secretKey = new SecretKeySpec("AES".equals(algorithm) ? Util.AES_DEFAULT : Util.TKDES_DEFAULT, algorithm);

        byte[] ivBytes = new byte[keySize];
        Arrays.fill(ivBytes, (byte) 0);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        rndB = cipher.doFinal(encRndB);

        SecureRandom random = new SecureRandom();
        byte[] rndA = new byte[keySize];
        random.nextBytes(rndA);
        byte[] command = new byte[] {(byte) 0x90, (byte) 0xAF, 0, 0,(byte) (keySize * 2)};
        ByteBuffer rndArndB = ByteBuffer.allocate(keySize * 2);
        rndB = Util.rotateLeft(rndB);

        byte[] encRndArndB = new byte[keySize * 2];

        // legacy mode = DECRYPT, non legacy = ENCRYPT
        boolean legacyMode = instruction == DesFireInstruction.AUTHENTICATE;
        cipher.init(legacyMode ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE,
                secretKey, ivParameterSpec);
        encRndArndB = cipher.doFinal(rndArndB.put(rndA).put(rndB).array());

        ByteBuffer byteBuffer = ByteBuffer.allocate(command.length + encRndArndB.length);
        byteBuffer.put(command).put(encRndArndB);

        // authenticate (2) send random bytes
        authenticateCommmand = new CommandApdu(byteBuffer.array());
        responseApdu = applet.process(authenticateCommmand);
        // decrypt and assert?
        byte[] encPiccRndA = Util.subByteArray(responseApdu.getBuffer(), (byte) 0, (byte) (keySize - 1));
        byte[] piccRndA = new byte[keySize];

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        piccRndA = cipher.doFinal(encPiccRndA);
        piccRndA = Util.rotateRight(piccRndA);
        assertTrue(Arrays.equals(rndA, piccRndA));
    }

    @Test
    public void testDesfireAuthenticate() throws GeneralSecurityException{
        createApplication(Util.AES);

        authenticate(16, "AES", DesFireInstruction.AUTHENTICATE_AES);
    }


    @Test
    public void testGetDesfireVersion() throws IOException, GeneralSecurityException {
        // class under test
        HceFramework framework = new HceFramework();
        framework.register(applet);
        Tag tag = Mockito.mock(Tag.class);
        TagWrapper tagWrapper = Mockito.mock(TagWrapper.class);

        when(tagWrapper.isConnected()).thenReturn(true);
        try {
            when(tagWrapper.transceive(responseApdu())).thenAnswer(commandApdu());
        } catch (IOException e) {
            Assert.fail();
        }
        framework.handleTag(tagWrapper);
        // send out version request..
        verify(tagWrapper, times(5)).transceive(Mockito.<byte[]>any());
    }

    private Answer<byte[]> commandApdu() {
        return new Answer<byte[]>() {
            @Override
            public byte[] answer(InvocationOnMock invocation) throws Throwable {
                return commands.get(requestCounter++);
            }
        };
    }

    private byte[] responseApdu() {
        return Mockito.argThat(new ArgumentMatcher<byte[]>() {

            @Override
            public boolean matches(Object o) {
                if (o instanceof byte[]) {
                    byte[] bytez = responses.get(requestCounter);
                    return Arrays.equals(bytez, (byte[]) o);
                }
                return false;
            }

        });
    }

}

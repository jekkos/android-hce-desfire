package net.jpeelaer.hce.desfire;

import android.nfc.Tag;
import com.google.common.collect.Lists;
import junit.framework.Assert;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.kevinvalk.hce.framework.HceFramework;
import org.kevinvalk.hce.framework.TagWrapper;
import org.kevinvalk.hce.framework.apdu.CommandApdu;
import org.kevinvalk.hce.framework.apdu.ResponseApdu;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import java.util.List;

import static junit.framework.Assert.assertTrue;
import static org.mockito.Mockito.*;

/**
 * Created by jekkos on 7/14/15.
 */
@RunWith(MockitoJUnitRunner.class)
public class DesfireInstructionTest extends AbstractAppletTest {

    private final List<byte[]> commands = Lists.newArrayList(CommandApdus.SELECT, CommandApdus.VERSION,
            CommandApdus.CONTINUE, CommandApdus.CONTINUE, ResponseApdus.OK);

    private final List<byte[]> responses = Lists.newArrayList(ResponseApdus.INIT, ResponseApdus.OK,
            Util.concatByteArray(ResponseApdus.VERSION_1, ResponseApdus.FRAME_CONTINUE),
            Util.concatByteArray(ResponseApdus.VERSION_2, ResponseApdus.FRAME_CONTINUE),
            Util.concatByteArray(ResponseApdus.VERSION_3, ResponseApdus.OPERATION_OK));

    private int requestCounter = 0;

    public DesfireInstructionTest() throws NoSuchAlgorithmException, NoSuchPaddingException { }

    @Test
    public void testDesfireAuthenticate() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, ShortBufferException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException {
        // first setup master file
        createApplication();

        {
            // authenticate key 0 (old style)
            CommandApdu authenticateCommmand = new CommandApdu(new byte[] {(byte) 0x90, (byte) 0x0A, 0, 0, 1, 0});
            ResponseApdu responseApdu = applet.process(authenticateCommmand);
            byte[] buffer = responseApdu.getBuffer();
            Assert.assertEquals(10, buffer.length);
            byte[] encRndB = Util.subByteArray(buffer, (short) 0, (short) (buffer.length - 3));
            Assert.assertEquals(8, encRndB.length);
            byte[] rndB = new byte[8];
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            Key deSede = new SecretKeySpec(Util.DEFAULT_MASTER_KEY, "DESede");

            byte[] ivBytes = new byte[8];
            Arrays.fill(ivBytes, (byte) 0);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, deSede, ivParameterSpec);
            cipher.doFinal(encRndB, 0, 8, rndB);

            SecureRandom random = new SecureRandom();
            byte[] rndA = new byte[8];
            random.nextBytes(rndA);
            byte[] command = new byte[] {(byte) 0x90, (byte) 0xAF, 0, 0, 16};
            ByteBuffer rndArndB = ByteBuffer.allocate(16);
            rndB = Util.rotateLeft(rndB);

            byte[] encRndArndB = new byte[16];

            // legacy mode = DECRYPT, non legacy = ENCRYPT
            cipher.init(Cipher.DECRYPT_MODE, deSede, ivParameterSpec);
            cipher.doFinal(rndArndB.put(rndA).put(rndB).array(), 0, encRndArndB.length, encRndArndB);

            ByteBuffer byteBuffer = ByteBuffer.allocate(command.length + encRndArndB.length);
            byteBuffer.put(command).put(encRndArndB);

            // authenticate (2) send random bytes
            authenticateCommmand = new CommandApdu(byteBuffer.array());
            responseApdu = applet.process(authenticateCommmand);
            // decrypt and assert?
            byte[] encPiccRndA = Util.subByteArray(responseApdu.getBuffer(), (byte) 0, (byte) 7);
            byte[] piccRndA = new byte[8];
            cipher.doFinal(encPiccRndA, 0, encPiccRndA.length, piccRndA);
            piccRndA = Util.rotateRight(piccRndA);
            assertTrue(Arrays.equals(rndA, piccRndA));
        }

        {
            // add 3 more keys to application
            // change master key .. 6..41 = enciphered new key? .. will need to follow (if authenticated it can be readily decrypted)
            CommandApdu commandApdu = new CommandApdu(new byte[] {(byte) 0x90, (byte) 0xC4, 0, 0, 41, 0});
        }

    }


    @Test
    public void testGetDesfireVersion() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException {
        // class under test
        HceFramework framework = new HceFramework();
        framework.register(applet);
        Tag tag = Mockito.mock(Tag.class);
        TagWrapper tagWrapper = Mockito.mock(TagWrapper.class);

        when(tagWrapper.isConnected()).thenReturn(true);
        try {
            when(tagWrapper.transceive(responzeApdu())).thenAnswer(commandApdu());
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

    private byte[] responzeApdu() {
        return Mockito.argThat(new BaseMatcher<byte[]>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("Bytes expected: ");
                byte[] bytez = responses.get(requestCounter);
                description.appendText(Arrays.toString(bytez));
            }

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

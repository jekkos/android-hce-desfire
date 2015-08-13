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
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

import static junit.framework.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Created by jekkos on 7/14/15.
 */
@RunWith(MockitoJUnitRunner.class)
public class AppletTest {

    private final List<byte[]> commands = Lists.newArrayList(CommandApdus.SELECT, CommandApdus.VERSION,
            CommandApdus.CONTINUE, CommandApdus.CONTINUE, ResponseApdus.OK);

    private final List<byte[]> responses = Lists.newArrayList(ResponseApdus.INIT, ResponseApdus.OK,
            Util.concatByteArray(ResponseApdus.VERSION_1, ResponseApdus.FRAME_CONTINUE),
            Util.concatByteArray(ResponseApdus.VERSION_2, ResponseApdus.FRAME_CONTINUE),
            Util.concatByteArray(ResponseApdus.VERSION_3, ResponseApdus.OPERATION_OK));

    private int requestCounter = 0;

    @Test
    public void testGetDesfireVersion() throws InvalidKeySpecException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, IOException {
        // class under test
        DesfireApplet applet = new DesfireApplet();

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

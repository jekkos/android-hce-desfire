package net.jpeelaer.hce.desfire;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.security.Key;
import java.util.Arrays;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

public class DesfireCryptoTest {

    @Test
    public void testSessionKeyCreation() {
        {
            ByteBuffer rndA = CommandApdus.parseBytes("00 01 02 03 04 05 06 07");
            ByteBuffer rndB = CommandApdus.parseBytes("D1 A5 6D 00 6D B7 DF 5E");
            Key generatedSessionKey = DesfireKey.TK3DES.buildSessionKey(rndA.array(), rndB.array());
            assertEquals("DESede", generatedSessionKey.getAlgorithm());
            ByteBuffer sessionKey = CommandApdus.parseBytes("00 01 02 03 D1 A5 6D 00 04 05 06 07 6D B7 DF 5E");
            assertTrue(Arrays.equals(sessionKey.array(), generatedSessionKey.getEncoded()));
        }

        {
            ByteBuffer rndA = CommandApdus.parseBytes("41 12 01 1A 11 12 0C 22");
            ByteBuffer rndB = CommandApdus.parseBytes("B6 0E 3A 8D B9 63 43 DA");
            Key generatedSessionKey = DesfireKey.DES.buildSessionKey(rndA.array(), rndB.array());
            ByteBuffer sessionKey = CommandApdus.parseBytes("41 12 01 1A B6 0E 3A 8D");
            // chop off first 8 bytes
            byte[] bytes = Util.subByteArray(generatedSessionKey.getEncoded(), (short) 0, (short) 7);
            assertTrue(Arrays.equals(bytes, sessionKey.array()));
        }


    }

}

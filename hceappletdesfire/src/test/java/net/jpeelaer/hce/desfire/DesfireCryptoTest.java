package net.jpeelaer.hce.desfire;

import org.junit.Test;
import org.kevinvalk.hce.framework.apdu.CommandApdu;

import java.nio.ByteBuffer;
import java.security.Key;
import java.util.Arrays;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

public class DesfireCryptoTest extends AbstractAppletTest {

    @Test
    public void testSessionKeyCreation() {
        {
            ByteBuffer rndA = CommandApdus.parseBytes("00 01 02 03 04 05 06 07");
            ByteBuffer rndB = CommandApdus.parseBytes("D1 A5 6D 00 6D B7 DF 5E");
            Key generatedSessionKey = DesfireKey.TDES.buildSessionKey(rndA.array(), rndB.array());
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

        {
            ByteBuffer rndA = CommandApdus.parseBytes("74 B2 5E EC AC 78 DE DB 35 3C EC A7 AD 44 4C 20");
            ByteBuffer rndB = CommandApdus.parseBytes("6B A4 28 79 EC 04 7A 88 CF 51 95 62 45 DF 31 A6");
            Key generatedSessionKey = DesfireKey.AES.buildSessionKey(rndA.array(), rndB.array());
            ByteBuffer sessionKey = CommandApdus.parseBytes("74 B2 5E EC 6B A4 28 79 AD 44 4C 20 45 DF 31 A6");
            assertTrue(Arrays.equals(generatedSessionKey.getEncoded(), sessionKey.array()));
        }

    }

    @Test
    public void testCrc32() {

        {
            ByteBuffer inputData = CommandApdus.parseBytes("C4 00 01 02 03 00 00 00 00 00 00 00 00 00 00 00 00 00");
            byte[] crc32 = Util.crc32(inputData.array());
            ByteBuffer expectedCrc32 = CommandApdus.parseBytes("FD 25 74 8E");
            assertTrue(Arrays.equals(expectedCrc32.array(), crc32));
        }

        {
            ByteBuffer inputData = CommandApdus.parseBytes("C4 00 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 00");
            byte[] crc32 = Util.crc32(inputData.array());
            ByteBuffer expectedCrc32 = CommandApdus.parseBytes("65 b3 01 cb");
            assertTrue(Arrays.equals(expectedCrc32.array(), crc32));
        }


    }

}

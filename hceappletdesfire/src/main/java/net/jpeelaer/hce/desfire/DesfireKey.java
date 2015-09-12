package net.jpeelaer.hce.desfire;

import org.kevinvalk.hce.framework.IsoException;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Arrays;

public enum DesfireKey {

    DES(8, 4, "DESede", Util.TDES),
    TDES(16, 8, "DESede", Util.TKTDES),
    TK3DES(24, 16, "DESede", Util.TKTDES),
    AES(16, 16, 16, "AES", Util.AES);

    public final static byte[] _64_BIT = new byte[8];
    public final static byte[] _128_BIT = new byte[16];
    public final static byte[] _192_BIT = new byte[24];

    static
    {
        Arrays.fill(_192_BIT, (byte) 0x00);
        Arrays.fill(_128_BIT, (byte) 0x00);
        Arrays.fill(_64_BIT, (byte) 0x00);
    }

    private final int keySize;
    private final int randomBlockSize;
    private final int blockSize;
    private final String algorithm;
    private final byte cryptoMethod;

    DesfireKey(int keySize, int randomBlockSize, int blockSize, String algorithm, byte cryptoMethod) {
        this.keySize = keySize;
        this.algorithm = algorithm;
        this.cryptoMethod = cryptoMethod;
        this.blockSize = blockSize;
        this.randomBlockSize = randomBlockSize;
    }

    DesfireKey(int keySize, int randomBlockSize, String algorithm, byte cryptoMethod) {
        this(keySize, randomBlockSize, 8, algorithm, cryptoMethod);
    }

    public int keySize() {
        return keySize;
    }

    public int blockSize() {
        return blockSize;
    }

    public int randomBlockSize() {
        return randomBlockSize;
    }

    public byte cryptoMethod() {
        return cryptoMethod;
    }

    public String algorithm() {
        return algorithm;
    }

    public static DesfireKey parse(byte keyType) {
        switch(keyType) {
            // aes authenticate 0xAA
            case Util.AES : return AES;
            // legacy authenticate 0x1A
            case Util.TDES: return TDES;
            // iso authenticate 0x0A
            case Util.TKTDES : return TK3DES;
        }
        return DES;
    }

    public Key buildDefaultKey() {
        return new SecretKeySpec(defaultKey(), algorithm);
    }

    public Key buildKey(MasterFile masterFile) {
        return buildKey(masterFile.getDefaultKey());
    }

    public Key buildKey(byte[] bytes) {
        return new SecretKeySpec(bytes, algorithm);
    }

    public Key buildSessionKey(byte[] a, byte[] b) {
        switch(this) {
            case AES : return buildAesSessionKey(a, b);
            case TDES: return buildTDesSessionKey(a, b);
            case DES:  return buildDesSessionKey(a, b);
            case TK3DES: return build3K3DesSessionKey(a, b);
        }
        throw new IsoException(DesfireStatusWord.NO_SUCH_KEY.toShort());
    }

    private Key buildDesSessionKey(byte[] a, byte[] b) {
        byte[] result = new byte[keySize];
        for (int i = 0; i < 4; i++) {
            result[i] = a[i];
            result[i+4] = b[i];
        }
        return buildKey(result);
    }

    private Key build3K3DesSessionKey(byte[] a, byte[] b) {
        byte[] result = new byte[keySize];
        for (int i = 0; i < 4; i++) {
            result[i] = a[i];
            result[i+4] = b[i];
        }

        for (int i = 4; i < 8; i++) {
            result[i+4] = a[i+2];
            result[i+8] = b[i+2];
        }

        for (int i = 12; i < 16; i++) {
            result[i+4] = a[i];
            result[i+8] = b[i];
        }

/*        memcpy (buffer, rnda, 4);
        180     memcpy (buffer+4, rndb, 4);
        181     memcpy (buffer+8, rnda+6, 4);
        182     memcpy (buffer+12, rndb+6, 4);
        183     memcpy (buffer+16, rnda+12, 4);
        184     memcpy (buffer+20, rndb+12, 4);
*/
        return buildKey(result);
    }

    private Key buildTDesSessionKey(byte[] a, byte[] b) {
        byte[] result = new byte[keySize];
        for (int i = 0; i < 4; i++) {
            result[i] = a[i];
            result[i+4] = b[i];
        }

        for (int i = 4; i < 8; i++) {
            result[i+4] = a[i];
            result[i+8] = b[i];
        }
        return buildKey(result);
    }

    private Key buildAesSessionKey(byte[] a, byte[] b) {
        byte[] result = new byte[keySize];
        // eerste 4 v byte a en b
        for (int i = 0; i < 4; i++) {
            result[i] = a[i];
        }
        for (int i = 4; i < 8; i++) {
            result[i] = b[i-4];
        }
        // laaste 4 bytes van a en b
        for (int i = 8; i < 12; i++) {
            result[i] = a[i+4];
        }
        for (int i = 12; i < 16; i++) {
            result[i] = b[i];
        }
        return buildKey(result);
    }

    public byte[] defaultKey() {
        switch(this) {
            case DES : return _64_BIT;
            case AES : return _128_BIT;
            case TDES: return _192_BIT;
            case TK3DES: return _192_BIT;
        }
        return null;
    }

}

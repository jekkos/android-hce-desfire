package net.jpeelaer.hce.desfire;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.kevinvalk.hce.framework.IsoException;

import android.util.Log;

//El Directory File equivale a la aplicaci�n. 

public class DirectoryFile extends File {

    private byte[] AID;
    private static final byte MAX_FILES = 32;
    public boolean[] activatedFiles = new boolean[32];
    private boolean[] waitingForTransaction = new boolean[32];
    private File[] arrayFiles = new File[MAX_FILES];
    private Key[] keyList;
    private byte numberFiles = 0;
    private Key masterKey;
    private byte keyType;

    //Key Settings
    private byte changeKeyAccessRights;//que clave es precisa para cambiar una clave (nivel App)
    public boolean configurationChangeable;//true-es posible cambiar estas settings(mkAuth requerida)
    private boolean masterNotNeededForManage;//Para crear/eliminar (1-No hace falta Ath)
    private boolean masterNotNeededForCheck;//Para commandos get (1-No hace falta Ath)
    private boolean masterChangeable;//0-MK inmovil 1-MK cambiable (Es precisa la Master Key correspondiente)
    private byte maxKeyNumber;//Maximo numero de claves que se pueden almacenar (aplicaci�n)
    private boolean ISOFileIDSupported;

    /**
     * Constructor for the Master File
     *
     * @param fid
     */
    protected DirectoryFile(byte fid) {
        super(fid);//llama al constructor de la clase File
        for (byte i = 0; i < activatedFiles.length; i++) {
            activatedFiles[i] = false;
        }
        configurationChangeable = true;
        masterNotNeededForManage = true;
        masterNotNeededForCheck = true;
        masterChangeable = true;
        //La master key puede ser 3DES(16), TKDES(24) o AES(16)
        keyType = Util.TDES;

        SecretKeyFactory desKeyFactory;
        try {
            Key newKey = generateSecretKey(Util.DEFAULT_MASTER_KEY);
            masterKey = newKey;
        } catch (Exception e) {
            Log.e("NFC", e.getMessage(), e);
        }
        maxKeyNumber = -1;

    }

    /**
     * Constructor for the applications
     */
    protected DirectoryFile(byte fid, byte[] keySettings, DirectoryFile parent) {
        super(fid, parent);//llama al constructor de la clase File
        changeKeySettings(keySettings[0]);
        keyType = (byte) (keySettings[1] & 0xF0);
        maxKeyNumber = (byte) (keySettings[1] & (byte) 0x0F);
        ISOFileIDSupported = (keySettings[1] & (byte) 0x10) == (byte) 0x10;

        keyList = new Key[maxKeyNumber];
        byte[] defaultKey = ((MasterFile) getParent()).getDefaultKey();
        // for auth it's des or aes, 8 byte or 16 block size
        keyList[0] = generateSecretKey(defaultKey);//Application Master Key
    }

    public void setAID(byte[] AID) { }

    public byte getNumberFiles() {
        return numberFiles;
    }

    public File getFile(byte fid) {
        if (activatedFiles[fid] == true) {
            return (arrayFiles[fid]);
        }  else {
            IsoException.throwIt((short) Util.FILE_NOT_FOUND);//File not found
            return null;
        }
    }

    /**
     * Checks if the file with the given file number exists
     *
     * @return True if it is activated already
     */
    public boolean isValidFileNumber(byte fileN) {
        return activatedFiles[fileN];
    }

    public void updateFile(File update, byte fileID) {
        arrayFiles[fileID] = update;
    }

    public void addFile(File s) {
        if (activatedFiles[s.getFileID()] == true) {
            IsoException.throwIt(Util.DUPLICATE_ERROR);//Duplicate File
        }
        arrayFiles[s.getFileID()] = s;
        numberFiles++;
        activatedFiles[s.getFileID()] = true;

    }

    public void deleteFile(byte id) {

        activatedFiles[id] = false;
        arrayFiles[id] = null;
        numberFiles--;
    }

    public Key getKey(byte keyNumber) {
        if (keyNumber >= maxKeyNumber) IsoException.throwIt(Util.NO_SUCH_KEY);//No Such Key
        else if (keyList[keyNumber] == null) IsoException.throwIt(Util.NO_SUCH_KEY);//No Such Key
        return (keyList[keyNumber]);
    }

    public Key getMasterKey() {
        return masterKey;
    }

    private Key generateSecretKey(byte[] keyBytes) {
        KeyFactory secretKeyFactory = null;
        Key key = null;
        switch (keyType) {
            //La master key puede ser 3DES(16), TKDES(24) o AES(16)
            case Util.AES: {
                key = new SecretKeySpec(keyBytes, "AES");
                break;
            }
            case Util.TDES:
            case Util.TKTDES: {
                key = new SecretKeySpec(keyBytes, "DESede");
            }
        }
        return key;
    }

    public void changeKey(byte keyNumber, byte[] keyBytes) {
        if (keyNumber >= maxKeyNumber) IsoException.throwIt(Util.NO_SUCH_KEY);//No Such Key
        if (isMasterFile()) { //Si es Master File
            //Segun el keyNumber se decide el tipo de clave que tenemos.
            //FALTA
            Key newKey = generateSecretKey(keyBytes);
            masterKey = newKey;
        } else {//It's not MasterFile
            Key newKey = generateSecretKey(keyBytes);
            keyList[keyNumber] = newKey;
        }
    }

    public byte getMasterKeyType() {
        return keyType;
    }

    public boolean hasChangeAccess(byte keyNAuthenticated, byte keyNToChange) {
        if (keyNToChange >= maxKeyNumber) IsoException.throwIt(Util.NO_SUCH_KEY);//No Such Key
        if (this.getFileID() == (byte) 0x00) {//Si es la PICC Master Key
            if ((keyNAuthenticated == (byte) 0x00) & (masterChangeable == true)) return true;
            else return false;
        }
        if (changeKeyAccessRights == (byte) 0x00) {//Es necesaria mkAuth
            if (keyNAuthenticated == 0) return true;
            else return false;
        }
        if (changeKeyAccessRights == (byte) 0x0F) {//Solo se puede cambiar mk con mkAuth
            if ((keyNToChange == 0) & (keyNAuthenticated == 0) & (masterChangeable == true)) return true;
            else return false;
        }
        if (changeKeyAccessRights == (byte) 0x0E) {//Es precisa la propia clave q se va a cambiar
            if ((keyNToChange == 0x00) & (masterChangeable == false)) return false;
            if (keyNToChange == keyNAuthenticated) return true;
            else return false;
        }
        //Resto de posibilidades(0x01-0x0D):ChangeKeyAccessSettings es la propia clave necesaria
        //para cambiar cualquier clave
        if (keyNToChange == changeKeyAccessRights) {//Para cambiar la changeKey se precisa la MK
            if (keyNAuthenticated == (byte) 0x00) return true;
            else return false;
        }
        if (keyNToChange == (byte) 0x00) {//Para cambiar la MK se precisa la MK
            if (masterChangeable == false) return false;
            if (keyNAuthenticated == (byte) 0x00) return true;
            else return false;
        }
        if (changeKeyAccessRights == keyNAuthenticated) return true;//Si estamos autentificados con la changeKey
        else return false;
    }

    public boolean hasKeySettingsChangeAllowed(byte authenticated) {
        if (configurationChangeable == false) return false;
        if (authenticated == (byte) 0x00) return true;//Hace falta autentificacion con la master Key
        return false;
    }

    public void changeKeySettings(byte newKS) {
        if (getFileID() != (byte) 0x00) {
            changeKeyAccessRights = (byte) (((byte) (newKS >> 4)) & ((byte) 0x0F));
        }
        if ((newKS | (byte) 0xF7) == 0xF7) configurationChangeable = false;
        else configurationChangeable = true;

        if ((newKS | (byte) 0xFB) == 0xFB) masterNotNeededForManage = false;
        else masterNotNeededForManage = true;

        if ((newKS | (byte) 0xFD) == 0xFD) masterNotNeededForCheck = false;
        else masterNotNeededForCheck = true;

        if ((newKS | (byte) 0xFE) == 0xFE) masterChangeable = false;
        else masterChangeable = true;
    }

    public boolean hasGetRights(byte authenticated) {
        if (masterNotNeededForCheck) return true;
        else if (authenticated == (byte) 0x00) return true;
        return false;
    }

    public boolean hasManageRights(byte authenticated) {
        if (masterNotNeededForManage) return true;
        else if (authenticated == (byte) 0x00) return true;
        return false;
    }

    public byte getKeySettings() {
        byte ks = 0;
        if (getFileID() != (byte) 0x00) {
            ks = (byte) (changeKeyAccessRights << 4);
        }
        if (configurationChangeable == true) ks = (byte) (ks | (byte) 0x08);
        if (masterNotNeededForManage == true) ks = (byte) (ks | (byte) 0x04);
        if (masterNotNeededForCheck == true) ks = (byte) (ks | (byte) 0x02);
        if (masterChangeable == true) ks = (byte) (ks | (byte) 0x01);
        return ks;
    }

    public byte getKeyNumber() {
        byte kn = 0;
        if (getFileID() == (byte) 0x00) return (byte) 0x01;
        kn = (byte) (keyType << 6);
        kn = (byte) (kn | maxKeyNumber);
        return kn;
    }

    /**
     * @return True if this DF is the Master File
     */
    public boolean isMasterFile() {
        return false;
    }

    /**
     * Checks if the key exists or not
     */
    public boolean isValidKeyNumber(byte keyNumber) {

        if (keyNumber >= maxKeyNumber) return false;//No Such Key
        else if (keyList[keyNumber] == null) return false;//No Such Key
        return true;
    }

    public void setWaitForTransaction(byte fileNumber) {
        waitingForTransaction[fileNumber] = true;
    }

    public void resetWaitForTransaction(byte fileNumber) {
        waitingForTransaction[fileNumber] = false;
    }

    public boolean getWaitingForTransaction(byte fileNumber) {
        return waitingForTransaction[fileNumber];
    }
}

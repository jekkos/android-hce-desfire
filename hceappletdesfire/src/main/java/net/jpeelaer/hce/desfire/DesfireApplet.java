package net.jpeelaer.hce.desfire;

import org.kevinvalk.hce.framework.Applet;
import org.kevinvalk.hce.framework.Iso7816;
import org.kevinvalk.hce.framework.IsoException;
import org.kevinvalk.hce.framework.apdu.Apdu;
import org.kevinvalk.hce.framework.apdu.CommandApdu;
import org.kevinvalk.hce.framework.apdu.ResponseApdu;
import org.kevinvalk.hce.framework.apdu.SecureApdu;
import org.spongycastle.util.Arrays;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

/**
 * DESfire Card operating system's emulation. This class installs the applet
 * in the card and runs the OS reading Apdu's and calling the required functions
 * depending on the INS field
 *
 * @author WinXp
 */
public class DesfireApplet extends Applet {

    private static final int CLA_PROTECTED_APDU = 0x0c;

    // DESFire AID
    private static final byte[] APPLET_AID = {(byte) 0xD2, 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x00};

    private static final String LOG_TAG = DesfireApplet.class.getSimpleName();

    // similar as AES_encrypt in openssl/aes.h?
    final Cipher AES_CIPHER;
    final Cipher DES_CIPHER;
    final Cipher TDES_CIPHER;

    /**
     * Master file of the card
     */
    protected MasterFile masterFile;
    /**
     * Sets if the messages are sent plain, with MAC or enciphered.
     */
    byte securityLevel;
    /**
     * Security level of the file that is being readed
     */
    byte fileSecurityLevel;
    /**
     * Current session key
     */
    Key sessionKey;
    byte[] randomNumberToAuthenticate;
    /**
     * File selected
     */
    private File selectedFile;
    /**
     * Directory file selected
     */
    private DirectoryFile selectedDF;
    /**
     * Sets wich command has to continue after a CONTINUE command
     */
    private DesFireInstruction commandToContinue;//para comandos que necesitan continuar
    /**
     * Used in R/W operations to keep the number of bytes processed so far
     */
    private short readed;
    /**
     * Pointer to the location where the operaton will continue
     */
    private short offset;
    /**
     * Number of bytes not processed yet
     */
    private short bytesLeft;
    /**
     * Keeps the number of the key that is going to be authenticated during
     * the authenticate operation
     */
    private byte keyNumberToAuthenticate;
    /**
     * Key number that has been authenticated last
     */
    private byte authenticated;
    private byte[] dataBuffer;
    /**
     * Check whether the original authenticate was done using 0x0A (legacy)  higher
     */
    private boolean legacyMode;


    /**
     * private constructor - called by the install method to instantiate a
     * EidCard instance
     * <p/>
     * needs to be protected so that it can be invoked by subclasses
     *
     * @throws NoSuchPaddingException wrong settingg for encryption padding
     * @throws NoSuchAlgorithmException unexistant encryption algorithm
     */
    public DesfireApplet() throws NoSuchPaddingException, NoSuchAlgorithmException {
        masterFile = new MasterFile();
        selectedDF = masterFile;
        commandToContinue = DesFireInstruction.NO_COMMAND_TO_CONTINUE;
        offset = 0;
        bytesLeft = 0;
        keyNumberToAuthenticate = 0;
        authenticated = Util.NO_KEY_AUTHENTICATED;
        securityLevel = Util.PLAIN_COMMUNICATION;
        AES_CIPHER = Cipher.getInstance("AES/CBC/NoPadding");
        DES_CIPHER = Cipher.getInstance("DES/CBC/NoPadding");
        TDES_CIPHER = Cipher.getInstance("DESede/CBC/NoPadding");
    }

    /**
     * PICC and reader device show in an encrypted way that they posses the same key.
     *
     * @throws GeneralSecurityException generic security exception
     * @effect Confirms that both entities are permited to do operations on each
     * other and creates a session key.
     * @note This procedure has two parts. depending on the commandToContinue status.
     * @note ||KeyNumber||
     */
    private ResponseApdu authenticate(CommandApdu apdu, byte[] buffer) throws GeneralSecurityException {
        //Apdu: KeyNo
        if (commandToContinue == DesFireInstruction.NO_COMMAND_TO_CONTINUE) {
            legacyMode = apdu.ins == DesFireInstruction.AUTHENTICATE.toByte();

            if ((byte) (buffer[Iso7816.OFFSET_LC]) != 1) IsoException.throwIt(Util.LENGTH_ERROR);
            // RndB is generated			
            keyNumberToAuthenticate = buffer[Iso7816.OFFSET_CDATA];
            if (!selectedDF.isValidKeyNumber(keyNumberToAuthenticate)) IsoException.throwIt(Util.NO_SUCH_KEY);
            DesfireKey keyType = selectedDF.getKeyType();
            int randomBlockSize = keyType.randomBlockSize();
            randomNumberToAuthenticate = new byte[randomBlockSize];
            SecureRandom sr = new SecureRandom();
            sr.nextBytes(randomNumberToAuthenticate);

            //Ek(RndB) is created
            byte[] ekRndB = new byte[randomBlockSize];
            Cipher cipher = cipherForSelectedFile(Cipher.ENCRYPT_MODE);
            ekRndB = cipher.doFinal(randomNumberToAuthenticate);
            commandToContinue = DesFireInstruction.AUTHENTICATE;

            //Ek(RndB) is sent
            return sendResponse(apdu, buffer, ekRndB, (byte) 0xAF);
        } else {
            DesfireKey keyType = selectedDF.getKeyType();
            int randomBlockSize = keyType.randomBlockSize();
            //SECCOND MESSAGE
            if ((byte) (buffer[Iso7816.OFFSET_LC]) != randomBlockSize * 2) IsoException.throwIt(Util.LENGTH_ERROR);
            commandToContinue = DesFireInstruction.NO_COMMAND_TO_CONTINUE;
            byte[] encryptedRndA = new byte[randomBlockSize];
            byte[] encryptedRndArndB = new byte[randomBlockSize * 2];
            byte[] rndA = new byte[randomBlockSize];
            byte[] rndB = new byte[randomBlockSize];
            byte[] rndArndB = new byte[randomBlockSize * 2];
            //Ek(RndA-RndB') is recieved. RndB' is a 8 bits left-shift of RndB
            encryptedRndArndB = Util.subByteArray(buffer, (byte) Iso7816.OFFSET_CDATA, (byte) (Iso7816.OFFSET_CDATA + randomBlockSize * 2 - 1));

            // encrypt in legacy mode (ins = 0x0A), encrypt otherwise
            Cipher cipher = cipherForSelectedFile(legacyMode ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE);
            rndArndB = cipher.doFinal(encryptedRndArndB);
            rndA = Util.subByteArray(rndArndB, (byte) 0, (byte) (randomBlockSize - 1));
            rndB = Util.subByteArray(rndArndB, (byte) (randomBlockSize) , (byte) (randomBlockSize  * 2 - 1));
            rndB = Util.rotateRight(rndB);//Because rndB was left shifted
            //RndB is checked
            if (!Arrays.areEqual(rndB, randomNumberToAuthenticate)) {
                //Authentication Error
                authenticated = Util.NO_KEY_AUTHENTICATED;
                IsoException.throwIt(Util.AUTHENTICATION_ERROR);
            } else {
                //The key is authenticated
                authenticated = keyNumberToAuthenticate;
            }
            //Session key is created
            Key sessionKey = keyType.buildSessionKey(rndA, rndB);
            // then encrypt session key ??
            //Ek(RndA')is sent back
            rndA = Util.rotateLeft(rndA);

            cipher = cipherForSelectedFile(Cipher.ENCRYPT_MODE);
            encryptedRndA = cipher.doFinal(rndA);
            return sendResponseAndChangeStatus(apdu, buffer, encryptedRndA, sessionKey);
        }
    }

    private Cipher cipherForSelectedFile(int opMode) throws InvalidAlgorithmParameterException, InvalidKeyException {
        DesfireKey keyType = selectedDF.getKeyType();
        byte[] ivBytes = new byte[keyType.blockSize()];
        java.util.Arrays.fill(ivBytes, (byte) 0);
        return cipherForSelectedFile(opMode, ivBytes);
    }

    private Cipher cipherForSelectedFile(int opMode,  byte[] ivBytes) throws InvalidKeyException, InvalidAlgorithmParameterException {
        Key key = selectedDF.getParent().getMasterKey();
        if (!selectedDF.isMasterFile()) {
            key = selectedDF.getKey(keyNumberToAuthenticate);
        }
        Cipher cipher = deriveCipherFromKey(key);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        cipher.init(opMode, key, ivParameterSpec);
        return cipher;
    }

    private int deriveKeyLengthForFile(DirectoryFile directoryFile, byte keyNumber) {
        Key key = directoryFile.getKey(keyNumber);
        return key.getEncoded().length;
    }

    public Cipher deriveCipherFromKey(Key key) {
        if (key.getAlgorithm().contains("AES")) {
            return AES_CIPHER;
        } else if (key.getAlgorithm().contains("DESede")) {
            return TDES_CIPHER;
        }
        return DES_CIPHER;
    }

    /**
     * Changes the master key settings on PICC and application level
     *
     * @note ||Ciphered Key Settings||
     * 8/16
     */
    private void changeKeySettings(Apdu Apdu, byte[] buffer) {

        //Hay que descifrar el campo de datos igual que con changeKey (no s� como)
        //FALTA
        if (((byte) (buffer[Iso7816.OFFSET_LC]) != 8) && ((byte) (buffer[Iso7816.OFFSET_LC]) != 16))
            IsoException.throwIt(Util.LENGTH_ERROR);
        byte keySettings = buffer[Iso7816.OFFSET_CDATA];
        if (!selectedDF.hasKeySettingsChangeAllowed(authenticated)) IsoException.throwIt(Util.PERMISSION_DENIED);
        if (selectedDF.getFileID() == (byte) 0x00) {
            masterFile.changeKeySettings(keySettings);
            selectedDF = masterFile;
        } else {
            selectedDF.changeKeySettings(keySettings);
            masterFile.arrayDF[selectedDF.getFileID()] = selectedDF;//Actualizamos
        }
        IsoException.throwIt(Util.OPERATION_OK);
    }

    /**
     * Changes any key stored on the PICC
     *
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws ShortBufferException
     * @throws InvalidKeyException
     * @note ||Key number | Ciphered Key Data||
     * 1			24-40
     */
    private void changeKey(Apdu Apdu, byte[] buffer) throws IllegalBlockSizeException, BadPaddingException, ShortBufferException, InvalidKeyException {


        if (((byte) (buffer[Iso7816.OFFSET_LC]) < 25) && ((byte) (buffer[Iso7816.OFFSET_LC]) > 41))
            IsoException.throwIt(Util.LENGTH_ERROR);
        byte keyN = buffer[Iso7816.OFFSET_CDATA];
        if ((selectedDF.isMasterFile() == true) && (keyN != 0)) IsoException.throwIt(Util.PARAMETER_ERROR);
        if ((selectedDF.isMasterFile() == false) && (keyN >= 28)) IsoException.throwIt(Util.PARAMETER_ERROR);
        if (selectedDF.hasChangeAccess(authenticated, keyN) == false) IsoException.throwIt(Util.PERMISSION_DENIED);

        byte[] encipheredKeyData = new byte[(byte) (buffer[Iso7816.OFFSET_LC] - 1)];
        for (byte i = 0; i < encipheredKeyData.length; i++) {
            encipheredKeyData[i] = buffer[(byte) (Iso7816.OFFSET_CDATA + i + 1)];
        }

        byte[] newKeyDecrypted = decryptEncipheredKeyData(encipheredKeyData, keyN);


        if (selectedDF.isMasterFile()) {
            if (authenticated == keyN) authenticated = Util.NO_KEY_AUTHENTICATED;
            masterFile.changeKey(keyN, newKeyDecrypted);
            selectedDF = masterFile;
        } else {
            if (authenticated == keyN) authenticated = Util.NO_KEY_AUTHENTICATED;
            selectedDF.changeKey(keyN, newKeyDecrypted);
            masterFile.arrayDF[selectedDF.getFileID()] = selectedDF;
        }
        IsoException.throwIt(Util.OPERATION_OK);
    }

    /**
     * Creates a new oplication on the PICC
     *
     * @note || AID | KeySettings1 | KeySettings2 | ISOFileID* | DF_FILE* ||
     * 3		   1			  1             2		1-16
     */
    private void createApplication(Apdu Apdu, byte[] buffer) {


        if (((byte) (buffer[Iso7816.OFFSET_LC]) < 5) && ((byte) (buffer[Iso7816.OFFSET_LC]) > 23))
            IsoException.throwIt(Util.LENGTH_ERROR);

        if (masterFile.hasManageRights(authenticated) == false) IsoException.throwIt(Util.PERMISSION_DENIED);
        if (masterFile.getIndexDF().hasWriteAccess((byte) 0) == false)
            IsoException.throwIt(Util.PERMISSION_DENIED);//CREO QUE SOBRAins
        byte[] AID = {buffer[Iso7816.OFFSET_CDATA], buffer[Iso7816.OFFSET_CDATA + 1], buffer[Iso7816.OFFSET_CDATA + 2]};
        byte[] keySettings = {buffer[Iso7816.OFFSET_CDATA + 3], buffer[Iso7816.OFFSET_CDATA + 4]};

        //A�adir el ISOFileID y el DF-Name  para compatibiliadad con 7816
        //FALTA
        masterFile.addDF(AID, keySettings);
        IsoException.throwIt(Util.OPERATION_OK);
    }

    /**
     * Permanently desactivates applications on the PICC
     *
     * @effect If the application that is going to be removed is the currently selected
     * the PICC level is set
     * @note || AID ||
     * 3
     */
    private void deleteApplication(Apdu Apdu, byte[] buffer) {


        if (((byte) (buffer[Iso7816.OFFSET_LC]) != 3)) IsoException.throwIt(Util.LENGTH_ERROR);
        byte[] AID = {buffer[Iso7816.OFFSET_CDATA], buffer[Iso7816.OFFSET_CDATA + 1], buffer[Iso7816.OFFSET_CDATA + 2]};
        if (masterFile.searchAID(AID) == -1) IsoException.throwIt(Util.APPLICATION_NOT_FOUND);
        if (masterFile.hasManageRights(authenticated) == false) IsoException.throwIt(Util.PERMISSION_DENIED);

        //If the application that is going to be removed is the currently selected the PICC level is set
        if (selectedDF.getFileID() == masterFile.searchAID(AID)) selectedDF = masterFile;
        masterFile.deleteDF(AID);
        if (selectedDF.isMasterFile()) selectedDF = masterFile;
        IsoException.throwIt(Util.OPERATION_OK);
    }

    /**
     * Returns the application identifiers of all applications on a PICC
     *
     * @note If the number of applications is higher than 19 the command will
     * work in two parts.
     */
    public ResponseApdu getApplicationIDs(Apdu Apdu, byte[] buffer) {
        if ((byte) buffer[Iso7816.OFFSET_LC] != 0) IsoException.throwIt(Util.LENGTH_ERROR);
        byte[] response;
        byte numApp = (byte) (masterFile.numApp - 1);//-1 because the IndexFile won't be included
        if (commandToContinue == DesFireInstruction.NO_COMMAND_TO_CONTINUE) {
            if (masterFile.hasGetRights(authenticated) == false) IsoException.throwIt(Util.PERMISSION_DENIED);
            if (numApp == 0) IsoException.throwIt(Util.OPERATION_OK);
//			if(numApp==1){
//				return sendResponse(Apdu,buffer,masterFile.getAID((byte) 1));
//				return;
//			}
            if (numApp > 19) {
                response = new byte[(byte) 19 * 3];
                commandToContinue = DesFireInstruction.GET_APPLICATION_IDS;
            } else response = new byte[(byte) (numApp * 3)];
            for (byte i = 0; i < response.length; i = (byte) (i + 3)) {
                byte[] AID = masterFile.getAID((byte) (i / 3 + 1));//+1 because the IndexFile won't be included
                response[i] = AID[0];
                response[(byte) (i + 1)] = AID[1];
                response[(byte) (i + 2)] = AID[2];
            }
//			IsoException.throwIt(response[3]);
            //Habr�a que devolver STATUS WORD AF si hay m�s AID q enviar
            return sendResponse(Apdu, buffer, response);
        } else {//Second part
            commandToContinue = DesFireInstruction.NO_COMMAND_TO_CONTINUE;
            response = new byte[(byte) ((numApp - 19) * 3)];
            for (byte i = 0; i < response.length; i = (byte) (i + 3)) {
                byte[] AID = masterFile.getAID((byte) (i / 3 + 21));//21 beacuase the IndexFile won't be included
                response[i] = AID[0];
                response[(byte) (i + 1)] = AID[1];
                response[(byte) (i + 2)] = AID[2];
            }
            return sendResponse(Apdu, buffer, response);
        }


    }

    /**
     * Get information on the PICC and application master key settings.
     * In addition it returns the maximum number of keys which are configured for the selected application.
     */
    private ResponseApdu getKeySettings(Apdu Apdu, byte[] buffer) {

        if ((byte) buffer[Iso7816.OFFSET_LC] != 0) IsoException.throwIt(Util.LENGTH_ERROR);
        if (!selectedDF.hasGetRights(authenticated)) IsoException.throwIt(Util.PERMISSION_DENIED);
        byte ks = selectedDF.getKeySettings();
        byte kn = selectedDF.getKeyNumber();
        byte[] response = new byte[2];
        response[0] = ks;
        response[1] = kn;
        return sendResponse(Apdu, buffer, response);
    }

    /**
     * Select one specific application for further access
     *
     * @note || AID ||
     */
    private void selectApplication(Apdu Apdu, byte[] buffer) {

        if ((byte) buffer[Iso7816.OFFSET_LC] != 3) IsoException.throwIt(Util.LENGTH_ERROR);
        //AID
        byte[] AID = {buffer[Iso7816.OFFSET_CDATA], buffer[Iso7816.OFFSET_CDATA + 1], buffer[Iso7816.OFFSET_CDATA + 2]};
        if (Arrays.areEqual(AID, Util.masterFileAID)) {
            selectedDF = masterFile;
        } else {
            byte i = masterFile.searchAID(AID);
            if (i != (byte) -1) selectedDF = masterFile.arrayDF[masterFile.searchAID(AID)];
            else IsoException.throwIt(Util.APPLICATION_NOT_FOUND);
        }
        authenticated = Util.NO_KEY_AUTHENTICATED;
        securityLevel = Util.PLAIN_COMMUNICATION;
        IsoException.throwIt(Util.OPERATION_OK);
    }

    /**
     * Releases the PICC user memory
     *
     * @note Requires a preceding authentication with the PICC Master Key
     * @effect All application are deleted and all files within them.
     * The PICC Master Keyand the PICC Master Key settings keep their currently set values
     */
    private void formatPICC(Apdu Apdu, byte[] buffer) {
        if (!selectedDF.isMasterFile()) IsoException.throwIt(Util.PERMISSION_DENIED);

        if ((byte) buffer[Iso7816.OFFSET_LC] != 0) IsoException.throwIt(Util.LENGTH_ERROR);
        if (!masterFile.isFormatEnabled()) IsoException.throwIt(Util.PERMISSION_DENIED);
        if (authenticated != 0) IsoException.throwIt(Util.PERMISSION_DENIED);
        masterFile.format();
        IsoException.throwIt(Util.OPERATION_OK);

    }

    /**
     * Configures the card and pre personalizes the card with a key, defines if the UID or the
     * random ID is sent back during communication setup and configures the ATS string
     *
     * Master key authentication on card level needs to be performed elsewise
     *                throws PERMISSION_DENIED
     * @note || Option | ciphered( data || CRC )||
     */
    private void setConfiguration(Apdu Apdu, byte[] buffer) {
        if ((selectedDF.isMasterFile() != true) || (this.authenticated != 0))
            IsoException.throwIt(Util.PERMISSION_DENIED);

        if (((byte) buffer[Iso7816.OFFSET_LC] < 9) && ((byte) buffer[Iso7816.OFFSET_LC] > 33))
            IsoException.throwIt(Util.LENGTH_ERROR);

        //Gets the data
        byte encData[] = new byte[(byte) (buffer[Iso7816.OFFSET_LC] - 1)];
        for (byte i = 0; i < encData.length; i++) {
            encData[i] = buffer[(byte) (i + Iso7816.OFFSET_CDATA + 1)];
        }

        byte[] data = decryptBytes(encData, sessionKey);
        //Checks the option
        switch (buffer[Iso7816.OFFSET_CDATA]) {
            case (byte) 0x00: //Configuration byte
                masterFile.setConfiguration(data[0]);
                break;
            case (byte) 0x01://Default key version and default key
                byte[] keyBytes = new byte[(byte) (data.length - 1)];
                //PARA LOS DISTINTOS TIPOS DE CLAVES PUEDEN COGERSE 8-16-24 BYTES DESDE LA IZQUIERDA
                //FALTA
                for (byte i = 0; i < 8; i++) {//When the key is 3DES
                    keyBytes[i] = data[i];
                }
                masterFile.setDefaultKey(keyBytes);
                break;
            case (byte) 0x02://Data is the user defined ATS
                //FALTA
                break;
            default:
                IsoException.throwIt(Util.PARAMETER_ERROR);
        }
    }

    /**
     * Returns the File Identifiers of all active files within the currently selected application
     */
    private ResponseApdu getFileIDs(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if ((byte) buffer[Iso7816.OFFSET_LC] != 0) IsoException.throwIt(Util.LENGTH_ERROR);
        if (selectedDF.hasGetRights(authenticated)) IsoException.throwIt(Util.PERMISSION_DENIED);
        byte[] IDs = new byte[selectedDF.getNumberFiles() + 1];
        byte mark = 0;
        for (byte i = 0; i < (byte) (IDs.length - 1); i++) {
            for (byte j = mark; j < 32; j++) {
                if (selectedDF.activatedFiles[j] == true) {
                    selectedFile = selectedDF.getFile(j);
                    selectedFile.getFileID();
                    IDs[i] = selectedFile.getFileID();
                    mark = (byte) (j + 1);
                    break;
                }
            }
        }
        IDs[(byte) IDs.length - 1] = (byte) 0x00;
        return sendResponse(Apdu, buffer, IDs);
    }

    /**
     * Creates files for the storage of plain unformatted user data within
     * an existing application on the PICC
     *
     * Throws PERMISION_DENIED if card level is selected or the application's configuration doesn't allow
     *               manage for the current authentication state.
     * @note The MSB in the 3 bytes values is not readed.
     * @note || File Number | Iso7816 FileID* | CommunicationSettings | AccessRights | FileSize(3) ||
     * 1				2                     1                  2           3
     */
    private void createStdDataFile(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if (((byte) buffer[Iso7816.OFFSET_LC] != 7) && ((byte) buffer[Iso7816.OFFSET_LC] != 9))
            IsoException.throwIt(Util.LENGTH_ERROR);
        if (selectedDF.hasManageRights(authenticated) == false) IsoException.throwIt(Util.PERMISSION_DENIED);

        byte fileID = (byte) buffer[Iso7816.OFFSET_CDATA];
        if (selectedDF.isValidFileNumber(fileID) == true) IsoException.throwIt(Util.DUPLICATE_ERROR);

        byte communicationSettings;
        byte[] accessPermissions;
        byte[] size;
        if (buffer[Iso7816.OFFSET_LC] == 9) {
            communicationSettings = (byte) buffer[Iso7816.OFFSET_CDATA + 3];
            accessPermissions = new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 5], (byte) buffer[Iso7816.OFFSET_CDATA + 4]};
            size = new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 7], (byte) buffer[Iso7816.OFFSET_CDATA + 6]};
        } else {
            communicationSettings = (byte) buffer[Iso7816.OFFSET_CDATA + 1];
            accessPermissions = new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 3], (byte) buffer[Iso7816.OFFSET_CDATA + 2]};
            size = new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 5], (byte) buffer[Iso7816.OFFSET_CDATA + 4]};
        }


        short sizeS = Util.byteArrayToShort(size);
        //if(sizeS>(short)JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT))IsoException.throwIt(Util.OUT_OF_EEPROM_ERROR);
        selectedFile = new StandartFile(fileID, masterFile.arrayDF[selectedDF.getFileID()], communicationSettings, accessPermissions, sizeS);
        selectedDF = masterFile.arrayDF[selectedDF.getFileID()];
        IsoException.throwIt(Util.OPERATION_OK);
    }

    /**
     * Creates files for the storage of plain unformatted user data within
     * an existing application on the PICC, additionally supporting the feature
     * of an integrated backup mechanism
     *
     * Throws PERMISION_DENIED if card level is selected or the application's configuration doesn't allow
     *               manage for the current authentication state.
     * @note The MSB in the 3 bytes values is not readed.
     * @note || File Number | Iso7816 FileID* | CommunicationSettings | AccessRights | FileSize(3) ||
     * 1				2                     1                  2           3
     */
    private void createBackupDataFile(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if (((byte) buffer[Iso7816.OFFSET_LC] != 7) && ((byte) buffer[Iso7816.OFFSET_LC] != 9))
            IsoException.throwIt(Util.LENGTH_ERROR);
        if (selectedDF.hasManageRights(authenticated) == false) IsoException.throwIt(Util.PERMISSION_DENIED);

        byte fileID = (byte) buffer[Iso7816.OFFSET_CDATA];
        if (selectedDF.isValidFileNumber(fileID) == true) IsoException.throwIt(Util.DUPLICATE_ERROR);

        byte communicationSettings;
        byte[] accessPermissions;
        byte[] size;
        if (buffer[Iso7816.OFFSET_LC] == 9) {
            communicationSettings = (byte) buffer[Iso7816.OFFSET_CDATA + 3];
            accessPermissions = new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 5], (byte) buffer[Iso7816.OFFSET_CDATA + 4]};
            size = new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 7], (byte) buffer[Iso7816.OFFSET_CDATA + 6]};
        } else {
            communicationSettings = (byte) buffer[Iso7816.OFFSET_CDATA + 1];
            accessPermissions = new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 3], (byte) buffer[Iso7816.OFFSET_CDATA + 2]};
            size = new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 5], (byte) buffer[Iso7816.OFFSET_CDATA + 4]};
        }


        short sizeS = Util.byteArrayToShort(size);
        //if(sizeS>(short)JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT))IsoException.throwIt(Util.OUT_OF_EEPROM_ERROR);
        selectedFile = new BackupFile(fileID, masterFile.arrayDF[selectedDF.getFileID()], communicationSettings, accessPermissions, sizeS);
        selectedDF = masterFile.arrayDF[selectedDF.getFileID()];
        IsoException.throwIt(Util.OPERATION_OK);
    }

    /**
     * Creates files for the storage and manipulation of 32bit signed
     * integer values within an existing application on the PICC
     *
     * @note || FileN | CommunicationSetting | AccessRights | LowerLimit(4) | UpperLimit(4) | Value(4) | LimitedCreditEnabled ||
     * 1                1                 2             4               4             4                  1
     */
    private void createValueFile(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if ((byte) buffer[Iso7816.OFFSET_LC] != 17) IsoException.throwIt(Util.LENGTH_ERROR);
        byte fileID = (byte) buffer[Iso7816.OFFSET_CDATA];
        if (selectedDF.isValidFileNumber(fileID) == true) IsoException.throwIt(Util.DUPLICATE_ERROR);
        byte communicationSettings = (byte) buffer[Iso7816.OFFSET_CDATA + 1];
        byte[] accessPermissions = {(byte) buffer[Iso7816.OFFSET_CDATA + 3], (byte) buffer[Iso7816.OFFSET_CDATA + 2]};
        Value lowerLimit = new Value(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 7], (byte) buffer[Iso7816.OFFSET_CDATA + 6], (byte) buffer[Iso7816.OFFSET_CDATA + 5], (byte) buffer[Iso7816.OFFSET_CDATA + 4]});
        Value upperLimit = new Value(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 11], (byte) buffer[Iso7816.OFFSET_CDATA + 10], (byte) buffer[Iso7816.OFFSET_CDATA + 9], (byte) buffer[Iso7816.OFFSET_CDATA + 8]});
        Value value = new Value(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 15], (byte) buffer[Iso7816.OFFSET_CDATA + 14], (byte) buffer[Iso7816.OFFSET_CDATA + 13], (byte) buffer[Iso7816.OFFSET_CDATA + 12]});
        if (upperLimit.compareTo(lowerLimit) != 1) IsoException.throwIt(Util.BOUNDARY_ERROR);
        if (upperLimit.compareTo(value) != 1) IsoException.throwIt(Util.BOUNDARY_ERROR);
        if (value.compareTo(lowerLimit) != 1) IsoException.throwIt(Util.BOUNDARY_ERROR);
        byte limitedCreditEnabled = (byte) buffer[Iso7816.OFFSET_CDATA + 16];
        //if((short)(30)>(short)JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT))IsoException.throwIt(Util.OUT_OF_EEPROM_ERROR);
        if (selectedDF.hasManageRights(authenticated) == false) IsoException.throwIt(Util.PERMISSION_DENIED);
        selectedFile = new ValueRecord(fileID, masterFile.arrayDF[selectedDF.getFileID()], communicationSettings, accessPermissions, lowerLimit, upperLimit, value, limitedCreditEnabled);
        selectedDF = masterFile.arrayDF[selectedDF.getFileID()];
        IsoException.throwIt(Util.OPERATION_OK);
    }

    /**
     * Creates files for multiple storage of structural similar data within
     * an existing application on the PICC.
     *
     * @note Once the file is filled completely with data records further
     * writing to the file is not possible unless it is cleared.
     * @note || File Number | Iso7816 FileID* | CommunicationSettings | AccessRights | RecordSize | MaxNumRecords ||
     * 1                2			           1                 2              3            3
     * @note The MSB in the 3 bits values is not readed.
     */
    private void createLinearRecordFile(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if (((byte) buffer[Iso7816.OFFSET_LC] != 10) && ((byte) buffer[Iso7816.OFFSET_LC] != 12))
            IsoException.throwIt(Util.LENGTH_ERROR);

        byte fileID = (byte) buffer[Iso7816.OFFSET_CDATA];
        if (selectedDF.isValidFileNumber(fileID) == true) IsoException.throwIt(Util.DUPLICATE_ERROR);
        byte communicationSettings = 0;
        byte[] accessPermissions = new byte[2];
        short recordSize = 0;
        short maxRecordNum = 0;
        if (buffer[Iso7816.OFFSET_LC] == 10) {
            communicationSettings = (byte) buffer[Iso7816.OFFSET_CDATA + 1];
            accessPermissions = new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 3], (byte) buffer[Iso7816.OFFSET_CDATA + 2]};
            recordSize = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 5], (byte) buffer[Iso7816.OFFSET_CDATA + 4]});
            maxRecordNum = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 8], (byte) buffer[Iso7816.OFFSET_CDATA + 7]});
        } else if (buffer[Iso7816.OFFSET_LC] == 12) {
            communicationSettings = (byte) buffer[Iso7816.OFFSET_CDATA + 3];
            accessPermissions = new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 5], (byte) buffer[Iso7816.OFFSET_CDATA + 4]};
            recordSize = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 7], (byte) buffer[Iso7816.OFFSET_CDATA + 6]});
            maxRecordNum = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 10], (byte) buffer[Iso7816.OFFSET_CDATA + 9]});
        }

        //if((short)(recordSize*maxRecordNum)>(short)JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT))IsoException.throwIt(Util.OUT_OF_EEPROM_ERROR);
        if (selectedDF.hasManageRights(authenticated) == false) IsoException.throwIt(Util.PERMISSION_DENIED);
        selectedFile = new LinearRecord(fileID, masterFile.arrayDF[selectedDF.getFileID()], communicationSettings, accessPermissions, recordSize, maxRecordNum);
        selectedDF = masterFile.arrayDF[selectedDF.getFileID()];
        IsoException.throwIt(Util.OPERATION_OK);
    }

    /**
     * Creates files for multiple storage of structural similar data within
     * an existing application on the PICC.
     *
     * @note Once the file is filled completely with data records, the oldest record
     * is overwritten with the latest written one.
     * @note || File Number | Iso7816 FileID | CommunicationSettings | AccessRights | RecordSize(3) | MaxNumRecords(3) ||
     * @note The MSB in the 3 bits values is not readed.
     */
    private void createCyclicRecordFile(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if (((byte) buffer[Iso7816.OFFSET_LC] != 10) && ((byte) buffer[Iso7816.OFFSET_LC] != 12))
            IsoException.throwIt(Util.LENGTH_ERROR);
        byte fileID = (byte) buffer[Iso7816.OFFSET_CDATA];
        if (selectedDF.isValidFileNumber(fileID) == true) IsoException.throwIt(Util.DUPLICATE_ERROR);
        byte communicationSettings = 0;
        byte[] accessPermissions = new byte[2];
        short recordSize = 0;
        short maxRecordNum = 0;
        if (buffer[Iso7816.OFFSET_LC] == 10) {
            communicationSettings = (byte) buffer[Iso7816.OFFSET_CDATA + 1];
            accessPermissions = new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 3], (byte) buffer[Iso7816.OFFSET_CDATA + 2]};
            recordSize = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 5], (byte) buffer[Iso7816.OFFSET_CDATA + 4]});
            maxRecordNum = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 8], (byte) buffer[Iso7816.OFFSET_CDATA + 7]});
        } else if (buffer[Iso7816.OFFSET_LC] == 12) {
            communicationSettings = (byte) buffer[Iso7816.OFFSET_CDATA + 3];
            accessPermissions = new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 5], (byte) buffer[Iso7816.OFFSET_CDATA + 4]};
            recordSize = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 7], (byte) buffer[Iso7816.OFFSET_CDATA + 6]});
            maxRecordNum = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 10], (byte) buffer[Iso7816.OFFSET_CDATA + 9]});
        }
        //if((short)(recordSize*maxRecordNum)>(short)JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT))IsoException.throwIt(Util.OUT_OF_EEPROM_ERROR);
        if (selectedDF.hasManageRights(authenticated) == false) IsoException.throwIt(Util.PERMISSION_DENIED);
        selectedFile = new CyclicRecord(fileID, masterFile.arrayDF[selectedDF.getFileID()], communicationSettings, accessPermissions, recordSize, maxRecordNum);
        selectedDF = masterFile.arrayDF[selectedDF.getFileID()];
        IsoException.throwIt(Util.OPERATION_OK);
    }

    /**
     * Permanently desactivates a file within the file directory of the
     * currently selected application
     *
     * @note || FileNumber ||
     * 1
     */
    private void deleteFile(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if ((byte) buffer[Iso7816.OFFSET_LC] != 1) IsoException.throwIt(Util.LENGTH_ERROR);
        byte fileID = (byte) buffer[Iso7816.OFFSET_CDATA];
        if (selectedDF.isValidFileNumber(fileID) == false) IsoException.throwIt(Util.FILE_NOT_FOUND);
        if (selectedDF.hasManageRights(authenticated) == false) IsoException.throwIt(Util.PERMISSION_DENIED);
        selectedDF.deleteFile(fileID);
        masterFile.arrayDF[selectedDF.getFileID()] = selectedDF;
        IsoException.throwIt(Util.OPERATION_OK);
    }

//	/**
//	 * 	Reads data frin Standard Data Files or Backup Data Files
//	 * 
//	 * 	@note	The MSB in the 3 bits values is not readed
//	 * 	@note	When data is sent, if the length of the data doesn't fit in one
//	 * 			message (59 bytes) the data field is splitted. If more thata will
//	 * 			be sent the PICC informs with the SW: 0xAF
//	 * @note	|| FileNumber | Offset | Length ||
//	 *                 1           3        3 	
//	 */
//	private void readData(Apdu Apdu, byte[] buffer){
//		if(selectedDF.isMasterFile()==true)IsoException.throwIt(Util.PERMISSION_DENIED);
//		
//		byte[] out;
//		if(((byte)buffer[Iso7816.OFFSET_INS]==Util.READ_DATA)&&((byte)buffer[Iso7816.OFFSET_LC]!=7))IsoException.throwIt(Util.LENGTH_ERROR);
//		if(((byte)buffer[Iso7816.OFFSET_INS]==Util.CONTINUE)&&((byte)buffer[Iso7816.OFFSET_LC]!=0))IsoException.throwIt(Util.LENGTH_ERROR);
//		if(commandToContinue==Util.NO_COMMAND_TO_CONTINUE){
//			byte fileID=buffer[Iso7816.OFFSET_CDATA];
//			if(selectedDF.isValidFileNumber(fileID)==false) IsoException.throwIt(Util.FILE_NOT_FOUND);
//			selectedFile=(StandartFile) selectedDF.getFile(fileID);
//			if(((StandartFile)selectedFile).hasReadAccess(authenticated)==false){
//				IsoException.throwIt(Util.PERMISSION_DENIED);
//			}
//			offset=Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA+2],(byte) buffer[Iso7816.OFFSET_CDATA+1]});		
//			bytesLeft=Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA+5],(byte) buffer[Iso7816.OFFSET_CDATA+4]});
//			if(bytesLeft==0)bytesLeft=selectedFile.getSize();
//		}
//		if(bytesLeft>=59){
//			out=new byte[59];
//			out=((StandartFile)selectedFile).readArray(offset,(byte)59,(byte)0);
//			bytesLeft=(short)(bytesLeft-59);
//			offset=(short)(offset+59);
//			commandToContinue=Util.READ_DATA;
//			sendResponse(Apdu,buffer,out,Util.CONTINUE);
//		}else{	
//			out=new byte[bytesLeft];
//			out=((StandartFile)selectedFile).readArray(offset,(short)bytesLeft,(byte)0);
//			bytesLeft=0;
//			offset=0;
//			commandToContinue=Util.NO_COMMAND_TO_CONTINUE;
//			sendResponse(Apdu,buffer,out,Util.OPERATION_OK,selectedFile.getCommunicationSettings());
//		}
//	}

    /**
     * Reads data frin Standard Data Files or Backup Data Files
     *
     * @note The MSB in the 3 bits values is not readed
     * @note This method just send the first (or only) message, if the readed data doesn't fit in one Apdu
     * the system will call the sendBlockData
     * @note || FileNumber | Offset | Length ||
     * 1           3        3
     */
    private ResponseApdu readData(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if (((byte) buffer[Iso7816.OFFSET_INS] == DesFireInstruction.READ_DATA.toByte()) && ((byte) buffer[Iso7816.OFFSET_LC] != 7))
            IsoException.throwIt(Util.LENGTH_ERROR);
        //Get parameters
        byte fileID = buffer[Iso7816.OFFSET_CDATA];
        if (selectedDF.isValidFileNumber(fileID) == false) IsoException.throwIt(Util.FILE_NOT_FOUND);
        selectedFile = (StandartFile) selectedDF.getFile(fileID);
        if (((StandartFile) selectedFile).hasReadAccess(authenticated) == false)
            IsoException.throwIt(Util.PERMISSION_DENIED);
        offset = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 2], (byte) buffer[Iso7816.OFFSET_CDATA + 1]});
        bytesLeft = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 5], (byte) buffer[Iso7816.OFFSET_CDATA + 4]});
        if (bytesLeft == 0) bytesLeft = selectedFile.getSize();

        //Read data
        dataBuffer = ((StandartFile) selectedFile).readArray(offset, bytesLeft, (short) 0);
        commandToContinue = DesFireInstruction.READ_DATA;

        return sendBlockResponse(Apdu, buffer, dataBuffer, (short) 0, selectedFile.getCommunicationSettings());

    }

//	/**
//	 *	Writes data to Standard Data Files or Backup Data Files
//	 *
//	 *	@note	The MSB in the 3 bits values is not readed
//	 *	@note	If the data doesn't fit in one message (52 bytes)
//	 *			the sender will split it in more messages (59 bytes)
//	 *		 	so this command may have more than one execution in row.
//	 *	@note	|| File No | Offset | Lenght | Data ||
//	 *                 1        3        3     1-52
//	 */
//	private void writeData(Apdu Apdu, byte[] buffer){
//		if(selectedDF.isMasterFile()==true)IsoException.throwIt(Util.PERMISSION_DENIED);
//		
//		if(((byte)buffer[Iso7816.OFFSET_INS]==Util.WRITE_DATA)&&((byte)buffer[Iso7816.OFFSET_LC]<8))IsoException.throwIt(Util.LENGTH_ERROR);
//		if(((byte)buffer[Iso7816.OFFSET_INS]==Util.CONTINUE)&&((byte)buffer[Iso7816.OFFSET_LC]!=0))IsoException.throwIt(Util.LENGTH_ERROR);
//		byte readed;
//		byte[] data;
//		if(commandToContinue==Util.NO_COMMAND_TO_CONTINUE){
//			byte fileID=buffer[Iso7816.OFFSET_CDATA];
//			if(selectedDF.isValidFileNumber(fileID)==false) IsoException.throwIt(Util.FILE_NOT_FOUND);
//			selectedFile=(StandartFile) selectedDF.getFile(fileID);
//			if(((StandartFile)selectedFile).hasWriteAccess(authenticated)==false)IsoException.throwIt(Util.PERMISSION_DENIED);
//			offset=Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA+2],(byte) buffer[Iso7816.OFFSET_CDATA+1]});	
//			bytesLeft=Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA+5],(byte) buffer[Iso7816.OFFSET_CDATA+4]});
//			data=new byte[52];
//			readed=(byte)(buffer[Iso7816.OFFSET_LC]-7);
//			bytesLeft=(short)(bytesLeft-(short) readed);
//			for (byte i = 0; i < readed; i++) {
//				data[i]=buffer[(byte)(Iso7816.OFFSET_CDATA+i+7)];					
//			}
//		}
//		else{ //commandToContinue==Util.WRITE_DATA
//			data=new byte[59];
//			readed=(byte)buffer[Iso7816.OFFSET_LC];
//			bytesLeft=(short)(bytesLeft-(short) readed);
//			for (byte i = 0; i < readed; i++) {
//				data[i]=buffer[(byte)(Iso7816.OFFSET_CDATA+i)];					
//			}
//		}	
//		//Write
//		((StandartFile)selectedFile).writeArray(data,offset,readed);
//
//		if(bytesLeft>0){
//			commandToContinue=Util.WRITE_DATA;
//			offset=(short)(offset+readed);
//			IsoException.throwIt(Util.CONTINUE);
//		}
//		else{ 
//			commandToContinue=Util.NO_COMMAND_TO_CONTINUE;
//			offset=0;
//			bytesLeft=0;
//			IsoException.throwIt(Util.OPERATION_OK);
//		}
//	}


    /**
     * Writes data to Standard Data Files or Backup Data Files
     *
     * @note The MSB in the 3 bits values is not readed
     * @note If the data doesn't fit in one message (52 bytes)
     * the sender will split it in more messages (59 bytes)
     * so this command may have more than one execution in row.
     * @note || File No | Offset | Lenght | Data ||
     * 1        3        3     1-52
     */
    private void writeData(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if (((byte) buffer[Iso7816.OFFSET_INS] == DesFireInstruction.WRITE_DATA.toByte()) && ((byte) buffer[Iso7816.OFFSET_LC] < 8))
            IsoException.throwIt(Util.LENGTH_ERROR);
        if (((byte) buffer[Iso7816.OFFSET_INS] == DesFireInstruction.CONTINUE.toByte()) && ((byte) buffer[Iso7816.OFFSET_LC] != 0))
            IsoException.throwIt(Util.LENGTH_ERROR);
        byte readed;
        if (commandToContinue == DesFireInstruction.NO_COMMAND_TO_CONTINUE) {
            //Get parameters
            byte fileID = buffer[Iso7816.OFFSET_CDATA];
            if (selectedDF.isValidFileNumber(fileID) == false) IsoException.throwIt(Util.FILE_NOT_FOUND);
            selectedFile = selectedDF.getFile(fileID);
            if (selectedFile.hasWriteAccess(authenticated) == false) IsoException.throwIt(Util.PERMISSION_DENIED);

            offset = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 2], (byte) buffer[Iso7816.OFFSET_CDATA + 1]});
            bytesLeft = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 5], (byte) buffer[Iso7816.OFFSET_CDATA + 4]});

            //Take first bytes

            readed = (byte) (buffer[Iso7816.OFFSET_LC] - 7);//number of bytes in the first message
            bytesLeft = (short) (bytesLeft - readed);//update number of bytes remaining
            dataBuffer = Util.subByteArray(buffer, (short) (Iso7816.OFFSET_CDATA + 7), (short) (Iso7816.OFFSET_CDATA + 7 + readed - 1));

        } else { //commandToContinue==Util.WRITE_DATA
            readed = (byte) buffer[Iso7816.OFFSET_LC];
            bytesLeft = (short) (bytesLeft - (short) readed);
            dataBuffer = Util.concatByteArray(dataBuffer, Util.subByteArray(buffer, Iso7816.OFFSET_CDATA, (short) (Iso7816.OFFSET_CDATA + readed)));
        }
        if (bytesLeft > 0) {//If there are still more bytes to receive we inform we are waiting for them
            commandToContinue = DesFireInstruction.WRITE_DATA;
            IsoException.throwIt(DesFireInstruction.CONTINUE.toByte());
        } else { //if this was the last message we reset the variables and inform the file
            commandToContinue = DesFireInstruction.NO_COMMAND_TO_CONTINUE;
            offset = 0;
            bytesLeft = 0;

//			IsoException.throwIt((short)0xABBB);
            ((StandartFile) selectedFile).writeArray(dataBuffer, offset, (short) dataBuffer.length);
            dataBuffer = null;
            IsoException.throwIt(Util.OPERATION_OK);
        }
    }

    private ResponseApdu getVersion(CommandApdu Apdu, byte[] buffer) {
        byte[] response;
        short statusBytes = Util.OPERATION_OK;
        if (commandToContinue == DesFireInstruction.NO_COMMAND_TO_CONTINUE) {
            response = ResponseApdus.VERSION_1;
            offset = (short) response.length;
            commandToContinue = DesFireInstruction.GET_VERSION;
            statusBytes = Util.ADDITIONAL_FRAME;
        } else if (offset == ResponseApdus.VERSION_1.length) {
            response = ResponseApdus.VERSION_2;
            offset = (short) (ResponseApdus.VERSION_1.length + ResponseApdus.VERSION_2.length);
            commandToContinue = DesFireInstruction.GET_VERSION;
            statusBytes = Util.ADDITIONAL_FRAME;
        } else {
            response = ResponseApdus.VERSION_3;
            commandToContinue = DesFireInstruction.NO_COMMAND_TO_CONTINUE;
            offset = 0;
        }
        return sendResponse(Apdu, buffer, response, statusBytes);
    }

    /**
     * Reads the currently stored value form Value Files
     *
     * @note || FileN ||
     * 1
     */
    private ResponseApdu getValue(Apdu Apdu, byte[] buffer) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if ((byte) buffer[Iso7816.OFFSET_LC] != 1) IsoException.throwIt(Util.LENGTH_ERROR);
        byte fileID = buffer[Iso7816.OFFSET_CDATA];
        if (selectedDF.isValidFileNumber(fileID) == false) IsoException.throwIt(Util.FILE_NOT_FOUND);
        selectedFile = (ValueRecord) selectedDF.getFile(fileID);
        if (((ValueRecord) selectedFile).hasReadAccess(authenticated) != true)
            IsoException.throwIt(Util.PERMISSION_DENIED);
        byte[] response = Util.switchBytes((((ValueRecord) selectedFile).getValue().getValue()));
        return sendResponse(Apdu, buffer, response, Util.OPERATION_OK, selectedFile.getCommunicationSettings());
    }

    /**
     * Increases a value stored in a Value File
     *
     * @note ||	FileN | Data  ||
     * 1       4
     */

    private void credit(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if ((byte) buffer[Iso7816.OFFSET_LC] != 5) IsoException.throwIt(Util.LENGTH_ERROR);
        byte fileID = (byte) buffer[Iso7816.OFFSET_CDATA];
        if (selectedDF.isValidFileNumber(fileID) == false) IsoException.throwIt(Util.FILE_NOT_FOUND);
        selectedFile = (ValueRecord) selectedDF.getFile(fileID);
        if (((ValueRecord) selectedFile).hasWriteAccess(authenticated) == false)
            IsoException.throwIt(Util.PERMISSION_DENIED);
        ((ValueRecord) selectedFile).addCredit(new Value(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 4], (byte) buffer[Iso7816.OFFSET_CDATA + 3], (byte) buffer[Iso7816.OFFSET_CDATA + 2], (byte) buffer[Iso7816.OFFSET_CDATA + 1]}));
        IsoException.throwIt(Util.OPERATION_OK);
    }

    /**
     * Decreases a value stored in a Value File
     *
     * @note ||	FileN | Data  ||
     */
    private void debit(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if ((byte) buffer[Iso7816.OFFSET_LC] != 5) IsoException.throwIt(Util.LENGTH_ERROR);
        byte fileID = (byte) buffer[Iso7816.OFFSET_CDATA];
        if (selectedDF.isValidFileNumber(fileID) == false) IsoException.throwIt(Util.FILE_NOT_FOUND);
        selectedFile = (ValueRecord) selectedDF.getFile(fileID);
        if (((ValueRecord) selectedFile).hasWriteAccess(authenticated) == false)
            IsoException.throwIt(Util.PERMISSION_DENIED);
        ((ValueRecord) selectedFile).decDebit(new Value(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 4], (byte) buffer[Iso7816.OFFSET_CDATA + 3], (byte) buffer[Iso7816.OFFSET_CDATA + 2], (byte) buffer[Iso7816.OFFSET_CDATA + 1]}));
        IsoException.throwIt(Util.OPERATION_OK);

    }

    /**
     * Writes data to a record in a Cyclic or Linear Record File
     *
     * @note The MSB in the 3 bits values is not readed
     * @note If the data doesn't fit in one message (52 bytes)
     * the sender will split it in more messages (59 bytes)
     * so this command may have more than one execution in row.
     * @note || FileN | Offset | Length | Data ||
     * 1        3        3     1-52
     */

    //ECHARLE UN VISTAZO A ESTO
    //FALTA
    private void writeRecord(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if (((byte) buffer[Iso7816.OFFSET_INS] == DesFireInstruction.WRITE_RECORD.toByte()) && ((byte) buffer[Iso7816.OFFSET_LC] < 8))
            IsoException.throwIt(Util.LENGTH_ERROR);
        if (((byte) buffer[Iso7816.OFFSET_INS] == DesFireInstruction.CONTINUE.toByte()) && ((byte) buffer[Iso7816.OFFSET_LC] != 0))
            IsoException.throwIt(Util.LENGTH_ERROR);

        if (commandToContinue == DesFireInstruction.NO_COMMAND_TO_CONTINUE) {

            byte fileID = buffer[Iso7816.OFFSET_CDATA];
            selectedFile = selectedDF.getFile(fileID);
            if (selectedDF.isValidFileNumber(fileID) == false) IsoException.throwIt(Util.FILE_NOT_FOUND);
            offset = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 2], (byte) buffer[Iso7816.OFFSET_CDATA + 1]});
            bytesLeft = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 5], (byte) buffer[Iso7816.OFFSET_CDATA + 4]});
            byte length = (byte) (buffer[Iso7816.OFFSET_LC] - 7);
            dataBuffer = new byte[bytesLeft];
            for (byte i = 0; i < length; i++) {
                dataBuffer[i] = buffer[(byte) (Iso7816.OFFSET_CDATA + i + 7)];
            }
            if (selectedFile instanceof LinearRecord) {
                selectedFile = (LinearRecord) selectedDF.getFile(buffer[Iso7816.OFFSET_CDATA]);
                if (((LinearRecord) selectedFile).hasWriteAccess(authenticated) == false) {
                    IsoException.throwIt(Util.PERMISSION_DENIED);
                }
            } else if (selectedFile instanceof CyclicRecord) {
                selectedFile = (CyclicRecord) selectedDF.getFile(buffer[Iso7816.OFFSET_CDATA]);
                if (((CyclicRecord) selectedFile).hasWriteAccess(authenticated) == false) {
                    IsoException.throwIt(Util.PERMISSION_DENIED);
                }
            }
            if (bytesLeft <= 52) {
                if (selectedFile instanceof LinearRecord) ((LinearRecord) selectedFile).writeRecord(dataBuffer, offset);
                if (selectedFile instanceof CyclicRecord) ((CyclicRecord) selectedFile).writeRecord(dataBuffer, offset);
                dataBuffer = null;
                offset = 0;
                bytesLeft = 0;
                IsoException.throwIt(Util.OPERATION_OK);
            } else {
                readed = 52;
                bytesLeft = (short) (bytesLeft - 52);
                commandToContinue = DesFireInstruction.WRITE_RECORD;
                IsoException.throwIt(DesFireInstruction.CONTINUE.toByte());
            }
        } else {//commandToContinue==Util.WRITE_RECORD
            byte length = (byte) (buffer[Iso7816.OFFSET_LC]);
            for (byte i = 0; i < length; i++) {
                dataBuffer[(short) (i + readed)] = buffer[(byte) (Iso7816.OFFSET_CDATA + i)];
            }
            if (bytesLeft <= 59) {
                if (selectedFile instanceof LinearRecord) ((LinearRecord) selectedFile).writeRecord(dataBuffer, offset);
                if (selectedFile instanceof CyclicRecord) ((CyclicRecord) selectedFile).writeRecord(dataBuffer, offset);
                dataBuffer = null;
                offset = 0;
                bytesLeft = 0;
                IsoException.throwIt(Util.OPERATION_OK);
            } else {
                readed = (short) (readed + 59);
                bytesLeft = (short) (bytesLeft - 59);
                commandToContinue = DesFireInstruction.WRITE_RECORD;
                IsoException.throwIt(DesFireInstruction.CONTINUE.toByte());
            }
        }
        return;
    }

    /**
     * Reads out a set of complete records from a Cyclic or Linear Record File
     *
     * @note Records are sent in cronological order.
     * @note When data is sent, if the length of the data doesn't fit in one
     * message (59 bytes) the data field is splitted. If more thata will
     * be sent the PICC informs with the SW: 0xAF
     * @note || FileN | Offset | Length ||
     * 1        3        3
     * Offset.	Position of the newest record to read starting from the end
     * Length.	Number of records to read
     */

    //USAR LOS NUEVOS METODOS IMPLEMENTADOS PARA REALIZARLO DE UNA MANERA M�S ELEGANTE
    private ResponseApdu readRecords(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if ((byte) buffer[Iso7816.OFFSET_LC] != 7) IsoException.throwIt(Util.LENGTH_ERROR);
        byte[] out = null;
        if (commandToContinue == DesFireInstruction.NO_COMMAND_TO_CONTINUE) {
            byte fileID = buffer[Iso7816.OFFSET_CDATA];
            if (selectedDF.isValidFileNumber(fileID) == false) IsoException.throwIt(Util.FILE_NOT_FOUND);
            selectedFile = selectedDF.getFile(fileID);
            offset = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 2], (byte) buffer[Iso7816.OFFSET_CDATA + 1]});
            short length = Util.byteArrayToShort(new byte[]{(byte) buffer[Iso7816.OFFSET_CDATA + 5], (byte) buffer[Iso7816.OFFSET_CDATA + 4]});
            if (selectedFile instanceof LinearRecord) {
                selectedFile = (LinearRecord) selectedDF.getFile(buffer[Iso7816.OFFSET_CDATA]);
                if (((LinearRecord) selectedFile).hasReadAccess(authenticated) == false) {
                    IsoException.throwIt(Util.PERMISSION_DENIED);
                }
                bytesLeft = (short) (length * ((LinearRecord) selectedFile).recordSize);
                offset = (short) (((LinearRecord) selectedFile).getCurrentSize() - offset * ((LinearRecord) selectedFile).recordSize - bytesLeft);//offset respecto al inicio
                if (bytesLeft <= 59) {
                    out = ((LinearRecord) selectedFile).readData(offset, bytesLeft, (byte) 0);
                    offset = 0;
                    bytesLeft = 0;
                    return sendResponse(Apdu, buffer, out, Util.OPERATION_OK, selectedFile.getCommunicationSettings());
                } else {
                    out = ((LinearRecord) selectedFile).readData(offset, (byte) 59, (byte) 0);
                    commandToContinue = DesFireInstruction.READ_RECORDS;
                    offset = (short) (offset + 59);
                    bytesLeft = (short) (bytesLeft - 59);
                    return sendResponse(Apdu, buffer, out, DesFireInstruction.CONTINUE.toByte(), selectedFile.getCommunicationSettings());
                }
            }
            if (selectedFile instanceof CyclicRecord) {
                selectedFile = (CyclicRecord) selectedDF.getFile(buffer[Iso7816.OFFSET_CDATA]);
                if (((CyclicRecord) selectedFile).hasReadAccess(authenticated) == false) {
                    IsoException.throwIt(Util.PERMISSION_DENIED);
                }

                bytesLeft = (short) (length * ((CyclicRecord) selectedFile).recordSize);
                offset = (short) (((CyclicRecord) selectedFile).getNextToWrite() - offset * ((CyclicRecord) selectedFile).recordSize - bytesLeft);//offset respecto al inicio
                if (bytesLeft <= 59) {
                    out = ((CyclicRecord) selectedFile).readData(offset, bytesLeft, (byte) 0);
                    offset = 0;
                    bytesLeft = 0;
                    return sendResponse(Apdu, buffer, out, Util.OPERATION_OK, selectedFile.getCommunicationSettings());
                } else {
                    out = ((CyclicRecord) selectedFile).readData(offset, (byte) 59, (byte) 0);
                    commandToContinue = DesFireInstruction.READ_RECORDS;
                    offset = (short) (offset + 59);
                    bytesLeft = (short) (bytesLeft - 59);
                    return sendResponse(Apdu, buffer, out, DesFireInstruction.CONTINUE.toByte(), selectedFile.getCommunicationSettings());
                }

            }

        } else {//commandToContinue==Util.READ_RECORDS
            if (selectedFile instanceof LinearRecord) {
                if (bytesLeft <= 59) {
                    out = ((LinearRecord) selectedFile).readData(offset, bytesLeft, (byte) 0);
                    offset = 0;
                    bytesLeft = 0;
                    commandToContinue = DesFireInstruction.NO_COMMAND_TO_CONTINUE;
                    return sendResponse(Apdu, buffer, out, Util.OPERATION_OK, selectedFile.getCommunicationSettings());
                } else {
                    out = ((LinearRecord) selectedFile).readData(offset, (byte) 59, (byte) 0);
                    commandToContinue = DesFireInstruction.READ_RECORDS;
                    offset = (short) (offset + 59);
                    bytesLeft = (short) (bytesLeft - 59);
                    return sendResponse(Apdu, buffer, out, DesFireInstruction.CONTINUE.toByte(), selectedFile.getCommunicationSettings());
                }
            }
            if (selectedFile instanceof CyclicRecord) {
                if (bytesLeft <= 59) {
                    out = ((CyclicRecord) selectedFile).readData(offset, bytesLeft, (byte) 0);
                    offset = 0;
                    bytesLeft = 0;
                    commandToContinue = DesFireInstruction.NO_COMMAND_TO_CONTINUE;
                    return sendResponse(Apdu, buffer, out, (byte) 0x00, selectedFile.getCommunicationSettings());
                } else {
                    out = ((CyclicRecord) selectedFile).readData(offset, (byte) 59, (byte) 0);
                    commandToContinue = DesFireInstruction.READ_RECORDS;
                    offset = (short) (offset + 59);
                    bytesLeft = (short) (bytesLeft - 59);
                    return sendResponse(Apdu, buffer, out, DesFireInstruction.CONTINUE.toByte());
                }
            }
        }
        IsoException.throwIt(Util.APPL_INTEGRITY_ERROR);
        return null;
    }

    /**
     * Resets a Cyclic or Linear Record File to empty state.
     *
     * @note || FileN ||
     * 1
     */
    private void clearRecordFile(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if ((byte) buffer[Iso7816.OFFSET_LC] != 1) IsoException.throwIt(Util.LENGTH_ERROR);
        byte fileID = buffer[Iso7816.OFFSET_CDATA];
        selectedFile = selectedDF.getFile(fileID);
        if (selectedDF.isValidFileNumber(fileID) == false) IsoException.throwIt(Util.FILE_NOT_FOUND);

        if (selectedFile instanceof LinearRecord) {
            selectedFile = (LinearRecord) selectedDF.getFile(buffer[Iso7816.OFFSET_CDATA]);
            if (((LinearRecord) selectedFile).hasWriteAccess(authenticated) == false) {
                IsoException.throwIt(Util.PERMISSION_DENIED);
            }
            ((LinearRecord) selectedFile).deleteRecords();
            IsoException.throwIt(Util.OPERATION_OK);
        }
        if (selectedFile instanceof CyclicRecord) {
            selectedFile = (CyclicRecord) selectedDF.getFile(buffer[Iso7816.OFFSET_CDATA]);
            if (((CyclicRecord) selectedFile).hasWriteAccess(authenticated) == false) {
                IsoException.throwIt(Util.PERMISSION_DENIED);
            }
            ((CyclicRecord) selectedFile).deleteRecords();
            IsoException.throwIt(Util.OPERATION_OK);
        }
    }

    /**
     * Validates all previous write access on Backup Data Files, Value Files and
     * Record Files within one application
     */
    private void commitTransaction(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);


        if ((byte) buffer[Iso7816.OFFSET_LC] != 0) IsoException.throwIt(Util.LENGTH_ERROR);
        for (byte i = 0; i < 32; i++) {
            if (selectedDF.getWaitingForTransaction(i) == true) {
                if (selectedDF.getFile(i) instanceof BackupFile) {
                    selectedFile = (BackupFile) selectedDF.getFile(i);
                    if (((BackupFile) selectedFile).hasWriteAccess(authenticated) == false)
                        IsoException.throwIt(Util.PERMISSION_DENIED);
                    ((BackupFile) selectedFile).commitTransaction();
                }
                if (selectedDF.getFile(i) instanceof LinearRecord) {
                    selectedFile = (LinearRecord) selectedDF.getFile(i);
                    if (((LinearRecord) selectedFile).hasWriteAccess(authenticated) == false)
                        IsoException.throwIt(Util.PERMISSION_DENIED);
                    ((LinearRecord) selectedFile).commitTransaction();
                }
                if (selectedDF.getFile(i) instanceof CyclicRecord) {
                    selectedFile = (CyclicRecord) selectedDF.getFile(i);
                    if (((CyclicRecord) selectedFile).hasWriteAccess(authenticated) == false)
                        IsoException.throwIt(Util.PERMISSION_DENIED);
                    ((CyclicRecord) selectedFile).commitTransaction();
                }
                if (selectedDF.getFile(i) instanceof ValueRecord) {
                    selectedFile = (ValueRecord) selectedDF.getFile(i);
                    if (((ValueRecord) selectedFile).hasWriteAccess(authenticated) == false)
                        IsoException.throwIt(Util.PERMISSION_DENIED);
                    ((ValueRecord) selectedFile).commitTransaction();
                }
            }
        }
        IsoException.throwIt(Util.OPERATION_OK);
    }

    /**
     * Invalidates all previous write access on Backup Data Files, Value Files and
     * Record Files within one application
     */
    private void abortTransaction(Apdu Apdu, byte[] buffer) {
        if (selectedDF.isMasterFile() == true) IsoException.throwIt(Util.PERMISSION_DENIED);

        if ((byte) buffer[Iso7816.OFFSET_LC] != 0) IsoException.throwIt(Util.LENGTH_ERROR);
        for (byte i = 0; i < 32; i++) {
            if (selectedDF.getWaitingForTransaction(i) == true) {
                if (selectedDF.getFile(i) instanceof BackupFile) {
                    selectedFile = (BackupFile) selectedDF.getFile(i);
                    if (((BackupFile) selectedFile).hasWriteAccess(authenticated) == false)
                        IsoException.throwIt(Util.PERMISSION_DENIED);
                    ((BackupFile) selectedFile).abortTransaction();
                }
                if (selectedDF.getFile(i) instanceof LinearRecord) {
                    selectedFile = (LinearRecord) selectedDF.getFile(i);
                    if (((LinearRecord) selectedFile).hasWriteAccess(authenticated) == false)
                        IsoException.throwIt(Util.PERMISSION_DENIED);
                    ((LinearRecord) selectedFile).abortTransaction();
                }
                if (selectedDF.getFile(i) instanceof CyclicRecord) {
                    selectedFile = (CyclicRecord) selectedDF.getFile(i);
                    if (((CyclicRecord) selectedFile).hasWriteAccess(authenticated) == false)
                        IsoException.throwIt(Util.PERMISSION_DENIED);
                    ((CyclicRecord) selectedFile).abortTransaction();
                }
                if (selectedDF.getFile(i) instanceof ValueRecord) {
                    selectedFile = (ValueRecord) selectedDF.getFile(i);
                    if (((ValueRecord) selectedFile).hasWriteAccess(authenticated) == false)
                        IsoException.throwIt(Util.PERMISSION_DENIED);
                    ((ValueRecord) selectedFile).abortTransaction();
                }
            }
        }
    }

    /**
     * Encrypts the message
     *
     * @return The message encrypted in the following way:
     * - The CRC is calculated
     * - The whole array is padded
     * - Everything is encyphered
     */
    public byte[] encryptBytes(byte[] msg, Key key) {
        try {
            byte[] crc = buildCrc(msg);// 16 or 32 bit
            msg = Util.concatByteArray(msg, crc);
            msg = Util.preparePaddedByteArray(msg);
            Cipher cipher = deriveCipherFromKey(key);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            msg = cipher.doFinal(msg);
        } catch(GeneralSecurityException e) {
            securityLevel = Util.PLAIN_COMMUNICATION;
            IsoException.throwIt(Util.INTEGRITY_ERROR);
        }
        return msg;
    }

    /**
     * Decrypts the message
     *
     * @return The message decrypted in the following way:
     * - Everything is decyphered
     * - The padding is taken out
     * - The CRC is calculated and compared with the received
     */
    private byte[] decryptBytes(byte[] encryptedMsg, Key key) {
        byte[] msg = new byte[encryptedMsg.length];
        try {
            Cipher cipher = deriveCipherFromKey(key);
            //Decrypt
            cipher.init(Cipher.DECRYPT_MODE, key);
            cipher.doFinal(encryptedMsg, (short) 0, (short) encryptedMsg.length, msg, (short) 0);
            //Padding out
            byte[] data = Util.removePadding(msg);
            //Checks CRC
            int bytes = legacyMode ? 4 : 2;
            byte[] receivedCrc = Util.subByteArray(data, (byte) (data.length - bytes), (byte) (data.length - 1));
            data = Util.subByteArray(data, (byte) 0, (byte) (data.length - (bytes + 1)));
            byte[] newCrc = buildCrc(data);
            if (Util.byteArrayCompare(newCrc, receivedCrc) == false) {
                //We check if there was no padding
                receivedCrc = Util.subByteArray(msg, (byte) (msg.length - bytes), (byte) (msg.length - 1));
                msg = Util.subByteArray(msg, (byte) 0, (byte) (msg.length - (bytes + 1)));
                newCrc = buildCrc(legacyMode ? Util.getCData(data) : data);
                if (Util.byteArrayCompare(newCrc, receivedCrc) == false) {
                    securityLevel = Util.PLAIN_COMMUNICATION;
                    IsoException.throwIt(Util.INTEGRITY_ERROR);
                }
            }
        } catch (GeneralSecurityException e){
            securityLevel = Util.PLAIN_COMMUNICATION;
            IsoException.throwIt(Util.INTEGRITY_ERROR);
        }
        return msg;
    }

    private byte[] buildCrc(byte[] data) {
        return legacyMode ? Util.crc16(data) : Util.crc32(data);
    }

    /**
     * Returns the plain data of the Apdu
     */
    private byte[] getCData(byte[] buffer) {
        switch (this.securityLevel) {
            case Util.PLAIN_COMMUNICATION:
                return Util.getCData(buffer);
            case Util.FULLY_ENCRYPTED:
                if (buffer.length > 0) {
                    buffer = decryptBytes(buffer, sessionKey);
                } else return buffer;
            default:
                break;
        }
        return null;
    }

    private void receiveAPDU(Apdu apdu) {
        byte[] buffer = apdu.getBuffer();
        byte[] cData = getCData(buffer);
    }


    private ResponseApdu sendResponse(Apdu Apdu, byte[] buffer, byte[] response) {
        return sendResponse(Apdu, buffer, response, (byte) 0x00);
    }

    /**
     * Send a response with configurable status word
     *
     */
    private ResponseApdu sendResponse(Apdu Apdu, byte[] buffer, byte[] response, short status) {
        return sendResponse(Apdu, buffer, response, status, this.securityLevel);
    }

    /**
     * Send a response with configurable status word and security level
     *
     */
    private ResponseApdu sendResponse(Apdu Apdu, byte[] buffer, byte[] response, short status, byte securityLevel) {
        // construct the reply Apdu

        //short le = Apdu.setOutgoing();
        // if (le < (short)2) IsoException.throwIt( Iso7816.SW_WRONG_LENGTH );
        if (response.length == 0) IsoException.throwIt((short) 0x917E);//AUX
        //			this.securityLevel=Util.PLAIN_COMMUNICATION;
        // build response data in Apdu.buffer[ 0.. outCount-1 ];
        switch (securityLevel) {
            case Util.PLAIN_COMMUNICATION:
                break;
            case Util.PLAIN_COMMUNICATION_MAC:
                break;
            case Util.FULLY_ENCRYPTED:
                response = encryptBytes(response, sessionKey);
                break;
            default:
                break;
        }
//			Apdu.setOutgoingLength( (short) response.length );
//			for (byte i = 0; i < response.length; i++) {
//				buffer[i]=response[i];
//			}
//			Apdu.sendBytes ( (short)0 , (short)response.length );
        return new ResponseApdu(response, response.length, status);
    }

    /**
     * This is needed for the authentication because the last message should be sended
     * encrypted with the old session key and afterwards the session key should change
     */
    private ResponseApdu sendResponseAndChangeStatus(Apdu Apdu, byte[] buffer, byte[] response, Key newSessionKey) {

        // construct the reply Apdu
        //short le = Apdu.setOutgoing();
        // if (le < (short)2) IsoException.throwIt( Iso7816.SW_WRONG_LENGTH );
        if (response.length == 0) IsoException.throwIt((short) 0x917E);//AUX
        //			this.securityLevel=Util.PLAIN_COMMUNICATION;
        // build response data in Apdu.buffer[ 0.. outCount-1 ];
        switch (this.securityLevel) {
            case Util.PLAIN_COMMUNICATION:
                break;
            case Util.PLAIN_COMMUNICATION_MAC:
                break;
            case Util.FULLY_ENCRYPTED:
                response = encryptBytes(response, sessionKey);
                break;
            default:
                break;
        }

        sessionKey = newSessionKey;
        securityLevel = Util.FULLY_ENCRYPTED;
        for (byte i = 0; i < response.length; i++) {
            buffer[i] = response[i];
        }
        return new ResponseApdu(buffer, response.length);
    }

    /**
     * Perform any cleanup tasks and set the PICC level
     */
    private void clear() {
        selectedFile = null;
        selectedDF = masterFile;
        commandToContinue = DesFireInstruction.NO_COMMAND_TO_CONTINUE;
        authenticated = Util.NO_KEY_AUTHENTICATED;
        dataBuffer = null;
        securityLevel = Util.PLAIN_COMMUNICATION;
        fileSecurityLevel = Util.PLAIN_COMMUNICATION;
        readed = 0;
        offset = 0;
        bytesLeft = 0;
        keyNumberToAuthenticate = 0;
        //sessionKey.clearKey();	
        sessionKey = null;
    }

    /**
     * Decrypts the key data for some commands that require this particular
     * security mechanism
     *
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws ShortBufferException
     * @note If the key number to change is different from the key used for authentication,
     * it is needed to prove that the other key is also known so the PCD has to:
     * - bit-wise XOR both new and old key
     * - calculate CRC16 over the XOred data and append it to the end
     * @note The key to be change is enciphered by the PCD in the next way:
     * - append at the end the CRC16 calculated over the new key
     * - Do the paddingto reach an adequate frame size
     * - Encipher using he current session key
     * - The blocks are chained in CRC send mode.
     */
    public byte[] decryptEncipheredKeyData(byte[] encipheredData, byte keyN) throws InvalidKeyException, BadPaddingException, ShortBufferException, IllegalBlockSizeException {

        if (keyN == authenticated) {
            return decryptBytes(encipheredData, sessionKey);
        } else {
            //Decrypt
            Cipher cipher = deriveCipherFromKey(sessionKey);
            byte[] unpaddedData = new byte[encipheredData.length];
            cipher.init(Cipher.DECRYPT_MODE, sessionKey);
            cipher.doFinal(encipheredData, (short) 0, (short) encipheredData.length, unpaddedData, (short) 0);

            //Padding out
            byte[] data = Util.removePadding(unpaddedData);


            //Checks CRC
            byte[] receivedNewKeyCrc = Util.subByteArray(data, (byte) (data.length - 2), (byte) (data.length - 1));
            byte[] receivedXORCrc = Util.subByteArray(data, (byte) (data.length - 4), (byte) (data.length - 3));
            data = Util.subByteArray(data, (byte) 0, (byte) (data.length - 5));
            byte[] XORCrc = Util.crc16(data);
            if (Util.byteArrayCompare(XORCrc, receivedXORCrc) == false) {
                //We check if there was no padding
                receivedXORCrc = Util.subByteArray(unpaddedData, (byte) (unpaddedData.length - 4), (byte) (unpaddedData.length - 3));
                data = Util.subByteArray(unpaddedData, (byte) 0, (byte) (unpaddedData.length - 5));
                XORCrc = Util.crc16(data);
                if (Util.byteArrayCompare(XORCrc, receivedXORCrc) == false) {
                    securityLevel = Util.PLAIN_COMMUNICATION;
                    IsoException.throwIt(Util.INTEGRITY_ERROR);
                }
            }

            //The new key is obtained
            byte[] oldKey = new byte[16];
            try {
                oldKey = selectedDF.getKey(keyN).getEncoded();
                // FIXME is this correct??
                //((DESKey)selectedDF.getKey(keyN)).getKey(oldKey, (short)0);
            } catch (IsoException e) {
                oldKey = Util.getZeroArray((short) 16);
            }
            byte[] newKey = Util.xorByteArray(data, oldKey);

            //Check the CRC of the new key
            byte[] newKeyCrc = Util.crc16(newKey);
            if (Util.byteArrayCompare(newKeyCrc, receivedNewKeyCrc) == false) {
                //We check if there was no padding
                receivedNewKeyCrc = Util.subByteArray(unpaddedData, (byte) (unpaddedData.length - 2), (byte) (unpaddedData.length - 1));
                data = Util.subByteArray(unpaddedData, (byte) 0, (byte) (unpaddedData.length - 3));
                newKey = Util.xorByteArray(data, oldKey);
                newKeyCrc = Util.crc16(newKey);
                if (Util.byteArrayCompare(newKeyCrc, receivedNewKeyCrc) == false) {
                    securityLevel = Util.PLAIN_COMMUNICATION;
                    IsoException.throwIt(Util.INTEGRITY_ERROR);
                }
            }

            //If no exception is thrown the new key is returned
            return newKey;
        }
    }

    /**
     * It is called for the continuous sending of parts of a message. Everytime it is called it sends a block of MAX_BLOCK bytes
     * since the position pointed by the given offset
     *
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws ShortBufferException
     * @throws InvalidKeyException
     */
    private ResponseApdu sendBlockResponse(Apdu Apdu, byte[] buffer, byte[] data, short offset, byte securityLevel) {
        if ((short) (offset + Util.MAX_DATA_SIZE) < data.length) {
            this.offset = (short) (offset + Util.MAX_DATA_SIZE);
            return sendResponse(Apdu, buffer, Util.subByteArray(data, offset, (short) (offset + Util.MAX_DATA_SIZE - 1)), DesFireInstruction.CONTINUE.toByte(), securityLevel);
        } else {
//			IsoException.throwIt((short)securityLevel);
            halfClear();
            return sendResponse(Apdu, buffer, Util.subByteArray(data, offset, (short) (data.length - 1)), DesFireInstruction.CONTINUE.toByte(), securityLevel);
        }

    }

    /**
     * Reset the variables involved in a multiple-part execution
     */
    private void halfClear() {
        commandToContinue = DesFireInstruction.NO_COMMAND_TO_CONTINUE;
        dataBuffer = null;
        readed = 0;
        offset = 0;
        bytesLeft = 0;
        fileSecurityLevel = securityLevel;
    }

    public ResponseApdu process(CommandApdu apdu) {
// return if the Apdu is the applet SELECT command
//		if (selectingApplet())
//			return;
//		
//		byte[] buffer = Apdu.getBuffer();

        if (authenticated == -1) this.securityLevel = Util.PLAIN_COMMUNICATION;
        if ((commandToContinue != DesFireInstruction.NO_COMMAND_TO_CONTINUE) && (apdu.getBuffer()[Iso7816.OFFSET_INS] != (byte) 0xAF)) {
            clear();
            IsoException.throwIt((short) Util.COMMAND_ABORTED);
        }

        // Firstly check if it is protected and if so unwrap it
        boolean isProtected = (apdu.cla & CLA_PROTECTED_APDU) == CLA_PROTECTED_APDU;
        if (isProtected) {
            apdu = SecureApdu.unwrapCommandApdu(apdu);
        }
        try {
            // check the INS byte to decide which service method to call
            //switch (buffer[Iso7816.OFFSET_INS]) {
            DesFireInstruction instruction = DesFireInstruction.parseInstruction(apdu.ins);
            // push instruction to stack. apdu as well.C
            switch (instruction) {
                case GET_VERSION:
                    return getVersion(apdu, apdu.getBuffer());
                // legacy authentication
                case AUTHENTICATE:
                    return authenticate(apdu, apdu.getBuffer());
                case AUTHENTICATE_AES:
                    return authenticate(apdu, apdu.getBuffer());
                case CHANGE_KEY_SETTINGS:
                    changeKeySettings(apdu, apdu.getBuffer());
                    break;
                case CHANGE_KEY:
                    changeKey(apdu, apdu.getBuffer());
                    break;
                case CREATE_APPLICATION:
                    createApplication(apdu, apdu.getBuffer());
                    break;
                case DELETE_APPLICATION:
                    deleteApplication(apdu, apdu.getBuffer());
                    break;
                case GET_APPLICATION_IDS:
                    return getApplicationIDs(apdu, apdu.getBuffer());
                case GET_KEY_SETTINGS:
                    return getKeySettings(apdu, apdu.getBuffer());
                case SELECT_APPLICATION:
                    selectApplication(apdu, apdu.getBuffer());
                    break;
                case FORMAT_PICC:
                    formatPICC(apdu, apdu.getBuffer());
                    break;
                case SET_CONFIGURATION:
                    setConfiguration(apdu, apdu.getBuffer());
                    break;
                case GET_FILE_IDS:
                    return getFileIDs(apdu, apdu.getBuffer());
                case CREATE_STDDATAFILE:
                    createStdDataFile(apdu, apdu.getBuffer());
                    break;
                case CREATE_BACKUPDATAFILE:
                    createBackupDataFile(apdu, apdu.getBuffer());
                    break;
                case CREATE_VALUE_FILE:
                    createValueFile(apdu, apdu.getBuffer());
                    break;
                case CREATE_LINEAR_RECORD_FILE:
                    createLinearRecordFile(apdu, apdu.getBuffer());
                    break;
                case CREATE_CYCLIC_RECORD_FILE:
                    createCyclicRecordFile(apdu, apdu.getBuffer());
                    break;
                case DELETE_FILE:
                    deleteFile(apdu, apdu.getBuffer());
                    break;
                case READ_DATA:
                    return readData(apdu, apdu.getBuffer());
                case WRITE_DATA:
                    writeData(apdu, apdu.getBuffer());
                    break;
                case GET_VALUE:
                    return getValue(apdu, apdu.getBuffer());
                case CREDIT:
                    credit(apdu, apdu.getBuffer());
                    break;
                case DEBIT:
                    debit(apdu, apdu.getBuffer());
                    break;
                case READ_RECORDS:
                    return readRecords(apdu, apdu.getBuffer());
                case WRITE_RECORD:
                    writeRecord(apdu, apdu.getBuffer());
                    break;
                case CLEAR_RECORD_FILE:
                    clearRecordFile(apdu, apdu.getBuffer());
                    break;
                case COMMIT_TRANSACTION:
                    commitTransaction(apdu, apdu.getBuffer());
                    break;
                case ABORT_TRANSACTION:
                    abortTransaction(apdu, apdu.getBuffer());
                    break;
                case CONTINUE:
                    switch (commandToContinue) {
                        case AUTHENTICATE:
                            return authenticate(apdu, apdu.getBuffer());
                        case GET_APPLICATION_IDS:
                            return getApplicationIDs(apdu, apdu.getBuffer());
                        case READ_DATA:
                            return sendBlockResponse(apdu, apdu.getBuffer(), dataBuffer, offset, fileSecurityLevel);
                        case WRITE_DATA:
                            writeData(apdu, apdu.getBuffer());
                            break;
                        case READ_RECORDS:
                            return readRecords(apdu, apdu.getBuffer());
                        case WRITE_RECORD:
                            writeRecord(apdu, apdu.getBuffer());
                            break;
                        case GET_VERSION:
                            return getVersion(apdu, apdu.getBuffer());
                        default:
                            IsoException.throwIt((short) 0x911C);
                            break;
                    }
                    break;
                default:
                    IsoException.throwIt((short) 0x911C);
                    break;
            }
        } catch (IsoException e) {
            return new ResponseApdu(e.getErrorCode());
        } catch (Exception e) {
            return new ResponseApdu(Iso7816.SW_INTERNAL_ERROR);
        }
        return new ResponseApdu(Iso7816.SW_FUNC_NOT_SUPPORTED);
    }

    public String getName() {
        return LOG_TAG;
    }

    public byte[] getAid() {
        return APPLET_AID;
    }

    public MasterFile getMasterFile() {
        return masterFile;
    }

    public void setMasterFile(MasterFile masterFile) {
        this.masterFile = masterFile;
    }
}



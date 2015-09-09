package net.jpeelaer.hce.desfire;


import org.kevinvalk.hce.framework.IsoException;
import org.spongycastle.util.Arrays;


public class MasterFile extends DirectoryFile {
    private static final byte MF_FID = 0x00;
    /**
     * Sets if it's possible to format the card's memory
     */
    private boolean formatEnabled = true;

    /**
     * ??????????????
     */
    private boolean randomID = false;

    /**
     * Index of applications for search by their AID
     */
    IndexFile indexDF; //28 aplicaciones

    /**
     * Actual number of applications
     */
    byte numApp;

    /**
     * Pointers to the different applications
     */
    DirectoryFile[] arrayDF;

    /**
     * Default key to wich all new keys will be initialized
     */
    byte[] defaultKeyBytes;


    public MasterFile() {
        // file identifier of MasterFile is hard coded to 3F00
        super(MF_FID);
        numApp = 1;//El 0 es el IndexDF
        indexDF = new IndexFile((byte) 0x00, this, (short) 3, (short) 28);
        byte[] AID = {(byte) 0xF4, (byte) 0x01, (byte) 0x10};
        indexDF.writeRecord((short) 0, AID);
        arrayDF = new DirectoryFile[28];
        defaultKeyBytes = Util.TKDES_DEFAULT;
    }

    public byte[] getDefaultKey() {
        return defaultKeyBytes;
    }

    public byte addDF(byte[] AID, byte[] keySettings) {

        if (searchAID(AID) != (byte) -1) IsoException.throwIt(Util.DUPLICATE_ERROR);//AID repetida
        if (numApp == 27) IsoException.throwIt((short) 0x91CE);//Num App excede las 28
        indexDF.writeRecord(numApp, AID);
        arrayDF[numApp] = new DirectoryFile(numApp, keySettings, this);
        numApp++;
        return (byte) (numApp - 1);
    }

    public void deleteDF(byte[] AID) {
        byte ID = searchAID(AID);
        arrayDF[ID] = null;
        numApp--;
        //Borrar DF del record
        //FALTA
        indexDF.deleteRecord(ID);
    }

    /**
     * Search the AID and returns the internal index of the directory file
     *
     * @return "-1" if the AID is not found
     */
    public byte searchAID(byte[] AID) {
        for (byte i = 0; i < indexDF.size; i++) {
            if (Arrays.areEqual(AID, indexDF.readValue(i))) return (i);
        }
        return ((byte) -1); //if no mismatch
    }

    public byte[] getAID(byte index) {
        return indexDF.readValue(index);
    }

    public IndexFile getIndexDF() {
        return indexDF;
    }

    public void setConfiguration(byte configuration) {
        //Comprueba que tiene permiso para hacer esto
        //FALTA

        if ((configuration & (byte) 0x01) == (byte) 0x01) formatEnabled = false;
        else formatEnabled = true;
        if ((configuration & (byte) 0x02) == (byte) 0x02) randomID = false;
        else randomID = true;
    }

    /**
     * Checks if the key number is 0 since there is only the Master Key
     * in the card level
     */
    public boolean isValidKeyNumber(byte keyNumber) {
        if (keyNumber == 0) return true;
        else return false;
    }

    /**
     * Checks if this Directory File is the Master File
     *
     * @return True because this is the Master File
     */
    public boolean isMasterFile() {
        return true;
    }

    public boolean isFormatEnabled() {
        return (formatEnabled == true);
    }

    public boolean isRandomID() {
        return (randomID == true);
    }

    /**
     * Releases the user memory
     */
    public void format() {
        for (byte i = 0; i < arrayDF.length; i++) {
            if (arrayDF[i] != null) {
                deleteDF(getAID(i));
            }
        }
    }

    public void setDefaultKey(byte[] newDefaultKeyBytes) {
        defaultKeyBytes = newDefaultKeyBytes;
    }
}

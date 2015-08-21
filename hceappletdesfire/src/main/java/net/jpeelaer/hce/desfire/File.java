package net.jpeelaer.hce.desfire;

public abstract class File {
    private byte fileID;

    /**
     * Current size of the data in the file
     */
    private short size;

    /**
     * Link to the parent file
     */
    private DirectoryFile parentFile;

    /**
     * Word configurating the access rules to the file
     */
    private byte[] permissions;

    /**
     * Sets the security level of this file in particular
     *
     * @note The file's security level has priority over the card's security level.
     * So if the card's security level is enciphered and the file access is free
     * then the data readed is not enciphered.
     */

    private byte communicationSettings;


    /**
     * Constructor for the Master File
     *
     * @param fid
     */
    public File(byte fid) {
        fileID = fid;
    }

    /**
     * Constructor for the Directory Files
     */
    public File(byte fid, DirectoryFile parentFile) {
        this.parentFile = parentFile;
        fileID = fid;
        this.permissions = new byte[]{0x00, 0x00};
    }

    /**
     * Constructor for the Data Files
     */
    public File(byte fid, DirectoryFile parentFile, byte communicationSettings, byte[] permissions) {
        this.parentFile = parentFile;
        this.fileID = fid;
        setCommunicationSettings(communicationSettings);
        this.permissions = permissions;
    }

    private void setCommunicationSettings(byte cs) {
        if ((cs & (byte) 0x01) == (byte) 0x00) this.communicationSettings = Util.PLAIN_COMMUNICATION;
        if ((cs & (byte) 0x03) == (byte) 0x01) this.communicationSettings = Util.PLAIN_COMMUNICATION_MAC;
        if ((cs & (byte) 0x03) == (byte) 0x03) this.communicationSettings = Util.FULLY_ENCRYPTED;
    }

    public byte getFileID() {
        return fileID;
    }

    public byte getCommunicationSettings() {
        return communicationSettings;
    }

    public short getSize() {
        return size;
    }

    public void setSize(short s) {
        this.size = s;
    }

    public DirectoryFile getParent() {
        return parentFile;
    }

    public void setWaitingForTransaction() {
        getParent().setWaitForTransaction(getFileID());
    }

    public void resetWaitingForTransaction() {
        getParent().resetWaitForTransaction(getFileID());
    }

    /**
     * Checks wich access permissions are offered for the given key.
     *
     * @param keyNumber
     * @return
     */
    public byte getAccessRight(byte keyNumber) {
        if (((permissions[1]) & ((byte) 0x0F)) == (byte) keyNumber) return ((byte) 4);//CHANGE
        if (((permissions[1]) & ((byte) 0x0F)) == (byte) 0x0E) return ((byte) 4);//CHANGE
        if (((permissions[1]) & ((byte) 0xF0)) == (byte) (keyNumber << 4)) return ((byte) 3);//W&R
        if (((permissions[1]) & ((byte) 0xF0)) == (byte) 0xE0) return ((byte) 3);//W&R
        if (((permissions[0]) & ((byte) 0x0F)) == (byte) keyNumber) return ((byte) 2);//WRITE
        if (((permissions[0]) & ((byte) 0x0F)) == (byte) 0x0E) return ((byte) 2);//WRITE
        if (((permissions[0]) & ((byte) 0xF0)) == (byte) (keyNumber << 4)) return ((byte) 1);//READ
        if (((permissions[0]) & ((byte) 0xF0)) == (byte) 0xE0) return ((byte) 1);//READ
//		if((((byte)(keyNumber << 4))&(permissions[1])& ((byte)0x0F))==(byte)0xFF)return((byte) 3);//W&R
//		if((((byte)keyNumber)&(permissions[0])& ((byte)0x0F))==(byte)0xFF)return((byte) 2);//WRITE
//		if((((byte)(keyNumber << 4))&(permissions[0])& ((byte)0x0F))==(byte)0xFF)return((byte) 1);//READ	
        return ((byte) 0);
    }

    public boolean hasWriteAccess(byte keyNumber) {

        if (((permissions[0]) & ((byte) 0x0F)) == (byte) keyNumber) return (true);//WRITE
        if (((permissions[0]) & ((byte) 0x0F)) == (byte) 0x0E) return (true);//WRITE
        if (((permissions[1]) & ((byte) 0xF0)) == (byte) (keyNumber << 4)) return (true);//W&R
        if (((permissions[1]) & ((byte) 0xF0)) == (byte) 0xE0) return (true);//W&R
        return (false);
    }

    public boolean hasReadAccess(byte keyNumber) {
        if (((permissions[0]) & ((byte) 0xF0)) == (byte) (keyNumber << 4)) return (true);//READ
        if (((permissions[0]) & ((byte) 0xF0)) == (byte) 0xE0) return (true);//READ
        if (((permissions[1]) & ((byte) 0xF0)) == (byte) (keyNumber << 4)) return (true);//W&R
        if (((permissions[1]) & ((byte) 0xF0)) == (byte) 0xE0) return (true);//W&R
        return (false);
    }

    public byte[] getPermissions() {
        return permissions;
    }

}
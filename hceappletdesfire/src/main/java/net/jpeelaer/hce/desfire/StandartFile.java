package net.jpeelaer.hce.desfire;


public class StandartFile extends File {

	/**
	 * Data stored in the file
	 */
	protected byte[] data;
		
	/**
	 * Constructor for an empty file setting  the maximum size
	 * 
	 */
	public StandartFile(byte fid, DirectoryFile parent,byte communicationSettings,byte[] accessPermissions, short maxSize) {
		super(fid,parent,communicationSettings,accessPermissions);	
		data = new byte[maxSize];
		setSize((short) 0);
		parent.addFile(this);
	}
	
	public byte[] getData() {
		return data;
	}
	
	public short getMaxSize() {
		return (short) data.length;
	}
	
	/**
	 * 	Read an array from the file 
	 */
	public byte[] readArray(short offset, short length, short s){
		byte[] bytesRead=new byte[length];
		for (short i = 0; i < length; i++) {
			bytesRead[(short)(s+i)]=data[(short)(offset+i)];				
		}
		return(bytesRead);
	}
	
	/**
	 * 	Write an array in the file
	 */
	public void writeArray(byte[] data, short offset, short length){
		
		for (short i = 0; i < length; i++) {
			this.data[(short)(offset+i)]=data[i];				
		}
		setSize(Util.max(getSize(),(short) (offset+length)));
	}
	
}
	

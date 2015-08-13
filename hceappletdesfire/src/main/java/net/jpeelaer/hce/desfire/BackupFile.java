package net.jpeelaer.hce.desfire;

import org.kevinvalk.hce.framework.IsoException;


public class BackupFile extends StandartFile {

	/**
	 * Temporary data stored in the file
	 */
	private byte[] uncommitedData;
	
	private short uncommitedSize;
		
	/**
	 * Constructor for an empty file setting  the maximum size
	 * 
	 */
	public BackupFile(byte fid, DirectoryFile parent,byte communicationSettings,byte[] accessPermissions, short maxSize) {
		super(fid,parent,communicationSettings,accessPermissions,maxSize);
		uncommitedData=this.data;
	}
	
	public byte[] getData() {
		return data;
	}
	
	public short getMaxSize() {
		return (short) data.length;
	}
	
	public short getUncommitedSize(){
		return uncommitedSize;
	}
	
	public void setUncommitedSize(short newUncommitedSize){
		this.uncommitedSize=newUncommitedSize;
	}
	
	/**
	 * 	Write an array in the temporary file
	 */
	public void writeArray(byte[] data, short offset, short length){
		if((short)(offset+length)>getMaxSize()) IsoException.throwIt(Util.BOUNDARY_ERROR);
		getParent().setWaitingForTransaction();
		
		//copy new data in temporal file
		for (short i = 0; i < length; i++) {
			this.uncommitedData[(short)(offset+i)]=data[i];				
		}
		setUncommitedSize(Util.max(getUncommitedSize(),(short) (offset+length)));
	}
	
	/**
	 * 	Last uncommited write operations take place
	 */
	public void commitTransaction(){
		getParent().resetWaitingForTransaction();//notifies to the DF there are not transactions waiting anymore 
		this.data=uncommitedData;
		setSize(getUncommitedSize());
	}
	
	/** 
	 * 		Last uncommited write operations are cancelled and the uncommited record
	 * 	is reset to the current data of the file 
	 * 		
	 */
	public void abortTransaction(){
		getParent().resetWaitingForTransaction();//notifies to the DF there are not transactions waiting anymore
		this.uncommitedData=getData();
		setUncommitedSize(getSize());
	}
}
	

package net.jpeelaer.hce.desfire;

import org.kevinvalk.hce.framework.IsoException;


public class IndexFile extends File{

	/**
	 * 	Data stored in the file
	 */
	private byte[] data;
	/**
	 *  Current size of data stored in file
	 */
	short size;
	
	/**
	 * 	Size in bytes of each record
	 */
	short recordSize;
	
	public IndexFile(byte fid, DirectoryFile parent, short recordSize, short maxSize) {
		super(fid,parent);
		this.data = new byte[(short)(maxSize*recordSize)];
		this.size = (short) 0;
		this.recordSize=recordSize;
		parent.addFile(this);
	}

	public byte[] getData() {
		return data;
	}
	
	public short getCurrentSize() {
		return size;
	}
	
	public short getMaxSize() {
		return (short) data.length;
	}
	
	/**
	 * Delete the information about an specific application
	 */
	public void deleteRecord(short index){
		for (short i = (short)(index*recordSize); i <(short)((index+1)*recordSize); i++) {
			this.data[i]=(byte)0x00;						
		}
		size--;	
	}
	
	/**
	 * 	Write the information of a new application installed in the card
	 */
	public void writeRecord(short index, byte[] newData) {
		 if(newData.length!=recordSize) IsoException.throwIt((short)0xBB01); 
		size++;
		for (short i = (short)(index*recordSize); i <(short)((index+1)*recordSize); i++) {
			this.data[i]=newData[(short)(i-index*recordSize)];						
		}		
	}
	
	/**
	 * Read the information about an specific application
	 */
	public byte[] readValue(short index){
		byte[] value= new byte[recordSize];
		for (short i = 0; i < recordSize; i++) {
			value[i]=data[(short)(i+index*recordSize)];
		}
		return(value);
	}	
}

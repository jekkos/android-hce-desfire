package net.jpeelaer.hce.desfire;
import org.kevinvalk.hce.framework.IsoException;

/**
 * 		Definition of a file for multiple sotrage of structural data where, 
 * 	once the file is fill, it's possible to overwrite the oldest record
 * 	with the latest written one.
 * 
 * 	@author Jorge Prado
 *
 */
public class CyclicRecord extends File{
	
	
	
	/**
	 * Data stored in the file
	 */
	private byte[] data;
	
	/**
	 * Temporary record where the new uncommited record is stored
	 * 
	 * @note It could only allow one record in it. If two write operations
	 * are done before commitment, the second overwrites the first in this 
	 * record.
	 */
	private byte[] uncommitedRecord;
	
	
	/**
	 *  Position of the currently last written record
	 */
	short nextToWrite;
	
	
	
	/**
	 * 	Maximum number of bytes allowed in the file
	 */
	short maxSize;
	
	/**
	 * 	Number of bytes of each record
	 */
	short recordSize;

	/**
	 * 		Notifies that a ClearRecordFile command has been called so
	 *  writte accesses will be blocked and after a CommitTransaction
	 *  all records will be deleted. 
	 */
	private boolean waitingToClearFile;
	
	
	
	public CyclicRecord(byte fid, DirectoryFile parent,byte communicationSettings,byte[] accessPermissions, short recordSize, short maxSize) {
		super(fid,parent,communicationSettings,accessPermissions);
		this.data = new byte[(short)(maxSize*recordSize)];
		this.nextToWrite = (short) 0;
		this.recordSize=recordSize;
		this.maxSize=maxSize;
		this.uncommitedRecord=new byte[recordSize];
		parent.addFile(this);
	}
	
	public short getNextToWrite() {
			return nextToWrite;
	}
	
	public short getMaxSize() {
		return (short) data.length;
	}
	
	/**
	 * 		Notifies that the file will be cleared in the next CommitTransaction
	 * 	and tell it to the application
	 */
	public void deleteRecord(){
		//No se puede borrar hasta que la transaccion se compromete
		getParent().setWaitingForTransaction();
		this.waitingToClearFile=true;
	}
	
	/**
	 * Set the file and all its data to the empty state
	 */
	public void deleteRecords(){
		for (short i = 0; i < data.length; i++) {
			data[i]=0;
		}
		nextToWrite=0;
		
	}
	
	/**
	 * 	Write data in the temporary record
	 *
	 * 	@exception 	Throws BOUNDARY_EXCEPTION if the data is
	 *				bigger than the record size
	 */
	public void writeRecord(byte[] newData) {
		if(newData.length>=recordSize) IsoException.throwIt((short)Util.BOUNDARY_ERROR);
		if(waitingToClearFile==true)IsoException.throwIt((short)Util.PERMISSION_DENIED);
		getParent().setWaitingForTransaction();
		
		// copy new data
		for (short i = 0; i < recordSize; i++) {
			this.uncommitedRecord[i]=newData[i];
			if(i>=newData.length)this.uncommitedRecord[i]=(byte)0x00;
		}		
	}
	
	/**
	 * 		Write data in the temporary record with an offset from 
	 * 	the beggining of the record
	 * 	
	 * 	@exception 	Throws BOUNDARY_EXCEPTION if the data's length plus 
	 * 				the offset is bigger than the record size 
	 */
	public void writeRecord(byte[] data,short offset) {
		if(offset==0)writeRecord(data);
		writeRecord(Util.concatByteArray(Util.getZeroArray(offset), data));
	}
	
	/**
	 * 		The last write operation takes place so a new record is created and 
	 * 	filled with the content of the temporary record or all the records are 
	 * 	erased if the ClearRecordFile command was called.
	 * 
	 * 	@note	If all the records are filled and, even so, the file is full,
	 * 			the oldest records is overwritten with the new one
	 */
	public void commitTransaction(){
		getParent().resetWaitingForTransaction();
		if(waitingToClearFile==true){
			waitingToClearFile=false;
			deleteRecords();
		} else{
			if(nextToWrite==maxSize)nextToWrite=0; //the pointer is reset so the overwrite starts
			for (short i = (short)(nextToWrite*recordSize); i <(short)((nextToWrite+1)*recordSize); i++) {
				this.data[i]=uncommitedRecord[i];
				nextToWrite++;//update lastWritten
			}
		}
	}
	
	/**
	 * The last write operation over the temporary file is cancelled
	 */
	public void abortTransaction(){
		getParent().resetWaitingForTransaction();
	}
	
	//DEPRECATED
	public byte[] readData(short offset, short length, byte offsetOut){
		byte[] bytesRead=new byte[length];
		for (short i = 0; i < length; i++) {
			bytesRead[(short)(offsetOut+i)]=data[(short)(offset+i)];				
		}
		return(bytesRead);
	}
	
	/**
	 * 	Read the record in the backPosition(counting from the last record's position
	 *
	 *	@note	If backPosition=0 the last written record is readed
	 *	@note 	It can be possible to read records that haven't been written if the whole
	 *			file hasn't been filled and the backposition is higher than the number of 
	 *			records written.
	 */
	public byte[] readRecord(byte backPosition){
		byte[] bytesRead=new byte[recordSize];
		for (short i = 0; i < bytesRead.length; i++) {
			if(backPosition>nextToWrite){
				bytesRead[i]=data[(short)((maxSize-(backPosition-nextToWrite))*recordSize)];
			}
			bytesRead[i]=data[(short)((nextToWrite-backPosition)*recordSize)];
		}
		return bytesRead;
	}
	
	
	
	
	
	
}
package net.jpeelaer.hce.desfire;

import org.kevinvalk.hce.framework.IsoException;



public class ValueRecord extends File {

	
	/**
	 * Data stored in the file
	 */
	private Value value;
	
	/**
	 * Higher value the file could have
	 */
	private Value upperLimit;
	
	/**
	 * Lower value the file can have
	 */
	private Value lowerLimit;
	
	/**
	 * Notifies the limited credit option is activated
	 */
	boolean limitedCreditEnabled;
	
	/**
	 * Notifies there is free read access to the file
	 */
	boolean freeGetValueEnabled;
	
	/**
	 * 	Temporary record where the new uncommited value is stored
	 * 
	 * 	@note	If two write operations are done before commitment,
	 *  the second overwrites the first in this record.
	 */
	Value uncommitedValue;

	
	public ValueRecord(byte fid, DirectoryFile parent,byte communicationSettings,byte[] accessPermissions, Value lowerLimit,Value upperLimit,Value value,byte limitedCreditEnabled) {
		super(fid,parent,communicationSettings,accessPermissions);
		setSize((byte) 4);
		this.upperLimit =upperLimit;
		this.lowerLimit = lowerLimit;
		this.value=value;
		if((limitedCreditEnabled & (byte)0x01)==(byte)0x01)this.limitedCreditEnabled=true;
		else this.limitedCreditEnabled=false;
		if((limitedCreditEnabled & (byte)0x02)==(byte)0x02)this.freeGetValueEnabled=true;
		else this.freeGetValueEnabled=false;
		this.uncommitedValue=this.value;
		parent.addFile(this);
	}
	
	public Value getValue() {
			return value;
	}
	
	public Value getLowerLimit() {
		return lowerLimit;
	}
	
	public Value getUpperLimit() {
		return upperLimit;
	}
	
	/**
	 * 	Check if the value is between the upper limit and the lower limit
	 */
	public boolean valueOutBounds(Value value){
		if(value.compareTo(lowerLimit)==2)return true;
		if(value.compareTo(upperLimit)==1)return true;
		return false;
	}
	
	/**
	 * 	Add credit to the value in the uncommited record
	 * 
	 * 	@exception Throws BOUNDARY_ERROR if the limits are exceeded
	 */
	public void addCredit(Value credit){
		Value newValue=this.uncommitedValue;
		if(newValue.addValue(credit)==false) IsoException.throwIt((short)Util.BOUNDARY_ERROR);//Exception if the operation finishes with overflow
		if(valueOutBounds(newValue)==true) IsoException.throwIt((short)Util.BOUNDARY_ERROR);
		this.uncommitedValue=newValue;
		getParent().setWaitingForTransaction();
		return ;
	}
	
	/**
	 * 	Substract credit to the value in the uncommited record
	 * 
	 * 	@exception Throws BOUNDARY_ERROR if the limits are exceeded
	 */
	public void decDebit(Value debit){
		Value newValue=this.uncommitedValue;
		if(newValue.subtractValue(debit)==false) IsoException.throwIt((short)Util.BOUNDARY_ERROR);
		if(valueOutBounds(newValue)==true) IsoException.throwIt((short)Util.BOUNDARY_ERROR);
		this.uncommitedValue=newValue;
		getParent().setWaitingForTransaction();
		return;
	}
	
	/**
	 * The value is updated to the uncommited one
	 */
	public void commitTransaction(){
		getParent().resetWaitingForTransaction();
		this.value=uncommitedValue;
	}
	
	/**
	 * The uncommited value is deleted
	 */
	public void abortTransaction(){
		getParent().resetWaitingForTransaction();
		this.uncommitedValue=this.value;
	}
	
	
}
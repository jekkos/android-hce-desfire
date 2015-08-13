package net.jpeelaer.hce.desfire;

import org.kevinvalk.hce.framework.IsoException;


public class Value {
	
	/**
	 * Byte array representation of a signed integer
	 */
	private byte[] value;
	
	/**
	 * Constructor for the class
	 */
	public Value(byte[] value){
		if(value.length!=4)IsoException.throwIt((short)Util.WRONG_VALUE_ERROR);
		this.value=value;
		
	}
	
	public byte[] getValue(){
		return this.value;
	}
	
	/**
	  * Compares this value to another
	  * @return 1 if higher // 2 if lower //0 if equal
	  * @note Java uses 2-complement
	  */
	public byte compareTo(Value b){
		if(isPositive(getValue())){
			if(!isPositive(b.getValue()))return 1;
			else return compareAbsoluteValueTo(b);
		}
		else{
			if(isPositive(b.getValue())) return 2;
			else return compareAbsoluteValueTo(b);
		}
	}
	
	/**
	  * Compares this value to another without sign
	  * @return 1 if higher // 2 if lower //0 if equal
	  */
	public byte compareAbsoluteValueTo(Value b){
		byte a1,b1;
		for (byte i= 0;i< 4; i++) {
			a1=getValue()[i];
			b1=b.getValue()[i];
			if(a1>b1)return 1;
			if(a1<b1)return 2;
		}
		return 0;
	}
	
	/**
	 * Makes the sum with this value and the given
	 * 
	 * @param b
	 * @return True if the operation hasn't overflow
	 */
	public boolean addValue(Value b){
		byte sum;
		boolean overflow=false;
		for (byte i = 3; i>=0 ; i--) {
			sum=(byte)(getValue()[i]+b.getValue()[i]);
			if(overflow==true){
				overflow=hasOverflowSum(getValue()[i],b.getValue()[i],sum);
				sum++;
				this.value[i]=sum;
			}
			else {
				overflow=hasOverflowSum(getValue()[i],b.getValue()[i],sum);
				this.value[i]=sum;
			}
		}
		return !overflow;
	}
	
	/**
	 * Adds the 2-complementary of the given value
	 * @param b
	 * @return True if there is not overflow
	 */
	public boolean subtractValue(Value b){
		byte[] compBBytes=new byte[4];
		for (byte i = 0; i < 4; i++) {
			compBBytes[i]=(byte)(b.getValue()[i]^(byte)0xFF);
		}
		Value compB=new Value(compBBytes);
		compB.addValue(new Value(new byte[]{(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01}));
		return !this.addValue(compB);
	}
	
	/**
	 * Checks if a sum has terminated with overflow
	 * @param a
	 * @param b
	 * @param sum
	 * 			Result of the sum a+b
	 * @return True if the sum has overflow
	 */
	public boolean hasOverflowSum(byte a,byte b,byte sum){
		if(isPositive(a)&& isPositive(b)){
			if(isPositive(sum))return false;
			else return true;
		}
		if(!isPositive(a)&&!isPositive(b)){
			if(!isPositive(sum))return false;
			else return true;
		}
		else return false;
	}

	 /**
	  * Checks if the integer is positive or 0.
	  * @param 	a
	  * 		Byte array representation of a signed integer
	  */
	 private boolean isPositive(byte[]a){
		 return((a[0])&((byte)0x80))==(byte)0x00;
	 }
	 /**
	  * Checks if a byte is positive or 0
	  * @param  a
	  * 		Byte 2-complementary
	  */
	 private boolean isPositive(byte a){
		 return((a)&((byte)0x80))==(byte)0x00;
	 }

}

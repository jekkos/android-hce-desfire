package org.kevinvalk.hce.framework;

public class IsoException extends RuntimeException 
{
	private static final long serialVersionUID = 2363777434863899376L;
	short errorCode;
	
	public IsoException(short errorCode)
	{
		super("IsoException");
		this.errorCode = errorCode;
	}
	
	public short getErrorCode()
	{
		return errorCode;
	}
	
	public static void throwIt(short sw) throws IsoException
	{
		throw new IsoException(sw);
	}

}
package org.kevinvalk.hce.framework.apdu;

import org.spongycastle.util.Arrays;

public class Apdu
{
	private byte[] apdu;
	
	public Apdu()
	{
		this(null);
	}
	
	public Apdu(byte[] apdu)
	{
		this.apdu = apdu;
	}
	
	public Apdu(byte[] apdu, int length)
	{
		this(Arrays.copyOf(apdu, length));
	}
	
	/**
	 * Get the raw APDU buffer (everything)
	 * 
	 * @return
	 */
	public byte[] getBuffer()
	{
		return apdu;
	}
}

package org.kevinvalk.hce.framework.apdu;

import org.kevinvalk.hce.framework.Iso7816;
import org.kevinvalk.hce.framework.IsoException;
import org.spongycastle.util.Arrays;

import struct.JavaStruct;
import struct.StructClass;
import struct.StructException;
import struct.StructField;

@StructClass
public class ResponseApdu extends Apdu
{
	@StructField(order = 0)
	public byte[] data;
		
	@StructField(order = 1)
	public short sw;

	// FIXME: Introduced for jmrt port
	public int length = 0;
	
	public ResponseApdu(short status)
	{
		this(new byte[0], status);
	}
	
	public ResponseApdu(byte[] data)
	{
		this(data, Iso7816.SW_NO_ERROR);
	}
	
	public ResponseApdu(Apdu apdu)
	{
		try
		{
			JavaStruct.unpack(this, apdu.getBuffer());
		}
		catch (StructException e)
		{
			IsoException.throwIt(Iso7816.SW_INTERNAL_ERROR);
		}
	}
	
	public ResponseApdu(byte[] data, short status)
	{
		if (data == null)
			data = new byte[0];
		this.data = data;
		this.sw = status;
	}
	
	public ResponseApdu(int size)
	{
		this.data = new byte[size];
	}
	
	public ResponseApdu(byte[] data, int size)
	{
		this(Arrays.copyOfRange(data, 0, size));
	}
	
	public ResponseApdu(byte[] data, int size, short status)
	{
		this(Arrays.copyOfRange(data, 0, size), status);
	}
	
	@Override
	public byte[] getBuffer()
	{
		byte[] bytes = null;
		try
		{
			bytes = JavaStruct.pack(this);
		}
		catch (StructException e)
		{
			IsoException.throwIt(Iso7816.SW_INTERNAL_ERROR);
		}
		return bytes;
	}
}

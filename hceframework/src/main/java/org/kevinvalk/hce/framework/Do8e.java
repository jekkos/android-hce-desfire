package org.kevinvalk.hce.framework;

import struct.ArrayLengthMarker;
import struct.JavaStruct;
import struct.StructClass;
import struct.StructException;
import struct.StructField;

@StructClass
public class Do8e
{
	public static final byte DO_8E = (byte) 0x8E;
	
	@StructField(order = 0)
	public byte do8e = DO_8E;
	
	@StructField(order = 1)
	@ArrayLengthMarker(fieldName = "checksum")
	public byte length;
	
	@StructField(order = 2)
	public byte[] checksum;
	
	
	public Do8e(byte [] buffer)
	{
		try
		{
			JavaStruct.unpack(this, buffer);
		}
		catch(StructException e)
		{
			IsoException.throwIt(Iso7816.SW_INTERNAL_ERROR);
		}
	}
}

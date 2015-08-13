package org.kevinvalk.hce.framework;

import org.spongycastle.util.Arrays;

import struct.ArrayLengthMarker;
import struct.JavaStruct;
import struct.StructClass;
import struct.StructException;
import struct.StructField;

@StructClass
public class Do87
{
	public enum Type
	{
		NO_INDICATION( (byte) 0x00),
		HAS_PADDING( (byte) 0x01),
		NO_PADDING( (byte) 0x02);
		
		private final byte type;
		Type(byte type){this.type = type;}
		public byte getValue(){return type;}
	}
	
	public static final byte DO_87 = (byte) 0x87;
	
	@StructField(order = 0)
	public byte do87 = DO_87;
	
	@StructField(order = 1)
	@ArrayLengthMarker(fieldName = "data")
	public byte length;
		
	@StructField(order = 2)
	public byte[] data;
	
	public Type getType()
	{
		if (data != null && data.length >= 1)
			return Type.values()[data[0]];
		return Type.NO_INDICATION;
	}
	
	public void setType(Type type)
	{
		if (data == null || data.length <= 0)
			data = new byte[1];
		data[0] = type.getValue();
	}
	
	public byte[] getData()
	{
		return Arrays.copyOfRange(data, 1, length);
	}
	
	public void setData(byte[] data)
	{
		Type type = getType();
		this.data = new byte[data.length+1];
		setType(type);
		System.arraycopy(data, 0, this.data, 1, data.length);
	}
	
	public int getLength()
	{
		return length + 2;
	}
	
	public Do87(byte [] buffer)
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

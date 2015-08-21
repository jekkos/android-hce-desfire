package org.kevinvalk.hce.framework.apdu;

import java.util.Arrays;

import org.kevinvalk.hce.framework.Iso7816;
import org.kevinvalk.hce.framework.IsoException;
import org.kevinvalk.hce.framework.Util;

import struct.JavaStruct;
import struct.StructClass;
import struct.StructException;
import struct.StructField;

@StructClass
public class CommandApdu extends Apdu
{
	@StructField(order = 0)
	public byte cla;
	
	@StructField(order = 1)
	public byte ins;
	
	@StructField(order = 2)
	public byte p1;
	
	@StructField(order = 3)
	public byte p2;
	
	@StructField(order = 4)
	public byte[] body;
	
	// State variables
	private int lc;
	private int le;
	private byte[] cdata = null;

	public CommandApdu(byte[] buffer, int length)
	{
		this(Arrays.copyOf(buffer, length));
	}
	
	public CommandApdu(byte[] buffer)
	{
		this(new Apdu(buffer));
	}


	
	public CommandApdu(Apdu apdu)
	{
		try
		{
			body = new byte[apdu.getBuffer().length-4];
			JavaStruct.unpack(this, apdu.getBuffer());
			
			// Parse Lc and Le and the body (if Lc is short then Le is short, if Lc is extended then Le is extended)
			if(body.length > 0)
			{
				// We running extended or not
				boolean extended = (body[0] == 0x0 && body.length >= 3); // If extended flag is true, we expect at least 2 more bytes
				int size = (extended ? 3 : 1); //1
				int offset = (extended ? 1 : 0); //0
				int lSize = (extended ? 2 : 1); //1
				
				// Parse the body
				if (body.length == size)
				{
					// We only have Le
					le = (int) Util.getSomething(body, offset, lSize);
				}
				else
				{
					// We have Lc
					lc = (int) Util.getSomething(body, offset, lSize);
					
					// Check if we have Le field
					if (body.length - lc - size > 0)
						le = (int) Util.getSomething(body, size + lc, lSize);
				}
				
				// Extract the Data if we have some
				if (lc >= 1)
					cdata = Arrays.copyOfRange(body, size, size + lc);
			}
			else
			{
				// We have no body!
				cdata = new byte[0];
				le = 0;
				lc = 0;
			}
		}
		catch (StructException e)
		{
			IsoException.throwIt(Iso7816.SW_INTERNAL_ERROR);
		}
	}
	
	/**
	 * Get the length of the body
	 * @return
	 */
	public int getLc()
	{
		return lc;
	}
	
	/**
	 * Get the expected length
	 * 
	 * @return
	 */
	public int getLe()
	{
		return le;
	}
	
	/**
	 * Gets the command data
	 * @return
	 */
	public byte[] getData()
	{
		return cdata;
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

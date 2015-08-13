package org.kevinvalk.hce.framework.apdu;

import org.kevinvalk.hce.framework.Do87;
import org.kevinvalk.hce.framework.Do8e;
import org.spongycastle.util.Arrays;

public class SecureApdu
{
	public static CommandApdu unwrapCommandApdu(CommandApdu apdu)
	{
		// Default info easy to get
		byte cla = apdu.cla;
		byte ins = apdu.ins;
		byte p1 = apdu.p1;
		byte p2 = apdu.p2;
		int lc = apdu.getLc();
		
		// Check if we have data
		byte[] body = apdu.getData();
		if (body.length >= 1)
		{
			int offset = 0;
			
			// Check for DO87
			if (body[offset] == Do87.DO_87)
			{
				Do87 do87 = new Do87(body);
				offset += do87.getLength(); 
			}
			
			// Check for DO97
			if (body[offset] == (byte) 0x97)
			{
				
			}
			
			// Check for DO8E
			if (body[offset] == Do8e.DO_8E)
			{
				Do8e do8e = new Do8e(Arrays.copyOfRange(body, offset, lc));
			}
		}
		
		
		return null;
		
	}

}

package org.kevinvalk.hce.framework;

import java.io.IOException;

import org.kevinvalk.hce.framework.apdu.Apdu;
import org.kevinvalk.hce.framework.apdu.CommandApdu;
import org.kevinvalk.hce.framework.apdu.ResponseApdu;

public class AppletThread implements Runnable 
{
	private volatile boolean isRunning = false;
	Applet applet = null;
	Apdu firstApdu = null;
	TagWrapper tag = null;

	public AppletThread()
	{
		
	}
	
	public AppletThread(Applet applet, TagWrapper tag, Apdu firstApdu)
	{
		this.applet = applet;
		this.tag = tag;
		this.firstApdu = firstApdu;
	}
	
	public synchronized void stop()
	{
		isRunning = false;
		try
		{
			if (tag != null)
				tag.close();
		}
		catch(Exception e)
		{
			Thread.currentThread().interrupt();
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public synchronized boolean setApplet(Applet applet, TagWrapper tag)
	{
		// If we are busy then deny
		if(isRunning)
			return false;
		
		// Select the new one
		this.applet = applet;
		this.tag = tag;
		
		return true;
	}
	
	public synchronized void setApdu(Apdu apdu)
	{
		this.firstApdu = apdu;
	}

	@Override
	public void run()
	{
		// Initialize
		Apdu apdu = firstApdu;
		firstApdu = null;
		isRunning = true;
		
		// Lets start handling all incoming traffic
		while(isRunning)
		{
			try
			{
				try
				{
					// Let the applet handle the APDU
					ResponseApdu response = applet.process(new CommandApdu(apdu));
					
					// If we have a response send it, else just wait
					if (response != null)
						apdu = sendApdu(tag, response);
					else
						apdu = getApdu(tag);
				}
				catch(IsoException iso)
				{
					// We got an soft error so send response to our terminal
					apdu = sendApdu(tag, new ResponseApdu(iso.getErrorCode()));
				}
			}
			catch(Exception e)
			{
				// We got a hard error so stop this
				Util.d("THREAD", "Caught exception `%s` at %s", e.getMessage(), e.getStackTrace()[0].toString());
				isRunning = false;
				return;
			}
		}
		
		Util.d("THREAD", "Gracefull stop");
	}
	
	/**
	 * Sends an APDU to the terminal and waits for the next one
	 * 
	 * @param tag
	 * @param Apdu The APDU to send
	 * @return Apdu response
	 */
	public static Apdu sendApdu(TagWrapper tag, Apdu apdu) throws IOException
	{	
		if(apdu != null)
			Util.d("NFC", "Send apdu: %s", Util.toHex(apdu.getBuffer()));
		byte [] response = tag.transceive((apdu == null ? new byte[0] : apdu.getBuffer()));
		Util.d("NFC", "Recv apdu: %s", Util.toHex(response));
		return new Apdu(response);
	}
	
	/**
	 * Waits for a new APDU from the terminal
	 * 
	 * @param tag
	 * @return Apdu response
	 */
	public static Apdu getApdu(TagWrapper tag) throws IOException
	{
		return sendApdu(tag, null);
	}
}

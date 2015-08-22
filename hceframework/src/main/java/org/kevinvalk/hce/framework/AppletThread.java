package org.kevinvalk.hce.framework;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.IOException;

import org.kevinvalk.hce.framework.apdu.Apdu;
import org.kevinvalk.hce.framework.apdu.CommandApdu;
import org.kevinvalk.hce.framework.apdu.ResponseApdu;

public class AppletThread implements Runnable
{

	public static final String LAST_APDUS = "lastApdus";
	public static final String LAST_ERROR = "lastError";
	private final String TAG = getClass().getSimpleName();

	private volatile boolean isRunning = false;
	private Applet applet = null;
	private Apdu firstApdu = null;
	private TagWrapper tag = null;

	private PropertyChangeSupport propertyChangeSupport = new PropertyChangeSupport(this);
	private Apdu[] lastApdus;
	private Exception lastError;

	public AppletThread(PropertyChangeListener propertyChangeListener)
	{
		this.propertyChangeSupport.addPropertyChangeListener(propertyChangeListener);
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
				ResponseApdu responseApdu = null;
				try
				{
					// Let the applet handle the APDU
					responseApdu = applet.process(new CommandApdu(apdu));

					// If we have a response send it, else just wait
					if (responseApdu != null) {
						apdu = sendApdu(tag, responseApdu);
					} else {
						apdu = getApdu(tag);
					}

				}
				catch(IsoException iso)
				{
					// We got an soft error so send response to our terminal
					setLastError(iso);
					apdu = sendApdu(tag, new ResponseApdu(iso.getErrorCode()));

				}
			}
			catch(Exception e)
			{
				// We got a hard error so stop this
				setLastError(e);
				Util.d(TAG, "Caught exception `%s` at %s", e.getMessage(), e.getStackTrace()[0].toString());
				isRunning = false;
				return;
			}
		}
		
		Util.d(TAG, "Graceful stop");
	}

	private void setLastError(Exception lastError) {
		propertyChangeSupport.firePropertyChange(LAST_ERROR, this.lastError, this.lastError = lastError);
	}

	public Exception getLastError() {
		return lastError;
	}

	public Apdu[] getLastApdus() {
		return lastApdus;
	}

	public void setLastApdus(Apdu... lastApdus) {
		propertyChangeSupport.firePropertyChange(LAST_APDUS, this.lastApdus, this.lastApdus = lastApdus);
	}

	/**
	 * Sends an APDU to the terminal and waits for the next one
	 * 
	 * @param tag
	 * @param responseApdu The APDU to send
	 * @return Apdu response
	 */
	public Apdu sendApdu(TagWrapper tag, ResponseApdu responseApdu) throws IOException
	{	
		if(responseApdu != null) {
			Util.d(TAG, "<- %s", Util.toHex(responseApdu.getBuffer()));
		}
		byte [] response = tag.transceive((responseApdu == null ? new byte[0] : responseApdu.getBuffer()));
		Util.d(TAG, "-> %s", Util.toHex(response));
		Apdu commandApdu = new Apdu(response);
		setLastApdus(commandApdu, responseApdu);
		return commandApdu;
	}
	
	/**
	 * Waits for a new APDU from the terminal
	 * 
	 * @param tag
	 * @return Apdu response
	 */
	public Apdu getApdu(TagWrapper tag) throws IOException
	{
		return sendApdu(tag, null);
	}
}

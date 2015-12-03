package org.kevinvalk.hce.framework;

import java.beans.PropertyChangeListener;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

import org.kevinvalk.hce.framework.apdu.Apdu;
import org.kevinvalk.hce.framework.apdu.CommandApdu;
import org.kevinvalk.hce.framework.apdu.ResponseApdu;

public class HceFramework
{

	private Map<ByteBuffer, Applet> applets;
	private Applet activeApplet;
	private volatile AppletThread appletThread;

	public HceFramework() {
		this(null);
	}

	public HceFramework(PropertyChangeListener propertyChangeListener)
	{
		activeApplet = null;
		applets = new HashMap<ByteBuffer, Applet>();
		appletThread = new AppletThread(propertyChangeListener);
	}
	
	/**
	 * Registers an applet to the framework
	 * 
	 * @param applet
	 * @return boolean
	 */
	public boolean register(Applet applet)
	{
		// If it already contains this AID then just return true
		if (applets.containsKey(ByteBuffer.wrap(applet.getAid())))
			return true;
		return (applets.put(ByteBuffer.wrap(applet.getAid()), applet) == null);
	}

	/**
	 * Handles a new terminal
	 * 
	 * @param tag
	 * @return boolean
	 */
	public boolean handleTag(TagWrapper tag)
	{
		try
		{
			// Get the first APDU from the tag
			Apdu apdu = appletThread.getApdu(tag);

			// Keep trying
			do
			{
				CommandApdu commandApdu = new CommandApdu(apdu);
				
				// SELECT
				if (commandApdu.cla == Iso7816.CLA_ISO7816 && commandApdu.ins == Iso7816.INS_SELECT)
				{
					
					// We have an applet
					if (applets.containsKey(ByteBuffer.wrap(commandApdu.getData())))
					{					
						// If we have an active applet deselect it
						if (activeApplet != null)
							activeApplet.deselect();
											
						// Set the applet to active and select it
						activeApplet = applets.get(ByteBuffer.wrap(commandApdu.getData()));
						activeApplet.select();
						
						// Send an OK and start the applet
						Apdu response = appletThread.sendApdu(tag, new ResponseApdu(Iso7816.SW_NO_ERROR));
						
						// Stop current applet thread and wait just a bit
						appletThread.stop();
						Thread.sleep(100);
						
						// Set the applet to the active runnable
						appletThread.setApplet(activeApplet, tag);
						appletThread.setApdu(response);
						
						// Run it
						Thread thread= new Thread(appletThread);
						thread.setName("AppletThread");
						thread.start();
						
						// Stop trying
						return true;
					}
					else
					{
						// Something went wrong
						apdu = appletThread.sendApdu(tag, new ResponseApdu(Iso7816.SW_APPLET_SELECT_FAILED));
						continue;
					}
				}
				
				// This is as defined in the specifications
				// If we have an active applet let them process this commandApdu
				if (activeApplet != null) {
					apdu = appletThread.sendApdu(tag, activeApplet.process(commandApdu));
				} else {
					apdu = appletThread.sendApdu(tag, new ResponseApdu(Iso7816.SW_INS_NOT_SUPPORTED));
				}
			}
			while(true);
		}
		catch(Exception e)
		{
			return false;
		}
	}
}

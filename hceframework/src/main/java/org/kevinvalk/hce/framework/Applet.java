package org.kevinvalk.hce.framework;

import org.kevinvalk.hce.framework.apdu.CommandApdu;
import org.kevinvalk.hce.framework.apdu.ResponseApdu;


public abstract class Applet
{
	/**
	 * Processes an incoming command APDU
	 * 
	 * @param CommandApdu incoming APDU
	 * @return ResponseApdu outgoing APDU
	 */
	public abstract ResponseApdu process(CommandApdu apdu);
	
	
	/**
	 * To let you know you have been selected by a terminal
	 */
	public void select() {};
	
	/**
	 * To let you know you have been deselected by the system
	 */
	public void deselect() {};
	
	/**
	 * Get the applets name
	 * @return
	 */
	public abstract String getName();
	
	/**
	 * Get the application identifier for this applet
	 * @return
	 */
	public abstract byte[] getAid();
	

	/**
	 * Checks if this APDU is the selecting command for this Applet
	 * 
	 * @param apdu
	 * @return True when selecting APDU and for this Applet 
	 */
	public boolean selectingApplet(CommandApdu apdu)
	{
		if (apdu.cla == Iso7816.CLA_ISO7816 && apdu.ins == Iso7816.INS_SELECT && apdu.p1 == 0x04 && apdu.p2 == 0x0C)
			return Util.equal(apdu.getData(), getAid());
		return false;
	}
	
	/*** BEGIN DEBUG FUNCTIONS ***/
	public void d(String msg)
	{
		Util.d(getName(), msg);
	}
	
	public void d(String format, Object... args)
	{
		Util.d(getName(), format, args);
	}
	/*** END DEBUG FUNCTIONS ***/
}

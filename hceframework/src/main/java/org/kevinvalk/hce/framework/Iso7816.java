package org.kevinvalk.hce.framework;

public abstract class Iso7816
{
	static final byte DO87_START = (byte) 0x87;
	static final int DO87_TYPE = 0x00000080;
	static final byte DO87_BYTENO = 0x7F;
	static final byte DO87_END = 0x01;
	
	public static final int LE_MAX = 256;
    /**
     * Response status : No Error = (short)0x9000
     */
    public static final short SW_NO_ERROR = -28672;
    /**
     * Response status : Response bytes remaining = 0x6100
     */
    public static final short SW_BYTES_REMAINING_00 = 24832;
    /**
     * >Response status : Wrong length = 0x6700
     */
    public static final short SW_WRONG_LENGTH = 26368;
    /**
     * Response status : Security condition not satisfied = 0x6982
     */
    public static final short SW_SECURITY_STATUS_NOT_SATISFIED = 27010;
    /**
     * Response status : File invalid = 0x6983
     */
    public static final short SW_FILE_INVALID = 27011;
    /**
     * Response status : Data invalid = 0x6984
     */
    public static final short SW_DATA_INVALID = 27012;
    /**
     * Response status : Conditions of use not satisfied = 0x6985
     */
    public static final short SW_CONDITIONS_NOT_SATISFIED = 27013;
    /**
     * Response status : Command not allowed (no current EF) = 0x6986
     */
    public static final short SW_COMMAND_NOT_ALLOWED = 27014;
    /**
     * Response status : Applet selection failed = 0x6999;
     */
    public static final short SW_APPLET_SELECT_FAILED = 27033;
    /**
     * Response status : Wrong data = 0x6A80
     */
    public static final short SW_WRONG_DATA = 27264;
    /**
     * Response status : Function not supported = 0x6A81
     */
    public static final short SW_FUNC_NOT_SUPPORTED = 27265;
    /**
     * Response status : File not found = 0x6A82
     */
    public static final short SW_FILE_NOT_FOUND = 27266;
    /**
     * Response status : Record not found = 0x6A83
     */
    public static final short SW_RECORD_NOT_FOUND = 27267;
    /**
     * Response status : Incorrect parameters (P1,P2) = 0x6A86
     */
    public static final short SW_INCORRECT_P1P2 = 27270;
    /**
     * Response status : Incorrect parameters (P1,P2) = 0x6B00
     */
    public static final short SW_WRONG_P1P2 = 27392;
    /**
     * Response status : Correct Expected Length (Le) = 0x6C00
     */
    public static final short SW_CORRECT_LENGTH_00 = 27648;
    /**
     * Response status : INS value not supported = 0x6D00
     */
    public static final short SW_INS_NOT_SUPPORTED = 27904;
    /**
     * Response status : CLA value not supported = 0x6E00
     */
    public static final short SW_CLA_NOT_SUPPORTED = 28160;
    /**
     * Response status : No precise diagnosis = 0x6F00
     */
    public static final short SW_UNKNOWN = 28416;
    /**
     * Response status : Not enough memory space in the file  = 0x6A84
     */
    public static final short SW_FILE_FULL = 27268;
    /**
     * Response status : Card does not support logical channels  = 0x6881
     */
    public static final short SW_LOGICAL_CHANNEL_NOT_SUPPORTED = 26753;
    /**
     * Response status : Card does not support secure messaging = 0x6882
     */
    public static final short SW_SECURE_MESSAGING_NOT_SUPPORTED = 26754;
    /**
     * Response status : Warning, card state unchanged  = 0x6200
     */
    public static final short SW_WARNING_STATE_UNCHANGED = 25088;
    
	public static final short SW_REFERENCE_DATA_NOT_FOUND = (short) 0x6A88;
	
	public static final short SW_INTERNAL_ERROR = (short) 0x6d66;
	
    /**
     * APDU header offset : CLA = 0
     */
    public static final byte OFFSET_CLA = 0;
    /**
     * APDU header offset : INS = 1
     */
    public static final byte OFFSET_INS = 1;
    /**
     * APDU header offset : P1 = 2
     */
    public static final byte OFFSET_P1 = 2;
    /**
     * APDU header offset : P2 = 3
     */
    public static final byte OFFSET_P2 = 3;
    /**
     * APDU header offset : LC = 4
     */
    public static final byte OFFSET_LC = 4;
    /**
     * APDU command data offset : CDATA = 5
     */
    public static final byte OFFSET_CDATA = 5;
    /**
     * APDU command CLA : ISO 7816 = 0x00
     */
    public static final byte CLA_ISO7816 = 0;
    /**
     * APDU command INS : SELECT = 0xA4
     */
    public static final byte INS_SELECT = -92;
    /**
     * APDU command INS : EXTERNAL AUTHENTICATE = 0x82
     */
    public static final byte INS_EXTERNAL_AUTHENTICATE = -126;
    
    /**
     * P1
     */
    public static final byte P1_DF = 0x04;
    
    public static final byte P2_SELECT = 0x0C;
}

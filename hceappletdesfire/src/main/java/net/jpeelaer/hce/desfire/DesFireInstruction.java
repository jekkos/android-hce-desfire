package net.jpeelaer.hce.desfire;

import java.util.HashMap;
import java.util.Map;

public enum DesFireInstruction {

    //COMMAND CODES
    AUTHENTICATE((byte) 0x0A),
    AUTHENTICATE_ISO((byte)0x1A),
    AUTHENTICATE_AES((byte)0xAA),
    CHANGE_KEY_SETTINGS((byte)0x54),
    SET_CONFIGURATION((byte) 0x5C),
    CHANGE_KEY((byte) 0xC4),
    GET_KEY_VERSION((byte)0x64),
    CREATE_APPLICATION((byte) 0xCA),
    DELETE_APPLICATION((byte) 0xDA),
    GET_APPLICATION_IDS((byte)0x6A),
    FREE_MEMORY((byte)0x6E),
    GET_DF_NAMES((byte)0x6D),
    GET_KEY_SETTINGS((byte)0x45),
    SELECT_APPLICATION((byte) 0x5A),
    FORMAT_PICC((byte) 0xFC),
    GET_VERSION((byte)0x60),
    GET_CARD_UID((byte)0x51),
    GET_FILE_IDS((byte) 0x6F),
    GET_FILE_SETTINGS((byte)0xF5),
    CHANGE_FILE_SETTINGS((byte)0x5F),
    CREATE_STDDATAFILE((byte) 0xCD),
    CREATE_BACKUPDATAFILE((byte) 0xCB),
    CREATE_VALUE_FILE((byte) 0xCC),
    CREATE_LINEAR_RECORD_FILE((byte)0xC1),
    CREATE_CYCLIC_RECORD_FILE((byte)0xC0),
    DELETE_FILE((byte)0xDF),
    GET_ISO_FILE_IDS((byte)0x61),
    READ_DATA((byte) 0x8D),
    WRITE_DATA((byte) 0x3D),
    GET_VALUE((byte)0x6C),
    CREDIT((byte)0x0C),
    DEBIT((byte)0xDC),
    LIMITED_CREDIT((byte)0x1C),
    WRITE_RECORD((byte)0x3B),
    READ_RECORDS((byte)0xBB),
    CLEAR_RECORD_FILE((byte)0xEB),
    COMMIT_TRANSACTION((byte)0xC7),
    ABORT_TRANSACTION((byte)0xA7),
    CONTINUE((byte) 0xAF),

    //CommandToContinue
    NO_COMMAND_TO_CONTINUE((byte) 0x00);

    private static final Map<Byte, DesFireInstruction> INSTRUCTION_MAP =
            new HashMap<Byte, DesFireInstruction>();

    static {
        for (DesFireInstruction desFireInstruction : values()) {
            byte instruction = desFireInstruction.toByte();
            Byte aByte = Byte.valueOf(instruction);
            INSTRUCTION_MAP.put(aByte, desFireInstruction);
        }
    }

    private byte instruction;


    DesFireInstruction(byte instruction) {
        this.instruction = instruction;
    }

    public byte toByte() {
        return instruction;
    }

    public static DesFireInstruction parseInstruction(byte instruction) {
        return INSTRUCTION_MAP.get(instruction);
    }
}

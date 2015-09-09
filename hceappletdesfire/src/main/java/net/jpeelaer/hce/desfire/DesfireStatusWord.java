package net.jpeelaer.hce.desfire;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by jekkos on 8/17/15.
 */
public enum DesfireStatusWord {

    //Status Word
    OPERATION_OK((short)0x9100),
    NO_CHANGES((short)0x910C),
    OUT_OF_EEPROM_ERROR((short)0x910E),
    ILLEGAL_COMMAND_CODE((short)0x911C),
    INTEGRITY_ERROR((short)0x911E),
    NO_SUCH_KEY((short)0x9140),
    LENGTH_ERROR((short)0x917E),
    PERMISSION_DENIED((short)0x919D),
    PARAMETER_ERROR((short)0x919E),
    APPLICATION_NOT_FOUND((short)0x91A0),
    APPL_INTEGRITY_ERROR((short)0x91A1),
    AUTHENTICATION_ERROR((short)0x91AE),
    ADDITIONAL_FRAME((short)0x91AF),
    BOUNDARY_ERROR((short)0x91BE),
    PICC_INTEGRITY_ERROR((short)0x91C1),
    COMMAND_ABORTED((short)0X91CA),
    PICC_DISABLED_ERROR((short)0x91CD),
    COUNT_ERROR((short)0x91CE),
    DUPLICATE_ERROR((short)0x91DE),
    EEPROM_ERROR((short)0x91EE),
    FILE_NOT_FOUND((short)0x91F0),
    FILE_INTEGRITY_ERROR((short)0x91F1);

    private static final Map<Short, DesfireStatusWord> STATUS_WORD_MAP = new HashMap<>();

    static {
        for (DesfireStatusWord desfireStatusWord : values()) {
            short statusWord = desfireStatusWord.toShort();
            Short aStatusWord = Short.valueOf(statusWord);
            STATUS_WORD_MAP.put(aStatusWord, desfireStatusWord);
        }
    }

    private short statusWord;

    private DesfireStatusWord(short statusWord) {
        this.statusWord = statusWord;
    }

    public short toShort() {
        return statusWord;
    }

    public static DesfireStatusWord parseInstruction(byte instruction) {
        return STATUS_WORD_MAP.get(instruction);
    }


}

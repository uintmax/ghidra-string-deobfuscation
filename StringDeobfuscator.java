//Finds strings obfuscated by https://github.com/adamyaxley/Obfuscate and deobfuscates them.
//Check out the program in the obfuscated-example directory as an example target.
//Different compilers and optimization levels may require changes to the script.
//@author uintmax
//@category Deobfuscation
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

class Utils {
    public static List<Address> findPattern(String pattern, Memory mem) {
        var byteStrArr = pattern.split(" ");
        byte[] patternBytes = new byte[byteStrArr.length];
        byte[] mask = new byte[byteStrArr.length];
        for (int i = 0; i < byteStrArr.length; i++) {
            // Wildcard
            if (byteStrArr[i].equals("??")) {
                patternBytes[i] = 0x00;
                mask[i] = 0x00;
            } else {
                patternBytes[i] = (byte) Integer.parseInt(byteStrArr[i], 16);
                mask[i] = (byte) 0xFF;
            }
        }
        var patternLocations = new ArrayList<Address>();

        var blocks = mem.getBlocks();

        for (var block : blocks) {
            if (block.isExecute()) {
                var nextStartAddr = block.getStart();
                Address patternAddr;
                do {
                    patternAddr = mem.findBytes(nextStartAddr, block.getEnd(), patternBytes, mask, true,
                            TaskMonitor.DUMMY);
                    if (patternAddr != null) {
                        patternLocations.add(patternAddr);
                        nextStartAddr = patternAddr.add(patternBytes.length);
                    }
                } while (patternAddr != null);
            }
        }

        return patternLocations;
    }

    public static Instruction findFirstInstruction(String mnemonic, Address startAddr, Listing listing, boolean forward,
            int searchLimit) {
        Instruction currInstr = listing.getInstructionAt(startAddr);
        Instruction targetInstr = null;
        for (int iCounter = 0; iCounter < searchLimit; iCounter++) {
            if (currInstr.getMnemonicString().equals(mnemonic)) {
                targetInstr = currInstr;
                break;
            }
            currInstr = forward ? currInstr.getNext() : currInstr.getPrevious();
        }
        if (targetInstr == null) {
            throw new RuntimeException("Could not find " + mnemonic + " instruction");
        }

        return targetInstr;
    }
}

abstract class ObfuscatedString {

    public ObfuscatedString(Address addr, Program program) {
        this.program = program;
        this.listing = program.getListing();
        this.mem = program.getMemory();
        this.addr = addr;

        key = extractKey();
        len = extractLength();
        var obfuscatedBytes = extractObfuscatedStr(len);
        deobfuscatedStr = decryptObfStr(obfuscatedBytes, key);
    }

    protected Address addr;
    protected Program program;
    protected Listing listing;
    protected Memory mem;
    private byte[] key;
    private long len;
    private String deobfuscatedStr;

    protected abstract long extractLength();

    private List<Byte> extractObfuscatedStr(long strLen) {
        List<Byte> obfuscatedBytes = new ArrayList();
        Instruction movInstr = null;
        int searchLimit = 20;
        Address searchAddr = addr;
        do {
            /*- TODO: Add optional parameter to findFirstInstruction so we don't need this loop anymore */
            movInstr = Utils.findFirstInstruction("MOV", searchAddr, listing, false, 50);
            searchAddr = movInstr.getPrevious().getAddress();
            searchLimit--;
        }
        /*- TODO: Improve comparison, find something better than the string representation */
        while (!movInstr.getDefaultOperandRepresentation(0).startsWith("byte ptr [RSP") && searchLimit > 0);

        if (searchLimit == 0)
            throw new RuntimeException("Could not find MOV instruction");

        var currentMnemonic = movInstr.getMnemonicString();

        int bytesMoved = 0;

        // TODO: Improve length check
        while (currentMnemonic.equals("MOV") && bytesMoved != strLen
                && movInstr.getDefaultOperandRepresentation(0).startsWith("byte ptr [RSP")) {

            var b = Integer.decode(movInstr.getDefaultOperandRepresentation(1)).byteValue();
            obfuscatedBytes.add(b);

            movInstr = movInstr.getPrevious();
            currentMnemonic = movInstr.getMnemonicString();
            bytesMoved++;
        }
        return obfuscatedBytes.reversed();
    }

    private byte[] extractKey() {
        var keyInstruction = listing.getInstructionAt(addr);
        if (keyInstruction.getOperandType(1) != OperandType.SCALAR) {
            throw new RuntimeException("Could not extract decryption key, second operand of MOV is not a scalar");
        }
        var keyBytes = keyInstruction.getScalar(1).byteArrayValue();
        return keyBytes;
    }

    private String decryptObfStr(List<Byte> obfBytes, byte[] key) {

        byte[] deobfBytes = new byte[obfBytes.size()];
        for (int i = 0; i < obfBytes.size(); i++) {
            deobfBytes[i] = (byte) (obfBytes.get(i).byteValue() ^ key[7 - (i % 8)]);
        }

        return new String(deobfBytes, StandardCharsets.UTF_8);
    }

    public Address getAddress() {
        return addr;
    }

    public byte[] getKey() {
        return key;
    }

    public long getLength() {
        return len;
    }

    public String getDeobfuscatedStr() {
        return deobfuscatedStr;
    }

}

class ObfLongString extends ObfuscatedString {

    public ObfLongString(Address addr, Program program) {
        super(addr, program);
    }

    @Override
    protected long extractLength() {
        var cmpLenInstruction = Utils.findFirstInstruction("CMP", addr, listing, true, 20);

        if (cmpLenInstruction.getOperandType(1) != OperandType.SCALAR) {
            throw new RuntimeException("Second operand of CMP is not a scalar");
        }
        var len = cmpLenInstruction.getScalar(1).getValue();
        return len;
    }

}

class ObfShortString extends ObfuscatedString {

    public ObfShortString(Address addr, Program program) {
        super(addr, program);
    }

    @Override
    protected long extractLength() {
        return 0;
    }

}

public class StringDeobfuscator extends GhidraScript {

    public void run() throws Exception {
        /*-
         * Pattern for long string decryption:
         *  48 be ?? ?? ?? ?? ?? ?? ?? ??      MOV      RSI, <8_byte_decryption_key>
         *  48 89 c1                           MOV      RCX,RAX
         *  83 e1 07                           AND      ECX,0x7             // Modulo 8
         *  48 c1 e1 03                        SHL      RCX,0x3             // Multiply by 8 -> Next byte
         *  48 89 ??                           MOV      ??,RSI              // Register varies
         *  48 d3 ??                           SHR      ??,CL               // Register varies
         */
        final var longStringPattern = "48 be ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 83 e1 07 48 c1 e1 03 48 89 ?? 48 d3 ??";

        /*-
         * Pattern for short string decryption:
         *  48 be ?? ?? ?? ?? ?? ?? ?? ??       MOV     RSI, <8_byte_decryption_key>
         *  48 89 f2                            MOV     RDX,RSI
         *  48 d3 ea                            SHR     RDX,CL              // Next byte
         *  30 10                               XOR     byte ptr [RAX],DL
         */
        final var shortStringPattern = "48 be ?? ?? ?? ?? ?? ?? ?? ?? 48 89 f2 48 d3 ea 30 10";

        var longStringLocations = Utils.findPattern(longStringPattern, currentProgram.getMemory());
        var shortStringLocations = Utils.findPattern(shortStringPattern, currentProgram.getMemory());

        println("Long string patterns found: " + longStringLocations.size());
        println("Short string patterns found: " + shortStringLocations.size());

        var keyFormat = HexFormat.ofDelimiter(" ");
        List<ObfuscatedString> obfuscatedStrings = new ArrayList();
        // TODO: Catch exceptions
        for (var longStr : longStringLocations) {
            ObfuscatedString obfStr = new ObfLongString(longStr, currentProgram);
            obfuscatedStrings.add(obfStr);
        }

        for (var shortStr : shortStringLocations) {
            ObfuscatedString obfStr = new ObfShortString(shortStr, currentProgram);
            obfuscatedStrings.add(obfStr);
        }

        // TODO: Sort
        for (var obfStr : obfuscatedStrings) {
            println("Obfuscated string at " + obfStr.getAddress());
            println("\tKey: " + keyFormat.formatHex(obfStr.getKey()));
            println("\tLength: " + obfStr.getLength());
            println("\tDeobfuscated string: " + obfStr.getDeobfuscatedStr());
        }

    }

}

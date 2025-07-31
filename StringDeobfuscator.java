//TODO write a description for this script
//@author uintmax
//@category Deobfuscation
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.*;

public class StringDeobfuscator extends GhidraScript {

	private List<Address> findPattern(String pattern) {
		var bytes = pattern.split(" ");
		String parsablePattern = "";
		byte[] mask = new byte[bytes.length];
		for (int i = 0; i < bytes.length; i++) {
			if (bytes[i].equals("??")) {
				parsablePattern += "00 ";
				mask[i] = 0x00;
			} else {
				parsablePattern += bytes[i] + " ";
				mask[i] = (byte) 0xFF;
			}
		}
		var patternBytes = HexFormat.ofDelimiter(" ").parseHex(parsablePattern.stripTrailing());
		var patternLocations = new ArrayList<Address>();

		var mem = currentProgram.getMemory();
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

	public void run() throws Exception {
		/*-
		 * Pattern for long string decryption:
		 *    48 be ?? ?? ?? ?? ?? ?? ?? ?? 	MOV		RSI, <8_byte_decryption_key>
		 *    48 89 c1        					MOV		RCX,RAX
		 *    83 e1 07        					AND    	ECX,0x7		// Modulo 8
		 *    48 c1 e1 03     					SHL   	RCX,0x3		// Multiply by 8 -> Next byte
		 *    48 89 ??        					MOV   	??,RSI		// Register varies
		 *    48 d3 ??        					SHR   	??,CL		// Register varies
		 */
		final var longStringPattern = "48 be ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 83 e1 07 48 c1 e1 03 48 89 ?? 48 d3 ??";
		final var shortStringPattern = "";

		var longStringLocations = findPattern(longStringPattern);
		// var shortStringLocations = findPattern(shortStringPattern);

		println("Long string patterns found: " + longStringLocations.size());
		for (int i = 0; i < longStringLocations.size(); i++) {
			println("\t[" + i + "] " + longStringLocations.get(i));
		}
	}

}

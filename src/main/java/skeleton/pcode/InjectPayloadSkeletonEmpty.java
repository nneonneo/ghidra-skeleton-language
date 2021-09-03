package skeleton.pcode;

import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

/**
 * Test to demonstrate a Ghidra bug: the decompiler crashes if the injection
 * returns an empty array
 */
public class InjectPayloadSkeletonEmpty extends InjectPayloadCallother {

	public InjectPayloadSkeletonEmpty(String sourceName) {
		super(sourceName);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		return new PcodeOp[0];
	}
}
package skeleton.pcode;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

/**
 * Simple injection payload to demonstrate callother handling
 */
public class InjectPayloadSkeletonSimple extends InjectPayloadCallother {

	public InjectPayloadSkeletonSimple(String sourceName) {
		super(sourceName);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		PcodeOpEmitter ops = new PcodeOpEmitter(program, con.baseAddr);

		Address reg1Address = program.getRegister("sp").getAddress();
		Address reg2Address = program.getRegister("r1").getAddress();
		ops.emitCopy(reg1Address, reg2Address, 4);

		return ops.getPcodeOps();
	}
}
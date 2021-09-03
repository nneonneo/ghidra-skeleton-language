package skeleton.pcode;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadSleigh;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

/* "uponentry" injection - injected at the start of every function */
public class InjectPayloadSkeletonEntry extends InjectPayloadSleigh {

	public InjectPayloadSkeletonEntry(String nm, int tp, String sourceName) {
		super(nm, tp, sourceName);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		PcodeOpEmitter ops = new PcodeOpEmitter(program, con.baseAddr);

		Address r0 = program.getRegister("r0").getAddress();
		ops.emitCopy(r0, r0, 4);
		return ops.getPcodeOps();
	}
}
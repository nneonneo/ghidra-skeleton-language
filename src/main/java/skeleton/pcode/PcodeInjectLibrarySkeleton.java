package skeleton.pcode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;

public class PcodeInjectLibrarySkeleton extends PcodeInjectLibrary {

	public PcodeInjectLibrarySkeleton(SleighLanguage l) {
		super(l);
	}

	public PcodeInjectLibrarySkeleton(PcodeInjectLibrarySkeleton op2) {
		super(op2);
	}

	@Override
	public PcodeInjectLibrary clone() {
		return new PcodeInjectLibrarySkeleton(this);
	}

	@Override
	public InjectPayload allocateInject(String sourceName, String name, int tp) {
		if (tp == InjectPayload.CALLMECHANISM_TYPE) {
			return new InjectPayloadSkeletonEntry(name, tp, sourceName);
		} else if (tp == InjectPayload.CALLOTHERFIXUP_TYPE) {
			switch (name) {
			case "simpleCallOther":
				return new InjectPayloadSkeletonSimple(sourceName);
				case "emptyCallOther":
				return new InjectPayloadSkeletonEmpty(sourceName);
			}
		}
		return super.allocateInject(sourceName, name, tp);
	}
}
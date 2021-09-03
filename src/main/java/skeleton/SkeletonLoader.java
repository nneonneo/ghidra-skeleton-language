/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package skeleton;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class SkeletonLoader extends AbstractLibrarySupportLoader {

	public final static long BASE_ADDRESS = 0x10000000;
	public final static byte[] SKELETON_MAGIC = new byte[] { (byte) 0x8f, (byte) 0xeb, (byte) 0xfd, (byte) 0xa9,
			(byte) 0x5e, (byte) 0xdd, (byte) 0xde, (byte) 0x15 };

	@Override
	public String getName() {
		return "Skeleton";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);

		byte[] magic = reader.readNextByteArray(8);
		if (Arrays.equals(magic, SKELETON_MAGIC)) {
			loadSpecs.add(new LoadSpec(this, BASE_ADDRESS,
					new LanguageCompilerSpecPair("Skeleton:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws IOException {

		try {
			doLoad(provider, program, monitor);
		} catch (Exception e) {
			Msg.error(this, "Failed to load Skeleton module", e);
		}
	}

	private void doLoad(ByteProvider provider, Program program, TaskMonitor monitor) throws Exception {
		BinaryReader reader = new BinaryReader(provider, true);
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, 0, provider.length(), monitor);

		reader.setPointerIndex(8); // skip magic
		for (int sectionIndex = 0;; sectionIndex++) {
			int sectionSize = reader.readNextInt();
			if (sectionSize == -1) {
				break;
			}
			long sectionAddress = reader.readNextUnsignedInt();
			long fileOffset = reader.getPointerIndex();
			reader.setPointerIndex(fileOffset + sectionSize);
			Address baseAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(sectionAddress);
			MemoryBlock block = program.getMemory().createInitializedBlock(".section" + sectionIndex, baseAddress,
					fileBytes, fileOffset, sectionSize, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);

			String functionName = "function" + sectionIndex;
			program.getFunctionManager().createFunction(functionName, baseAddress,
					new AddressSet(baseAddress, baseAddress.add(sectionSize)), SourceType.IMPORTED);
			program.getSymbolTable().createLabel(baseAddress, functionName, SourceType.IMPORTED);
		}
	}
}
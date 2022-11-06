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
package neogeopocketloader;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;


/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class NeoGeoPocketLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "Neo Geo Pocket";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, false);
		if (reader.readAsciiString(0xd, 0xf).equals("SNK CORPORATION")) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("TLCS900H:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);
		
		InputStream romStream = provider.getInputStream(0);
		boolean hasRomExtraStream = romStream.available() > 0x200000L;

		createSegment(fpa, romStream, "ROM_CART", 0x200000L, Math.min(romStream.available(), 0x1FFFFFL), true, false, true, false, log);
		if (hasRomExtraStream) {
			 InputStream romExtraStream = provider.getInputStream(0x200000L);
			 createSegment(fpa, romExtraStream, "ROM_EXTRA", 0x800000L, Math.min(romExtraStream.available(), 0x1FFFFFL), true, false, true, false, log);
		}
		createSegment(fpa, null, "ROM_BIOS",      0xFF0000L, 0x010000L, true, false, true, false, log);
		createSegment(fpa, null, "RAM_INTERNAL",  0x000000L, 0x000100L, true, true, false, true, log);
		createSegment(fpa, null, "RAM_WORK",      0x000100L, 0x006B00L, true, true, false, true, log);
		createSegment(fpa, null, "CPU_WORKSPACE", 0x006C00L, 0x000400L, true, true, false, true, log);
		createSegment(fpa, null, "RAM_SOUND",     0x007000L, 0x001000L, true, true, false, true, log);
		createSegment(fpa, null, "RAM_VIDEO",     0x008000L, 0x004000L, true, true, false, true, log);

		reader.setPointerIndex(0x1c);
		long entry = reader.readNextUnsignedInt();
		Address entryAddress = fpa.toAddr(entry);
		fpa.createFunction(entryAddress, "entry");
		fpa.addEntryPoint(entryAddress);
		
		createNamedData(fpa, program, 0x0020L, "TRUN", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0022L, "TREG0", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0023L, "TREG1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0024L, "T01MOD", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0025L, "TFFCFR", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0026L, "TREG2", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0027L, "TREG3", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0028L, "T23MOD", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0029L, "TRDC", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0050L, "Serial_Buffer_Data", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0051L, "Serial_Control", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0052L, "Serial_Mode_Control", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x006FL, "Watch_Dog_Timer", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0070L, "RTC_alarm_level", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0071L, "Z80_int_level", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0073L, "Timer_0_1_int_level", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0074L, "Timer_2_3_int_level", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0077L, "Serial_int_level", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0079L, "DMA_0_1_end_int_level", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x007AL, "DMA_2_3_end_int_level", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x007CL, "MicroDMA_0_start_vector", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x007DL, "MicroDMA_1_start_vector", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x007EL, "MicroDMA_2_start_vector", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x007FL, "MicroDMA_3_start_vector", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0091L, "RTC_Years", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0092L, "RTC_Months", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0093L, "RTC_Days", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0094L, "RTC_Hours", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0095L, "RTC_Minutes", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0096L, "RTC_Seconds", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0097L, "RTC_Day", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00A0L, "Noise_Channel", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00A1L, "Tone_Channel", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00A2L, "Left_DAC", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00A3L, "Right_DAC", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00B2L, "COMM_status", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00B8L, "Z80_Activation", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00B9L, "Sound_Chip_Activation", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00BCL, "Z80_TLCS900H_Comm_IF", ByteDataType.dataType, log);

		createNamedData(fpa, program, 0x6C00L, "Game_entrypoint", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6C04L, "Game_catalogue_id", WordDataType.dataType, log);
		createNamedData(fpa, program, 0x6C06L, "Game_subcatalogue_id", ByteDataType.dataType, log);
		createNamedArray(fpa, program, 0x6C08L, "Game_name", 12, ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6C55L, "Game_type", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6C58L, "EEPROM_LO_type", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6C59L, "EEPROM_HI_type", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6C5AL, "Copy_EEPROM_LO_manf_id_0x3", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6C5BL, "Copy_EEPROM_HI_manf_id_0x3", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6D05L, "Comm_status_flag", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6E82L, "Copy_6C04", WordDataType.dataType, log);
		createNamedData(fpa, program, 0x6E84L, "Copy_6C06", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6E94L, "Unk_6E94", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6F80L, "Battery_Voltage", WordDataType.dataType, log);
		createNamedData(fpa, program, 0x6F82L, "Controller_Status", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6F84L, "User_Boot", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6F85L, "User_Shutdown", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6F86L, "User_Answer", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6F87L, "Language", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6F91L, "OS_Version", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6F92L, "Copy_6C58", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6F93L, "Copy_6C59", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6F95L, "Display_Mode", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x6FB8L, "SWI_3", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FBCL, "SWI_4", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FC0L, "SWI_5", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FC4L, "SWI_6", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FC8L, "RTC_Alarm_Int", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FCCL, "Vertical_Blanking_Int", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FD0L, "Int_from_Z80", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FD4L, "Timer_0_Int", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FD8L, "Timer_1_Int", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FDCL, "Timer_2_Int", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FE0L, "Timer_3_Int", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FE4L, "Serial_Transmission_Int", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FE8L, "Serial_Reception_Int", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FECL, "Reserved_6FEC", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FF0L, "End_MicroDMA_0_Int", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FF4L, "End_MicroDMA_0_Int", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FF8L, "End_MicroDMA_0_Int", DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x6FFCL, "End_MicroDMA_0_Int", DWordDataType.dataType, log);

		createNamedData(fpa, program, 0x8000L, "Int_Control_Reg", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8002L, "Window_Horizontal_Origin", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8003L, "Window_Vertical_Origin", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8004L, "Window_X_Size", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8005L, "Window_Y_Size", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8006L, "Frame_Rate_Reg", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8008L, "Raster_Position_Horizontal", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8009L, "Raster_Position_Vertical", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8010L, "Char_Over_VBlank_Status", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8012L, "NEG_OOWC_Setting", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8020L, "Sprite_Plane_Scroll_X", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8021L, "Sprite_Plane_Scroll_Y", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8030L, "Scroll_Priority_Reg", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8032L, "Scroll_1_Scroll_X", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8033L, "Scroll_1_Scroll_Y", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8034L, "Scroll_2_Scroll_X", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8035L, "Scroll_2_Scroll_Y", ByteDataType.dataType, log);
		createNamedArray(fpa, program, 0x8100L, "Sprite_Palette_Table", 2, DWordDataType.dataType, log);
		createNamedArray(fpa, program, 0x8108L, "Scroll_1_Palette_Table", 2, DWordDataType.dataType, log);
		createNamedArray(fpa, program, 0x8110L, "Scroll_2_Palette_Table", 2, DWordDataType.dataType, log);
		createNamedData(fpa, program, 0x8118L, "BG_Colour_Reg", ByteDataType.dataType, log);
		createNamedArray(fpa, program, 0x8200L, "Sprite_Palette_Table", 16, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0x8280L, "Scroll_1_Palette_Table", 16, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0x8300L, "Scroll_2_Palette_Table", 16, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0x83E0L, "BG_Colour_Palette", 8, ByteDataType.dataType, log);
		createNamedArray(fpa, program, 0x83F0L, "Window_Colour_Palette", 8, ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8400L, "LED_Control_Reg", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x8402L, "LED_Flash_Cycle", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x87E0L, "2D_software_reset", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x87E2L, "Mode_Selection_Reg", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x87F0L, "Mode_Reg_Write_access", ByteDataType.dataType, log);
		createNamedArray(fpa, program, 0x8800L, "Sprites", 64, DWordDataType.dataType, log);
		createNamedArray(fpa, program, 0x8C00L, "Sprite_Palette_Numbers", 64, DWordDataType.dataType, log);
		createNamedArray(fpa, program, 0x9000L, "Scroll_1_Map", 0x800, ByteDataType.dataType, log);
		createNamedArray(fpa, program, 0x9800L, "Scroll_2_Map", 0x800, ByteDataType.dataType, log);
		createNamedArray(fpa, program, 0xA000L, "Pattern_Table", 0x2000, ByteDataType.dataType, log);

		monitor.setMessage(String.format("%s : Loading done", getName()));
	}

	private void createSegment(FlatProgramAPI fpa,
			InputStream stream,
			String name,
			long address,
			long size,
			boolean read,
			boolean write,
			boolean execute,
			boolean volatil,
			MessageLog log) {
		MemoryBlock block;
		try {
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			block.setRead(read);
			block.setWrite(write);
			block.setExecute(execute);
			block.setVolatile(volatil);
		} catch (Exception e) {
			log.appendException(e);
		}
	}
	
	private void createNamedArray(FlatProgramAPI fpa, Program program, long address, String name, int numElements, DataType type, MessageLog log) {
		try {
			CreateArrayCmd arrayCmd = new CreateArrayCmd(fpa.toAddr(address), numElements, type, type.getLength());
			arrayCmd.applyTo(program);
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	private void createNamedData(FlatProgramAPI fpa,
			Program program,
			long address,
			String name,
			DataType type,
			MessageLog log) {
		try {
			if (type.equals(ByteDataType.dataType)) {
				fpa.createByte(fpa.toAddr(address));
			} else if (type.equals(WordDataType.dataType)) {
				fpa.createWord(fpa.toAddr(address));
			} else if (type.equals(DWordDataType.dataType)) {
				fpa.createDWord(fpa.toAddr(address));
			}
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (Exception e) {
			log.appendException(e);
		}
	}
}

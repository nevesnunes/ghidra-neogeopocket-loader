
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
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

		reader.setPointerIndex(0x23);
		boolean isNGPC = reader.readNextUnsignedByte() == 0x10;

		InputStream biosStream = null;
		File biosFile = new File(isNGPC ?  "/tmp/ngpcbios.rom" : "/tmp/ngp_bios.ngp");
		if (biosFile.isFile()) {
			biosStream = new FileInputStream(biosFile);
			monitor.setMessage(String.format("Loading BIOS @ %s", biosFile));
		} else {
			int choice = OptionDialog.showOptionNoCancelDialog(
				null,
				"BIOS mapping",
				"Load BIOS file?",
				"Yes",
				"No (Just create empty mapping)",
				OptionDialog.QUESTION_MESSAGE
			);
			if (choice == OptionDialog.OPTION_ONE) {
				GhidraFileChooser chooser = new GhidraFileChooser(null);
				chooser.setTitle("Open BIOS file");
				File file = chooser.getSelectedFile(true);
				if (file != null) {
					biosStream = new FileInputStream(file);
				}
			}
		}

		createSegment(fpa, romStream, "ROM_CART", 0x200000L, Math.min(romStream.available(), 0x1FFFFFL), true, false, true, false, log);
		if (hasRomExtraStream) {
			 InputStream romExtraStream = provider.getInputStream(0x200000L);
			 createSegment(fpa, romExtraStream, "ROM_EXTRA", 0x800000L, Math.min(romExtraStream.available(), 0x1FFFFFL), true, false, true, false, log);
		}
		createSegment(fpa, biosStream, "ROM_BIOS", 0xFF0000L, 0x010000L, true, false, true, false, log);

		createSegment(fpa, null, "IO_INTERNAL",   0x000000L, 0x000100L, true, true, false, true, log);
		createSegment(fpa, null, "RAM_RESERVED",  0x000100L, 0x003F00L, true, true, false, true, log);
		createSegment(fpa, null, "CPU_RAM",       0x004000L, 0x002C00L, true, true, false, false, log);
		createSegment(fpa, null, "CPU_WORKSPACE", 0x006C00L, 0x000400L, true, true, false, false, log);
		createSegment(fpa, null, "APU_RAM",       0x007000L, 0x001000L, true, true, false, false, log);
		createSegment(fpa, null, "VIDEO_RAM",     0x008000L, 0x004000L, true, true, false, false, log);

		// https://github.com/mamedev/mame/blob/d0e027b0e66b26f4c15cf2497e56820f63fd6cac/src/devices/cpu/tlcs900/tmp95c061.cpp#L70
		createNamedData(fpa,  program, 0x0001L, "P1", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0004L, "P1CR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0006L, "P2", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0009L, "P2FC", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x000DL, "P5", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0010L, "P5CR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0011L, "P5FC", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0012L, "P6", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0013L, "P7", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0015L, "P6FC", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0016L, "P7CR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0017L, "P7FC", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0018L, "P8", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0019L, "P9", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x001AL, "P8CR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x001BL, "P8FC", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x001EL, "PA", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x001FL, "PB", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0020L, "TRUN", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0022L, "TReg0", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0023L, "TReg1", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0024L, "T01Mod", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0025L, "TFFCR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0026L, "TReg2", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0027L, "TReg3", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0028L, "T23Mod", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0029L, "TRDC", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0030L, "TReg45", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x0034L, "Cap12", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x0038L, "T4Mod", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0039L, "T4FFC", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x003AL, "T45CR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x003CL, "MSAR01", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x0040L, "TReg67", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x0044L, "Cap34", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x0048L, "T5Mod", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0049L, "T5FFCR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x004CL, "PGReg", WordDataType.dataType, log);
		createNamedData(fpa,  program, 0x004EL, "PG01CR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0050L, "SC0Buf", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0051L, "SC0CR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0052L, "SC0Mod", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0053L, "BR0CR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0054L, "SC1Buf", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0055L, "SC1CR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0056L, "SC1Mod", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0057L, "BR1CR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0058L, "ODE", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x005AL, "DREFCR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x005BL, "DMEMCR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x005CL, "MSAR23", DWordDataType.dataType, log);
		createNamedArray(fpa, program, 0x0060L, "ADReg", 8, ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0068L, "BCS", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x006CL, "BExCS", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x006DL, "ADMod", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x006EL, "WDMod", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x006FL, "WDCR", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0070L, "RTC_Alarm_Level", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0071L, "Z80_Int_Level", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0073L, "Timer01_Int_Level", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0074L, "Timer23_Int_Level", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0077L, "Serial_Int_Level", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0079L, "DMA01_End_Int_Level", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x007AL, "DMA23_End_Int_Level", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x007BL, "IIMC", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x007CL, "MicroDMA0_Start_Vector", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x007DL, "MicroDMA1_Start_Vector", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x007EL, "MicroDMA2_Start_Vector", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x007FL, "MicroDMA3_Start_Vector", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0091L, "RTC_Years", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0092L, "RTC_Months", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0093L, "RTC_Days", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0094L, "RTC_Hours", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0095L, "RTC_Minutes", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0096L, "RTC_Seconds", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x0097L, "RTC_Day", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x00A0L, "Noise_Channel", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x00A1L, "Tone_Channel", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x00A2L, "Left_DAC", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x00A3L, "Right_DAC", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x00B2L, "COMM_Status", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x00B8L, "Z80_Activation", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x00B9L, "Sound_Chip_Activation", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x00BCL, "Z80_TLCS900H_Comm_IF", ByteDataType.dataType, log);

		createNamedData(fpa,  program, 0x6C00L, "Game_Entrypoint", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6C04L, "Game_Catalogue_Id", WordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6C06L, "Game_Subcatalogue_Id", ByteDataType.dataType, log);
		createNamedArray(fpa, program, 0x6C08L, "Game_Name", 12, ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6C55L, "Game_Type", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6C58L, "EEPROM_LO_Type", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6C59L, "EEPROM_HI_Type", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6C5AL, "Copy_EEPROM_LO_Manf_Id_0x3", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6C5BL, "Copy_EEPROM_HI_Manf_Id_0x3", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6D05L, "Comm_Status_Flag", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6E82L, "Copy_6C04", WordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6E84L, "Copy_6C06", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6F80L, "Battery_Voltage", WordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6F82L, "Controller_Status", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6F84L, "User_Boot", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6F85L, "User_Shutdown", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6F86L, "User_Answer", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6F87L, "Language", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6F91L, "OS_Version", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6F92L, "Copy_6C58", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6F93L, "Copy_6C59", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6F95L, "Display_Mode", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FB8L, "SWI_3", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FBCL, "SWI_4", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FC0L, "SWI_5", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FC4L, "SWI_6", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FC8L, "RTC_Alarm_Int", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FCCL, "Vertical_Blanking_Int", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FD0L, "Int_From_Z80", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FD4L, "Timer0_Int", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FD8L, "Timer1_Int", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FDCL, "Timer2_Int", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FE0L, "Timer3_Int", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FE4L, "Serial_Transmission_Int", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FE8L, "Serial_Reception_Int", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FECL, "Reserved_6FEC", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FF0L, "End_MicroDMA0_Int", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FF4L, "End_MicroDMA1_Int", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FF8L, "End_MicroDMA2_Int", DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x6FFCL, "End_MicroDMA3_Int", DWordDataType.dataType, log);

		createNamedData(fpa,  program, 0x8000L, "Int_Ctrl_Reg", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8002L, "Window_Horizontal_Origin", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8003L, "Window_Vertical_Origin", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8004L, "Window_X_Size", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8005L, "Window_Y_Size", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8006L, "Frame_Rate_Reg", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8008L, "Raster_Position_Horizontal", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8009L, "Raster_Position_Vertical", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8010L, "Char_Over_VBlank_Status", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8012L, "NEG_OOWC_Setting", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8020L, "Sprite_Plane_Scroll_X", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8021L, "Sprite_Plane_Scroll_Y", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8030L, "Scroll_Priority_Reg", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8032L, "Scroll_1_Scroll_X", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8033L, "Scroll_1_Scroll_Y", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8034L, "Scroll_2_Scroll_X", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8035L, "Scroll_2_Scroll_Y", ByteDataType.dataType, log);
		createNamedArray(fpa, program, 0x8100L, "Sprite_Palette_Table", 2, DWordDataType.dataType, log);
		createNamedArray(fpa, program, 0x8108L, "Scroll_1_Palette_Table", 2, DWordDataType.dataType, log);
		createNamedArray(fpa, program, 0x8110L, "Scroll_2_Palette_Table", 2, DWordDataType.dataType, log);
		createNamedData(fpa,  program, 0x8118L, "BG_Colour_Reg", ByteDataType.dataType, log);
		createNamedArray(fpa, program, 0x8200L, "Sprite_Palette_Table", 16, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0x8280L, "Scroll_1_Palette_Table", 16, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0x8300L, "Scroll_2_Palette_Table", 16, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0x83E0L, "BG_Colour_Palette", 8, ByteDataType.dataType, log);
		createNamedArray(fpa, program, 0x83F0L, "Window_Colour_Palette", 8, ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8400L, "LED_Ctrl_Reg", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x8402L, "LED_Flash_Cycle", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x87E0L, "2D_Software_Reset", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x87E2L, "Mode_Selection_Reg", ByteDataType.dataType, log);
		createNamedData(fpa,  program, 0x87F0L, "Mode_Reg_Write_Access", ByteDataType.dataType, log);
		createNamedArray(fpa, program, 0x8800L, "Sprites", 64, DWordDataType.dataType, log);
		createNamedArray(fpa, program, 0x8C00L, "Sprite_Palette_Numbers", 64, DWordDataType.dataType, log);
		createNamedArray(fpa, program, 0x9000L, "Scroll_1_Map", 0x800, ByteDataType.dataType, log);
		createNamedArray(fpa, program, 0x9800L, "Scroll_2_Map", 0x800, ByteDataType.dataType, log);
		createNamedArray(fpa, program, 0xA000L, "Pattern_Table", 0x2000, ByteDataType.dataType, log);

		reader.setPointerIndex(0x1c);
		long entry = reader.readNextUnsignedInt();
		Address entryAddress = fpa.toAddr(entry);
		fpa.createFunction(entryAddress, "entry");
		fpa.addEntryPoint(entryAddress);

		Map <Long, String> mappings = new HashMap<>();
		long biosBase = 0xFFFE00L;
		mappings.put(biosBase + 4 * 0x00, "VEC_SHUTDOWN");
		mappings.put(biosBase + 4 * 0x01, "VEC_CLOCKGEARSET");
		mappings.put(biosBase + 4 * 0x02, "VEC_RTCGET");
		mappings.put(biosBase + 4 * 0x03, "VEC_UNK_03");
		mappings.put(biosBase + 4 * 0x04, "VEC_INTLVSET");
		mappings.put(biosBase + 4 * 0x05, "VEC_SYSFONTSET");
		mappings.put(biosBase + 4 * 0x06, "VEC_FLASHWRITE");
		mappings.put(biosBase + 4 * 0x07, "VEC_FLASHALLERS");
		mappings.put(biosBase + 4 * 0x08, "VEC_FLASHERS");
		mappings.put(biosBase + 4 * 0x09, "VEC_ALARMSET");
		mappings.put(biosBase + 4 * 0x0a, "VEC_UNK_0a");
		mappings.put(biosBase + 4 * 0x0b, "VEC_ALARMDOWNSET");
		mappings.put(biosBase + 4 * 0x0c, "VEC_UNK_0c");
		mappings.put(biosBase + 4 * 0x0d, "VEC_FLASHPROTECT");
		mappings.put(biosBase + 4 * 0x0e, "VEC_GETMODESET");
		mappings.put(biosBase + 4 * 0x0f, "VEC_UNK_0f");
		mappings.put(biosBase + 4 * 0x10, "VEC_COMINIT");
		mappings.put(biosBase + 4 * 0x11, "VEC_COMSENDSTART");
		mappings.put(biosBase + 4 * 0x12, "VEC_COMRECEIVESTART");
		mappings.put(biosBase + 4 * 0x13, "VEC_COMCREATEDATA");
		mappings.put(biosBase + 4 * 0x14, "VEC_COMGETDATA");
		mappings.put(biosBase + 4 * 0x15, "VEC_COMONRTS");
		mappings.put(biosBase + 4 * 0x16, "VEC_COMOFFRTS");
		mappings.put(biosBase + 4 * 0x17, "VEC_COMSENDSTATUS");
		mappings.put(biosBase + 4 * 0x18, "VEC_COMRECEIVESTATUS");
		mappings.put(biosBase + 4 * 0x19, "VEC_COMCREATEBUFDATA");
		mappings.put(biosBase + 4 * 0x1a, "VEC_COMGETBUFDATA");

		long biosIntBase = 0xFFFF00L;
		mappings.put(biosIntBase + 0x00, "SWI_0_HWRESET");
		mappings.put(biosIntBase + 0x04, "SWI_1");
		mappings.put(biosIntBase + 0x08, "SWI_2_ILLEGAL");
		mappings.put(biosIntBase + 0x0c, "SWI_3");
		mappings.put(biosIntBase + 0x10, "SWI_4");
		mappings.put(biosIntBase + 0x14, "SWI_5");
		mappings.put(biosIntBase + 0x18, "SWI_6");
		mappings.put(biosIntBase + 0x1c, "SWI_7");
		mappings.put(biosIntBase + 0x20, "NMI_POWER");
		mappings.put(biosIntBase + 0x24, "INT_WATCHDOG");
		mappings.put(biosIntBase + 0x28, "INT_0_RTC");
		mappings.put(biosIntBase + 0x2c, "INT_4_VBLANK");
		mappings.put(biosIntBase + 0x30, "INT_5_Z80");
		mappings.put(biosIntBase + 0x34, "INT_6");
		mappings.put(biosIntBase + 0x38, "INT_7");
		mappings.put(biosIntBase + 0x3c, "INT_RESERVED_3c");
		mappings.put(biosIntBase + 0x40, "INT_T0");
		mappings.put(biosIntBase + 0x44, "INT_T1");
		mappings.put(biosIntBase + 0x48, "INT_T2");
		mappings.put(biosIntBase + 0x4c, "INT_T3");
		mappings.put(biosIntBase + 0x50, "INT_TR4");
		mappings.put(biosIntBase + 0x54, "INT_TR5");
		mappings.put(biosIntBase + 0x58, "INT_TR6");
		mappings.put(biosIntBase + 0x5c, "INT_TR7");
		mappings.put(biosIntBase + 0x60, "INT_RX0");
		mappings.put(biosIntBase + 0x64, "INT_TX0");
		mappings.put(biosIntBase + 0x68, "INT_RX1");
		mappings.put(biosIntBase + 0x6c, "INT_TX1");
		mappings.put(biosIntBase + 0x70, "INT_AD");
		mappings.put(biosIntBase + 0x74, "INT_TC0");
		mappings.put(biosIntBase + 0x78, "INT_TC1");
		mappings.put(biosIntBase + 0x7c, "INT_TC2");
		mappings.put(biosIntBase + 0x80, "INT_TC3");
		
		mappings.forEach((address, name) -> {
			createNamedData(fpa, program, address, name, PointerDataType.dataType, log);
		});

		final boolean isBiosLoaded = biosStream != null;
		if (isBiosLoaded) {
			ByteProvider biosProvider = new MemoryByteProvider(fpa.getCurrentProgram().getMemory(), fpa.toAddr(0));
			BinaryReader biosReader = new BinaryReader(biosProvider, true);
			biosReader.setPointerIndex(biosBase);
			for (int i = 0; i < 0x200; i += 4) {
				long vec = biosReader.readNextUnsignedInt();
				if (vec == 0) {
					continue;
				}

				monitor.setMessage(String.format("Disassembling @ 0x%08x", vec));
				long vecEntry = biosBase + i;
				fpa.createFunction(fpa.toAddr(vec), mappings.getOrDefault(vecEntry, null));
				new DisassembleCommand(fpa.toAddr(vec), null, true).applyTo(program);
			}
		}

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
			} else if (type.equals(PointerDataType.dataType)) {
				new CreateDataCmd(fpa.toAddr(address), new PointerDataType()).applyTo(program);
			}
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (Exception e) {
			log.appendException(e);
		}
	}
}

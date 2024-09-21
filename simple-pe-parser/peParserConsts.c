/**
 * @file peParserConsts.c
 * @brief Constants file for the PE parser (converting numerical values to corresponding human-readable definition strings)
 */

#include <stdio.h>
#include <Windows.h>

char* getNTImageFileHeaderMachineType(WORD machineType) {
	switch (machineType) {
		case IMAGE_FILE_MACHINE_I386:
			return "Intel 386";
		case IMAGE_FILE_MACHINE_AMD64:
			return "AMD64 (x64)";
		case IMAGE_FILE_MACHINE_IA64:
			return "Intel Itanium";
		default:
			return "Unknown";
	}
}

void dissectNTImageCharacteristics(DWORD characteristics) {
	printf("    Characteristics:                       0x%08X\n", characteristics);

	// Separate the characteristics into individual flags by bit
	if (characteristics & IMAGE_FILE_RELOCS_STRIPPED)
		printf("        - (0x%08X) Relocation information stripped from file\n", IMAGE_FILE_RELOCS_STRIPPED);
	if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
		printf("        - (0x%08X) File is executable\n", IMAGE_FILE_EXECUTABLE_IMAGE);
	if (characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)
		printf("        - (0x%08X) Line numbers stripped from file\n", IMAGE_FILE_LINE_NUMS_STRIPPED);
	if (characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
		printf("        - (0x%08X) Local symbols stripped from file\n", IMAGE_FILE_LOCAL_SYMS_STRIPPED);
	if (characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM)
		printf("        - (0x%08X) Aggressively trim the working set(obsolete)\n", IMAGE_FILE_AGGRESIVE_WS_TRIM);
	if (characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
		printf("        - (0x%08X) Application can handle > 2GB addresses\n", IMAGE_FILE_LARGE_ADDRESS_AWARE);
	if (characteristics & IMAGE_FILE_BYTES_REVERSED_LO)
		printf("        - (0x%08X) Bytes of machine word are reversed(obsolete)\n", IMAGE_FILE_BYTES_REVERSED_LO);
	if (characteristics & IMAGE_FILE_32BIT_MACHINE)
		printf("        - (0x%08X) The computer supports 32-bit machine\n", IMAGE_FILE_32BIT_MACHINE);
	if (characteristics & IMAGE_FILE_DEBUG_STRIPPED)
		printf("        - (0x%08X) Debugging information wsa remove and stored to another file in .DBG file\n", IMAGE_FILE_DEBUG_STRIPPED);
	if (characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
		printf("        - (0x%08X) If image is on removable media, copy and run from swap file\n", IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP);
	if (characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP)
		printf("        - (0x%08X) If image is on network media, copy and run from swap file\n", IMAGE_FILE_NET_RUN_FROM_SWAP);
	if (characteristics & IMAGE_FILE_SYSTEM)
		printf("        - (0x%08X) System file\n", IMAGE_FILE_SYSTEM);
	if (characteristics & IMAGE_FILE_DLL)
		printf("        - (0x%08X) File is a DLL(Dynamic Link Library)\n", IMAGE_FILE_DLL);
	if (characteristics & IMAGE_FILE_UP_SYSTEM_ONLY)
		printf("        - (0x%08X) File should only be run on a UP machine\n", IMAGE_FILE_UP_SYSTEM_ONLY);
	if (characteristics & IMAGE_FILE_BYTES_REVERSED_HI)
		printf("        - (0x%08X) Bytes of machine word are reversed\n", IMAGE_FILE_BYTES_REVERSED_HI);
}
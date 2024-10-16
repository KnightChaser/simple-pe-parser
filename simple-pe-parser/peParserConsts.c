/**
 * @file peParserConsts.c
 * @brief Constants file for the PE parser (converting numerical values to corresponding human-readable definition strings)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

#define MAX_PATH_LENGTH 4096

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

char* getNTImageOptionalHeaderOSVersion(DWORD majorVersion, DWORD minorVersion) {
		switch (majorVersion) {
		case 0x00:
			switch (minorVersion) {
				case 0x00:
					return "Windows 95";
				case 0x01:
					return "Windows 98";
				case 0x0A:
					return "Windows 98 SE";
				default:
					return "Unknown";
			}
		case 0x01:
			switch (minorVersion) {
				case 0x00:
					return "Windows ME";
				default:
					return "Unknown";
			}
		case 0x05:
			switch (minorVersion) {
				case 0x00:
					return "Windows 2000";
				case 0x01:
					return "Windows XP";
				default:
					return "Unknown";
			}
		case 0x06:
			switch (minorVersion) {
				case 0x00:
					// Note that even later versions of Windows may still report as 6.0 (such as Windows 11)
					// This implementation follows the original versioning scheme
					return "Windows Vista / Windows Server 2008";
				case 0x01:
					return "Windows 7";
				case 0x02:
					return "Windows 8";
				case 0x03:
					return "Windows 8.1";
				default:
					return "Unknown";
			}
		case 0x0A:
			switch (minorVersion) {
				case 0x00:
					return "Windows 10";
				default:
					return "Unknown";
			}
		default:
			return "Unknown";
	}
}

char* getNTImageOptionalHeaderSubsystemDefinition(DWORD subsystem) {
		switch (subsystem) {
		case IMAGE_SUBSYSTEM_UNKNOWN:
			return "Unknown";
		case IMAGE_SUBSYSTEM_NATIVE:
			return "Native / No subsystem required (device drivers and native system processes).";
		case IMAGE_SUBSYSTEM_WINDOWS_GUI:
			return "Windows GUI(Graphical User Interface)";
		case IMAGE_SUBSYSTEM_WINDOWS_CUI:
			return "Windows CUI(Character User Interface)";
		case IMAGE_SUBSYSTEM_OS2_CUI:
			return "OS/2 CUI";
		case IMAGE_SUBSYSTEM_POSIX_CUI:
			return "POSIX CUI";
		case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
			return "Windows CE GUI";
		case IMAGE_SUBSYSTEM_EFI_APPLICATION:
			return "EFI(Extensible Firmware Interface) Application";
		case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
			return "EFI(Extensible Firmware Interface) Boot Service Driver";
		case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
			return "EFI(Extensible Firmware Interface) Runtime Driver";
		case IMAGE_SUBSYSTEM_EFI_ROM:
			return "EFI(Extensible Firmware Interface) ROM";
		case IMAGE_SUBSYSTEM_XBOX:
			return "XBOX";
		case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
			return "Windows Boot Application";
		default:
			return "Unknown";
	}
}

void dissectNTImageOptionalHeaderDLLCharacteristics(DWORD characteristics) {
	printf("    DLL Characteristics:                   0x%08X\n", characteristics);

	// Separate the characteristics into individual flags by bit
	DWORD IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA = 0x20;					// Why is this not defined in the Windows SDK?
	if (characteristics & IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA)
		printf("        - (0x%08X) Image supports 64 bits ASLR(Address Space Layout Randomization)\n", IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA);
	if (characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		printf("        - (0x%08X) DLL can be relocated at load time\n", IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
	if (characteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
		printf("        - (0x%08X) Code integrity checks are enforced\n", IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY);
	if (characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		printf("        - (0x%08X) Image is NX(Non-eXecutable) compatible\n", IMAGE_DLLCHARACTERISTICS_NX_COMPAT);
	if (characteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)
		printf("        - (0x%08X) Image does not use structured exception handling\n", IMAGE_DLLCHARACTERISTICS_NO_ISOLATION);
	if (characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)
		printf("        - (0x%08X) Do not use structured exception handling\n", IMAGE_DLLCHARACTERISTICS_NO_SEH);
	if (characteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND)
		printf("        - (0x%08X) Do not bind the image\n", IMAGE_DLLCHARACTERISTICS_NO_BIND);
	if (characteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER)
		printf("        - (0x%08X) Image must execute in an AppContainer\n", IMAGE_DLLCHARACTERISTICS_APPCONTAINER);
	if (characteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
		printf("        - (0x%08X) A WDM driver\n", IMAGE_DLLCHARACTERISTICS_WDM_DRIVER);
	if (characteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
		printf("        - (0x%08X) Terminal Server aware\n", IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE);
}

char* getNTImageOptionalHeaderDataDirectoryName(DWORD dataDirectoryIndex) {
	switch (dataDirectoryIndex) {
		case IMAGE_DIRECTORY_ENTRY_EXPORT:
			return "Export Directory";
		case IMAGE_DIRECTORY_ENTRY_IMPORT:
			return "Import Directory";
		case IMAGE_DIRECTORY_ENTRY_RESOURCE:
			return "Resource Directory";
		case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
			return "Exception Directory";
		case IMAGE_DIRECTORY_ENTRY_SECURITY:
			return "Security Directory";
		case IMAGE_DIRECTORY_ENTRY_BASERELOC:
			return "Base Relocation Table";
		case IMAGE_DIRECTORY_ENTRY_DEBUG:
			return "Debug Directory";
		case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
			return "Architecture Specific Data";
		case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
			return "Global Pointer Register";
		case IMAGE_DIRECTORY_ENTRY_TLS:
			return "Thread Local Storage Directory";
		case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
			return "Load Configuration Directory";
		case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
			return "Bound Import Directory in headers";
		case IMAGE_DIRECTORY_ENTRY_IAT:
			return "Import Address Table";
		case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
			return "Delay Load Import Descriptors";
		case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
			return "COM Runtime descriptor";
		default:
			return "Unknown";
	}
}

void dissectNTImageSectionHeaderCharacteristics(DWORD characteristics) {
	if (characteristics & IMAGE_SCN_TYPE_NO_PAD)
		printf("            - (0x%08X) Section should not be padded to the next boundary\n", IMAGE_SCN_TYPE_NO_PAD);
	if (characteristics & IMAGE_SCN_CNT_CODE)
		printf("            - (0x%08X) Section contains executable code\n", IMAGE_SCN_CNT_CODE);
	if (characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
		printf("            - (0x%08X) Section contains initialized data\n", IMAGE_SCN_CNT_INITIALIZED_DATA);
	if (characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
		printf("            - (0x%08X) Section contains uninitialized data\n", IMAGE_SCN_CNT_UNINITIALIZED_DATA);
	if (characteristics & IMAGE_SCN_LNK_OTHER)
		printf("            - (0x%08X) Reserved for future use\n", IMAGE_SCN_LNK_OTHER);
	if (characteristics & IMAGE_SCN_LNK_INFO)
		printf("            - (0x%08X) Section contains comments or some other type of information\n", IMAGE_SCN_LNK_INFO);
	if (characteristics & IMAGE_SCN_LNK_REMOVE)
		printf("            - (0x%08X) Section contents will not become part of image\n", IMAGE_SCN_LNK_REMOVE);
	if (characteristics & IMAGE_SCN_LNK_COMDAT)
		printf("            - (0x%08X) Section contents comdat\n", IMAGE_SCN_LNK_COMDAT);
	if (characteristics & IMAGE_SCN_GPREL)
		printf("            - (0x%08X) Section content can be accessed relative to GP\n", IMAGE_SCN_GPREL);
	if (characteristics & IMAGE_SCN_MEM_PURGEABLE)
		printf("            - (0x%08X) Reserved for future use\n", IMAGE_SCN_MEM_PURGEABLE);
	if (characteristics & IMAGE_SCN_MEM_16BIT)
		printf("            - (0x%08X) Reserved for future use\n", IMAGE_SCN_MEM_16BIT);
	if (characteristics & IMAGE_SCN_MEM_LOCKED)
		printf("            - (0x%08X) Reserved for future use\n", IMAGE_SCN_MEM_LOCKED);
	if (characteristics & IMAGE_SCN_MEM_PRELOAD)
		printf("            - (0x%08X) Reserved for future use\n", IMAGE_SCN_MEM_PRELOAD);
	if (characteristics & IMAGE_SCN_ALIGN_1BYTES)
		printf("            - (0x%08X) Align data on a 1-byte boundary\n", IMAGE_SCN_ALIGN_1BYTES);
	if (characteristics & IMAGE_SCN_ALIGN_2BYTES)
		printf("            - (0x%08X) Align data on a 2-byte boundary\n", IMAGE_SCN_ALIGN_2BYTES);
	if (characteristics & IMAGE_SCN_ALIGN_4BYTES)
		printf("            - (0x%08X) Align data on a 4-byte boundary\n", IMAGE_SCN_ALIGN_4BYTES);
	if (characteristics & IMAGE_SCN_ALIGN_8BYTES)
		printf("            - (0x%08X) Align data on a 8-byte boundary\n", IMAGE_SCN_ALIGN_8BYTES);
	if (characteristics & IMAGE_SCN_ALIGN_16BYTES)
		printf("            - (0x%08X) Align data on a 16-byte boundary\n", IMAGE_SCN_ALIGN_16BYTES);
	if (characteristics & IMAGE_SCN_ALIGN_32BYTES)
		printf("            - (0x%08X) Align data on a 32-byte boundary\n", IMAGE_SCN_ALIGN_32BYTES);
	if (characteristics & IMAGE_SCN_ALIGN_64BYTES)
		printf("            - (0x%08X) Align data on a 64-byte boundary\n", IMAGE_SCN_ALIGN_64BYTES);
	if (characteristics & IMAGE_SCN_ALIGN_128BYTES)
		printf("            - (0x%08X) Align data on a 128-byte boundary\n", IMAGE_SCN_ALIGN_128BYTES);
	if (characteristics & IMAGE_SCN_ALIGN_256BYTES)
		printf("            - (0x%08X) Align data on a 256-byte boundary\n", IMAGE_SCN_ALIGN_256BYTES);
	if (characteristics & IMAGE_SCN_ALIGN_512BYTES)
		printf("            - (0x%08X) Align data on a 512-byte boundary\n", IMAGE_SCN_ALIGN_512BYTES);
	if (characteristics & IMAGE_SCN_ALIGN_1024BYTES)
		printf("            - (0x%08X) Align data on a 1024-byte boundary\n", IMAGE_SCN_ALIGN_1024BYTES);
	if (characteristics & IMAGE_SCN_ALIGN_2048BYTES)
		printf("            - (0x%08X) Align data on a 2048-byte boundary\n", IMAGE_SCN_ALIGN_2048BYTES);
	if (characteristics & IMAGE_SCN_ALIGN_4096BYTES)
		printf("            - (0x%08X) Align data on a 4096-byte boundary\n", IMAGE_SCN_ALIGN_4096BYTES);
	if (characteristics & IMAGE_SCN_ALIGN_8192BYTES)
		printf("            - (0x%08X) Align data on a 8192-byte boundary\n", IMAGE_SCN_ALIGN_8192BYTES);
	if (characteristics & IMAGE_SCN_LNK_NRELOC_OVFL)
		printf("            - (0x%08X) Section contains extended relocations\n", IMAGE_SCN_LNK_NRELOC_OVFL);
	if (characteristics & IMAGE_SCN_MEM_DISCARDABLE)
		printf("            - (0x%08X) Section can be discarded\n", IMAGE_SCN_MEM_DISCARDABLE);
	if (characteristics & IMAGE_SCN_MEM_NOT_CACHED)
		printf("            - (0x%08X) Section is not cachable\n", IMAGE_SCN_MEM_NOT_CACHED);
	if (characteristics & IMAGE_SCN_MEM_NOT_PAGED)
		printf("            - (0x%08X) Section is not pageable\n", IMAGE_SCN_MEM_NOT_PAGED);
	if (characteristics & IMAGE_SCN_MEM_SHARED)
		printf("            - (0x%08X) Section is shareable\n", IMAGE_SCN_MEM_SHARED);
	if (characteristics & IMAGE_SCN_MEM_EXECUTE)
		printf("            - (0x%08X) Section is executable\n", IMAGE_SCN_MEM_EXECUTE);
	if (characteristics & IMAGE_SCN_MEM_READ)
		printf("            - (0x%08X) Section is readable\n", IMAGE_SCN_MEM_READ);
	if (characteristics & IMAGE_SCN_MEM_WRITE)
		printf("            - (0x%08X) Section is writeable\n", IMAGE_SCN_MEM_WRITE);
}

char* getNTImageRelocationType(WORD type) {
	switch (type) {
	case IMAGE_REL_BASED_ABSOLUTE:
		return "ABSOLUTE";
	case IMAGE_REL_BASED_HIGH:
		return "HIGH";
	case IMAGE_REL_BASED_LOW:
		return "LOW";
	case IMAGE_REL_BASED_HIGHLOW:
		return "HIGHLOW";
	case IMAGE_REL_BASED_HIGHADJ:
		return "HIGHADJ";
	case IMAGE_REL_BASED_MIPS_JMPADDR:
		return "MIPS_JMPADDR";
	case IMAGE_REL_BASED_MIPS_JMPADDR16:
		return "MIPS_JMPADDR16";
	case IMAGE_REL_BASED_DIR64:
		return "DIR64";
	default:
		return "Unknown";
	}
}

char* getCompIdTranslation(DWORD compId) {
	// Define the buffer for the file path
	char compIdListPath[MAX_PATH_LENGTH];
	DWORD pathLength = GetCurrentDirectoryA(MAX_PATH_LENGTH, compIdListPath);
	if (pathLength == 0 || pathLength > MAX_PATH_LENGTH - 20) {
		printf("[!] Failed to get the current directory or path is too long.\n");
		exit(-1);
	}

	// Modify the compIdListPath's last two directories to point to the compIdList.txt file like so:
	// Before: ...\simple-pe-parser\x64\Debug\
	// After : ...\simple-pe-parser\simple-pe-parser\ 
	compIdListPath[pathLength - 9] = '\0';
	strncat_s(compIdListPath, MAX_PATH_LENGTH, "simple-pe-parser", _TRUNCATE);

	// Append the "compIdList.txt" file name to the directory path
	strncat_s(compIdListPath, MAX_PATH_LENGTH, "\\compIdList.txt", _TRUNCATE);

	// Open the compIdList.txt file
	FILE* file = fopen(compIdListPath, "r");
	if (!file) {
		printf("[!] Failed to open %s\n", compIdListPath);
		return NULL;
	}

	static char translation[256];  // Buffer to hold the translation text
	char line[512];  // Buffer to hold each line read from the file

	// Read the file line by line to check for the compId
	while (fgets(line, sizeof(line), file)) {
		// Skip lines that are comments or empty
		if (line[0] == '#' || line[0] == '\n') {
			continue;
		}

		DWORD fileCompId;
		char compIdDescription[256];

		// Parse the line to extract @comp.id and the description
		if (sscanf_s(line, "%08x %[^\n]", &fileCompId, compIdDescription, (unsigned int)sizeof(compIdDescription)) == 2) {
			// Compare the @comp.id with the input compId
			if (fileCompId == compId) {
				// Copy the description into the translation buffer
				ZeroMemory(translation, sizeof(translation));
				strncpy_s(translation, sizeof(translation), compIdDescription, sizeof(translation) - 1);
				translation[sizeof(translation) - 1] = '\0';
				fclose(file);
				return translation;  // Return the translation if found
			}
		}
	}

	// If we reach here, no matching compId was found
	fclose(file);

	// Return a default message (Unknown)
	return "Unknown";
}
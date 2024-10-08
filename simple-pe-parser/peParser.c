/**
 * @file peParser.c
 * @brief Implementation file for the PE parser. Parsing each parts one by one.
 */

#include <stdio.h>
#include <Windows.h>
#include "peParser.h"
#include "peParserConsts.h"
#include "peParserUtils.h"

 // ANSI escape codes for colors
#define RESET   "\x1b[0m"
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define BOLD    "\x1b[1m"

// Determine if the environment is 32-bit or 64-bit
#if _WIN32 || _WIN64
	#if _WIN64
		#define ENV64BIT
	#else
		#define ENV32BIT
	#endif
#endif

void parse(LPVOID peFileData) {
	printf("[+] Parsing the PE file...\n");
	readDosHeader(peFileData);
	readNTHeader(peFileData);
	readNTFileDataDirectoryEntries(peFileData);
	readNTFileSectionHeaders(peFileData);
}

void readDosHeader(LPVOID peFileData) {
	PIMAGE_DOS_HEADER peFileDosHeader = (PIMAGE_DOS_HEADER)peFileData;
	printf(BOLD "[~] DOS HEADER\n" RESET);
	printf("    Magic number:                          0x%04X\n", peFileDosHeader->e_magic);
	printf("    Bytes on the last page of the file:    0x%04X\n", peFileDosHeader->e_cblp);
	printf("    Pages in the file:                     0x%04X\n", peFileDosHeader->e_cp);
	printf("    Relocations:                           0x%04X\n", peFileDosHeader->e_crlc);
	printf("    Size of the header in paragraphs:      0x%04X\n", peFileDosHeader->e_cparhdr);
	printf("    Minimum extra paragraphs needed:       0x%04X\n", peFileDosHeader->e_minalloc);
	printf("    Maximum extra paragraphs needed:       0x%04X\n", peFileDosHeader->e_maxalloc);
	printf("    Initial (relative) SS value:           0x%04X\n", peFileDosHeader->e_ss);
	printf("    Initial SP value:                      0x%04X\n", peFileDosHeader->e_sp);
	printf("    Initial IP value:                      0x%04X\n", peFileDosHeader->e_ip);
	printf("    Initial (relative) CS value:           0x%04X\n", peFileDosHeader->e_cs);
	printf("    File address of relocation table:      0x%04X\n", peFileDosHeader->e_lfarlc);
	printf("    Overlay number:                        0x%04X\n", peFileDosHeader->e_ovno);
	printf("    OEM identifier (for e_oeminfo):        0x%04X\n", peFileDosHeader->e_oemid);
	printf("    OEM information; e_oemid specific:     0x%04X\n", peFileDosHeader->e_oeminfo);
#if ENV32BIT
	printf("    File address of new exe header:        0x%04X\n", peFileDosHeader->e_lfanew);				// 32-bit (long)
#else
	printf("    File address of new exe header:        0x%08X\n", peFileDosHeader->e_lfanew);				// 64-bit (long)
#endif
}

void readNTHeader(LPVOID peFileData) {
	 PIMAGE_NT_HEADERS peFileNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)peFileData + ((PIMAGE_DOS_HEADER)peFileData)->e_lfanew);

	 // Check if the given NT header is 32-bit or 64-bit
	 WORD magicNumber = (WORD)peFileNtHeader->OptionalHeader.Magic;
	 switch (magicNumber) {
		 case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			 printf(BOLD "[~] NT HEADER (32-bit / Signature: 0x%08X)\n" RESET, peFileNtHeader->Signature);
			 printf(BOLD "    --- File Header ---\n" RESET);
			 readNTFileHeader(peFileData);
			 printf(BOLD "    --- Optional Header ---\n" RESET);
			 readNTFileOptionalHeader32(peFileData);
			 break;
		 case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			 printf(BOLD "[~] NT HEADER (64-bit / Signature: 0x%08X)\n" RESET, peFileNtHeader->Signature);
			 printf(BOLD "    --- File Header ---\n" RESET);
			 readNTFileHeader(peFileData);
			 printf(BOLD "    --- Optional Header ---\n" RESET);
			 readNTFileOptionalHeader64(peFileData);
			 break;
		 default:
			 printf(BOLD RED "[!] Invalid magic number: %04X\n" RESET, magicNumber);
			 exit(1);
			 return;
	 }
}

void readNTFileHeader(LPVOID peFileData) {
	PIMAGE_NT_HEADERS peFileNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)peFileData + ((PIMAGE_DOS_HEADER)peFileData)->e_lfanew);
	PIMAGE_FILE_HEADER peFileNtFileHeader = &peFileNtHeader->FileHeader;

	printf("    Machine:                               0x%04X     (-> %s architecture)\n", peFileNtFileHeader->Machine, getNTImageFileHeaderMachineType(peFileNtFileHeader->Machine));
	printf("    Number of sections:                    0x%04X     (-> %d sections)\n", peFileNtFileHeader->NumberOfSections, peFileNtFileHeader->NumberOfSections);
	printf("    Time date stamp:                       0x%08X (-> %s)\n", peFileNtFileHeader->TimeDateStamp, convertUnixTimeToHumanReadable(peFileNtFileHeader->TimeDateStamp));
	printf("    Pointer to symbol table:               0x%08X\n", peFileNtFileHeader->PointerToSymbolTable);
	printf("    Number of symbols:                     0x%08X (-> %d symbols)\n", peFileNtFileHeader->NumberOfSymbols, peFileNtFileHeader->NumberOfSymbols);
	printf("    Size of optional header:               0x%04X\n", peFileNtFileHeader->SizeOfOptionalHeader);
	dissectNTImageCharacteristics(peFileNtFileHeader->Characteristics);
}

void readNTFileOptionalHeader32(LPVOID peFileData) {
	PIMAGE_NT_HEADERS peFileNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)peFileData + ((PIMAGE_DOS_HEADER)peFileData)->e_lfanew);
	PIMAGE_OPTIONAL_HEADER32 peFileNtOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)(&peFileNtHeader->OptionalHeader);

	printf("    Magic:                                 0x%04X (PE32)\n", peFileNtOptionalHeader32->Magic);
	printf("    Major linker version:                  0x%02X\n", peFileNtOptionalHeader32->MajorLinkerVersion);
	printf("    Minor linker version:                  0x%02X\n", peFileNtOptionalHeader32->MinorLinkerVersion);
	printf("    Size of code(.text):                   0x%08X (-> %d Bytes)\n", peFileNtOptionalHeader32->SizeOfCode, peFileNtOptionalHeader32->SizeOfCode);
	printf("    Size of initialized data(.data):       0x%08X (-> %d Bytes)\n", peFileNtOptionalHeader32->SizeOfInitializedData, peFileNtOptionalHeader32->SizeOfInitializedData);
	printf("    Size of uninitialized data(.bss):      0x%08X (-> %d Bytes)\n", peFileNtOptionalHeader32->SizeOfUninitializedData, peFileNtOptionalHeader32->SizeOfUninitializedData);
	printf("    Address of entry point:                0x%08X\n", peFileNtOptionalHeader32->AddressOfEntryPoint);
	printf("    Base of code:                          0x%08X\n", peFileNtOptionalHeader32->BaseOfCode);
	printf("    Base of data(PE32 Only):               0x%08X\n", peFileNtOptionalHeader32->BaseOfData);
	printf("    Image base:                            0x%08X\n", peFileNtOptionalHeader32->ImageBase);
	printf("    Section alignment:                     0x%08X (-> %d Bytes)\n", peFileNtOptionalHeader32->SectionAlignment, peFileNtOptionalHeader32->SectionAlignment);
	printf("    File alignment:                        0x%08X (-> %d Bytes)\n", peFileNtOptionalHeader32->FileAlignment, peFileNtOptionalHeader32->FileAlignment);
	printf("    Major operating system version:        0x%04X\n", peFileNtOptionalHeader32->MajorOperatingSystemVersion);
	printf("    Minor operating system version:        0x%04X\n", peFileNtOptionalHeader32->MinorOperatingSystemVersion);
	printf("        -> Operating System Version:       %s\n", getNTImageOptionalHeaderOSVersion(peFileNtOptionalHeader32->MajorOperatingSystemVersion, peFileNtOptionalHeader32->MinorOperatingSystemVersion));
	printf("    Major image version:                   0x%04X\n", peFileNtOptionalHeader32->MajorImageVersion);
	printf("    Minor image version:                   0x%04X\n", peFileNtOptionalHeader32->MinorImageVersion);
	printf("    Major subsystem version:               0x%04X\n", peFileNtOptionalHeader32->MajorSubsystemVersion);
	printf("    Minor subsystem version:               0x%04X\n", peFileNtOptionalHeader32->MinorSubsystemVersion);
	printf("    Win32 version value:                   0x%08X\n", peFileNtOptionalHeader32->Win32VersionValue);
	printf("    Size of image:                         0x%08X (-> %d Bytes)\n", peFileNtOptionalHeader32->SizeOfImage, peFileNtOptionalHeader32->SizeOfImage);
	printf("    Size of headers:                       0x%08X (-> %d Bytes)\n", peFileNtOptionalHeader32->SizeOfHeaders, peFileNtOptionalHeader32->SizeOfHeaders);
	printf("    Checksum:                              0x%08X\n", peFileNtOptionalHeader32->CheckSum);
	printf("    Subsystem:                             0x%04X     (-> %s)\n", peFileNtOptionalHeader32->Subsystem, getNTImageOptionalHeaderSubsystemDefinition(peFileNtOptionalHeader32->Subsystem));
	dissectNTImageOptionalHeaderDLLCharacteristics(peFileNtOptionalHeader32->DllCharacteristics);
	printf("    Size of stack reserve:                 0x%08X (-> %d Bytes)\n", peFileNtOptionalHeader32->SizeOfStackReserve, peFileNtOptionalHeader32->SizeOfStackReserve);
	printf("    Size of stack commit:                  0x%08X (-> %d Bytes)\n", peFileNtOptionalHeader32->SizeOfStackCommit, peFileNtOptionalHeader32->SizeOfStackCommit);
	printf("    Size of heap reserve:                  0x%08X (-> %d Bytes)\n", peFileNtOptionalHeader32->SizeOfHeapReserve, peFileNtOptionalHeader32->SizeOfHeapReserve);
	printf("    Size of heap commit:                   0x%08X (-> %d Bytes)\n", peFileNtOptionalHeader32->SizeOfHeapCommit, peFileNtOptionalHeader32->SizeOfHeapCommit);
	printf("    Loader flags:                          0x%08X\n", peFileNtOptionalHeader32->LoaderFlags);
	printf("    Number of RVA and sizes:               0x%08X\n", peFileNtOptionalHeader32->NumberOfRvaAndSizes);
}

void readNTFileOptionalHeader64(LPVOID peFileData) {
	PIMAGE_NT_HEADERS peFileNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)peFileData + ((PIMAGE_DOS_HEADER)peFileData)->e_lfanew);
	PIMAGE_OPTIONAL_HEADER64 peFileNtOptionalHeader64 = &peFileNtHeader->OptionalHeader;

	printf("    Magic:                                 0x%04X (PE32+)\n", peFileNtOptionalHeader64->Magic);
	printf("    Major linker version:                  0x%02X\n", peFileNtOptionalHeader64->MajorLinkerVersion);
	printf("    Minor linker version:                  0x%02X\n", peFileNtOptionalHeader64->MinorLinkerVersion);
	printf("    Size of code(.text):                   0x%08X         (-> %d Bytes)\n", peFileNtOptionalHeader64->SizeOfCode, peFileNtOptionalHeader64->SizeOfCode);
	printf("    Size of initialized data(.data):       0x%08X         (-> %d Bytes)\n", peFileNtOptionalHeader64->SizeOfInitializedData, peFileNtOptionalHeader64->SizeOfInitializedData);
	printf("    Size of uninitialized data(.bss):      0x%08X         (-> %d Bytes)\n", peFileNtOptionalHeader64->SizeOfUninitializedData, peFileNtOptionalHeader64->SizeOfUninitializedData);
	printf("    Address of entry point:                0x%08X\n", peFileNtOptionalHeader64->AddressOfEntryPoint);
	printf("    Base of code:                          0x%08X\n", peFileNtOptionalHeader64->BaseOfCode);
	printf("    Image base:                            0x%016llX\n", peFileNtOptionalHeader64->ImageBase);
	printf("    Section alignment:                     0x%08X         (-> %d Bytes)\n", peFileNtOptionalHeader64->SectionAlignment, peFileNtOptionalHeader64->SectionAlignment);
	printf("    File alignment:                        0x%08X         (-> %d Bytes)\n", peFileNtOptionalHeader64->FileAlignment, peFileNtOptionalHeader64->FileAlignment);
	printf("    Major operating system version:        0x%04X\n", peFileNtOptionalHeader64->MajorOperatingSystemVersion);
	printf("    Minor operating system version:        0x%04X\n", peFileNtOptionalHeader64->MinorOperatingSystemVersion);
	printf("        -> Operating System Version:       %s\n", getNTImageOptionalHeaderOSVersion(peFileNtOptionalHeader64->MajorOperatingSystemVersion, peFileNtOptionalHeader64->MinorOperatingSystemVersion));
	printf("    Major image version:                   0x%04X\n", peFileNtOptionalHeader64->MajorImageVersion);
	printf("    Minor image version:                   0x%04X\n", peFileNtOptionalHeader64->MinorImageVersion);
	printf("    Major subsystem version:               0x%04X\n", peFileNtOptionalHeader64->MajorSubsystemVersion);
	printf("    Minor subsystem version:               0x%04X\n", peFileNtOptionalHeader64->MinorSubsystemVersion);
	printf("    Win32 version value:                   0x%08X\n", peFileNtOptionalHeader64->Win32VersionValue);
	printf("    Size of image:                         0x%08X         (-> %d Bytes)\n", peFileNtOptionalHeader64->SizeOfImage, peFileNtOptionalHeader64->SizeOfImage);
	printf("    Size of headers:                       0x%08X         (-> %d Bytes)\n", peFileNtOptionalHeader64->SizeOfHeaders, peFileNtOptionalHeader64->SizeOfHeaders);
	printf("    Checksum:                              0x%08X\n", peFileNtOptionalHeader64->CheckSum);
	printf("    Subsystem:                             0x%04X             (-> %s)\n", peFileNtOptionalHeader64->Subsystem, getNTImageOptionalHeaderSubsystemDefinition(peFileNtOptionalHeader64->Subsystem));
	dissectNTImageOptionalHeaderDLLCharacteristics(peFileNtOptionalHeader64->DllCharacteristics);
	printf("    Size of stack reserve:                 0x%016llX (-> %lld Bytes)\n", peFileNtOptionalHeader64->SizeOfStackReserve, peFileNtOptionalHeader64->SizeOfStackReserve);
	printf("    Size of stack commit:                  0x%016llX (-> %lld Bytes)\n", peFileNtOptionalHeader64->SizeOfStackCommit, peFileNtOptionalHeader64->SizeOfStackCommit);
	printf("    Size of heap reserve:                  0x%016llX (-> %lld Bytes)\n", peFileNtOptionalHeader64->SizeOfHeapReserve, peFileNtOptionalHeader64->SizeOfHeapReserve);
	printf("    Size of heap commit:                   0x%016llX (-> %lld Bytes)\n", peFileNtOptionalHeader64->SizeOfHeapCommit, peFileNtOptionalHeader64->SizeOfHeapCommit);
	printf("    Loader flags:                          0x%08X\n", peFileNtOptionalHeader64->LoaderFlags);
	printf("    Number of RVA and sizes:               0x%08X\n", peFileNtOptionalHeader64->NumberOfRvaAndSizes);
}

void readNTFileDataDirectoryEntries(LPVOID peFileData) {
	PIMAGE_NT_HEADERS peFileNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)peFileData + ((PIMAGE_DOS_HEADER)peFileData)->e_lfanew);
	PIMAGE_OPTIONAL_HEADER peFileNtOptionalHeader = &peFileNtHeader->OptionalHeader;

	printf(BOLD "[~] DATA DIRECTORY ENTRIES\n" RESET);
	printf("    +----------+-----------------------------------+---------------------+------------+\n");
	printf("    |  Index   |          Directory Name           |   Virtual Address   |    Size    |\n");
	printf("    +----------+-----------------------------------+---------------------+------------+\n");
	for (int i = 0; i < peFileNtOptionalHeader->NumberOfRvaAndSizes; i++) {
		printf("    |    %02d    | %33s |  0x%016llX | 0x%08X |\n", i, getNTImageOptionalHeaderDataDirectoryName(i), 
																		peFileNtOptionalHeader->DataDirectory[i].VirtualAddress, 
																		peFileNtOptionalHeader->DataDirectory[i].Size);
	}
	printf("    +----------+-----------------------------------+---------------------+------------+\n");
}

void readNTFileSectionHeaders(LPVOID peFileData) {
	PIMAGE_NT_HEADERS peFileNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)peFileData + ((PIMAGE_DOS_HEADER)peFileData)->e_lfanew);
	PIMAGE_SECTION_HEADER peFileSectionHeader = IMAGE_FIRST_SECTION(peFileNtHeader);

	

	printf(BOLD "[~] SECTION HEADERS\n" RESET);
	for (int i = 0; i < peFileNtHeader->FileHeader.NumberOfSections; i++) {
		printf("    Section %d: %s\n", i + 1, peFileSectionHeader[i].Name);
		printf("        Virtual Size:                      0x%08X\n", peFileSectionHeader[i].Misc.VirtualSize);
		printf("        Virtual Address:                   0x%08X\n", peFileSectionHeader[i].VirtualAddress);
		printf("        Size of Raw Data:                  0x%08X\n", peFileSectionHeader[i].SizeOfRawData);
		printf("        Pointer to Raw Data:               0x%08X\n", peFileSectionHeader[i].PointerToRawData);
		printf("        Pointer to Relocations:            0x%08X\n", peFileSectionHeader[i].PointerToRelocations);
		printf("        Pointer to Line Numbers:           0x%08X\n", peFileSectionHeader[i].PointerToLinenumbers);
		printf("        Number of Relocations:             0x%04X\n", peFileSectionHeader[i].NumberOfRelocations);
		printf("        Number of Line Numbers:            0x%04X\n", peFileSectionHeader[i].NumberOfLinenumbers);
		printf("        Characteristics:                   0x%08X\n", peFileSectionHeader[i].Characteristics);
		dissectNTImageSectionHeaderCharacteristics(peFileSectionHeader[i].Characteristics);
	}
}
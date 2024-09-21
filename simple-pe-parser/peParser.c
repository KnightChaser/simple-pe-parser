/**
 * @file peParser.c
 * @brief Implementation file for the PE parser. Parsing each parts one by one.
 */

#include <stdio.h>
#include <Windows.h>
#include "peParser.h"
#include "peParserConsts.h"
#include "peParserUtils.h"

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
}

void readDosHeader(LPVOID peFileData) {
	PIMAGE_DOS_HEADER peFileDosHeader = (PIMAGE_DOS_HEADER)peFileData;
	printf("[~] DOS HEADER\n");
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
			 printf("[~] NT HEADER (32-bit / Signature: 0x%08X)\n", peFileNtHeader->Signature);
			 readNTFileHeader(peFileData);
			 break;
		 case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			 printf("[~] NT HEADER (64-bit / Signature: 0x%08X)\n", peFileNtHeader->Signature);
			 readNTFileHeader(peFileData);
			 break;
		 default:
			 printf("[!] Invalid magic number: %04X\n", magicNumber);
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
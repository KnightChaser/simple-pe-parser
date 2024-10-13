/**
 * @file peParserUtils.c
 * @brief Utility functions for the PE parser
 */

#include <stdio.h>
#include <windows.h>
#include <time.h>

 // Convert a DWORD representing a Unix timestamp to a human-readable string
char* convertUnixTimeToHumanReadable(DWORD unixTime) {
	time_t timestamp = unixTime;
	char* timeString = ctime(&timestamp);
	timeString[strlen(timeString) - 1] = '\0'; // Remove newline character

	return timeString;
}

// Convert an RVA(Relative Virtual Address) to a file offset
DWORD rvaToFileOffset(PIMAGE_NT_HEADERS ntHeader, DWORD rva) {
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

	for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, sectionHeader++) {
		DWORD sectionStart = sectionHeader->VirtualAddress;
		DWORD sectionEnd = sectionStart + sectionHeader->Misc.VirtualSize;

		// If RVA is within this section
		if (rva >= sectionStart && rva < sectionEnd) {
			DWORD delta = rva - sectionStart;
			return sectionHeader->PointerToRawData + delta;
		}
	}

	// If we can't find a matching section, return the original RVA
	// This might indicate a malformed PE file or an incorrect assumption
	return rva;
}

// Read DWORD(Double Word) from memory(LPVOID peFileData) at the specified offset
DWORD readDwordFromMemory(LPVOID peFileData, DWORD offset) {
	return *(DWORD*)((BYTE*)peFileData + offset);
}
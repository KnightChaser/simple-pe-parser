/**
 * @file peParser.c
 * @brief Implementation file for the PE parser. Parsing each parts one by one.
 */

#include <stdio.h>
#include <Windows.h>
#include "peParser.h"

void parse(LPVOID peFileData) {
	printf("[+] Parsing the PE file...\n");
	readDosHeader(peFileData);
}

void readDosHeader(LPVOID peFileData) {
	PIMAGE_DOS_HEADER peFileDosHeader = (PIMAGE_DOS_HEADER)peFileData;
	printf("[~] DOS HEADER\n");
	printf(" Magic number:                          0x%04X\n", peFileDosHeader->e_magic);
	printf(" Bytes on the last page of the file:    0x%04X\n", peFileDosHeader->e_cblp);
	printf(" Pages in the file:                     0x%04X\n", peFileDosHeader->e_cp);
	printf(" Relocations:                           0x%04X\n", peFileDosHeader->e_crlc);
	printf(" Size of the header in paragraphs:      0x%04X\n", peFileDosHeader->e_cparhdr);
	printf(" Minimum extra paragraphs needed:       0x%04X\n", peFileDosHeader->e_minalloc);
	printf(" Maximum extra paragraphs needed:       0x%04X\n", peFileDosHeader->e_maxalloc);
	printf(" Initial (relative) SS value:           0x%04X\n", peFileDosHeader->e_ss);
	printf(" Initial SP value:                      0x%04X\n", peFileDosHeader->e_sp);
	printf(" Initial IP value:                      0x%04X\n", peFileDosHeader->e_ip);
	printf(" Initial (relative) CS value:           0x%04X\n", peFileDosHeader->e_cs);
	printf(" File address of relocation table:      0x%04X\n", peFileDosHeader->e_lfarlc);
	printf(" Overlay number:                        0x%04X\n", peFileDosHeader->e_ovno);
	printf(" OEM identifier (for e_oeminfo):        0x%04X\n", peFileDosHeader->e_oemid);
	printf(" OEM information; e_oemid specific:     0x%04X\n", peFileDosHeader->e_oeminfo);
	printf(" File address of new exe header:        0x%04X\n", peFileDosHeader->e_lfanew);
}
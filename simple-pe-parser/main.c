/**
 * @file main.c
 * @brief Main file for the simple PE parser
 */

#include <stdio.h>
#include <Windows.h>
#include "peParser.h"

int main(int argc, char* argv[]) {
	if (argc != 2) {
		printf("Usage: %s <PE file>\n", argv[0]);
		return 1;
	}

    const char* filename = argv[1];

	HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to open the file.\n");
		return 1;
	} else {
		printf("[+] File \"%s\" opened successfully.\n", filename);
		printf("[+] File size: %d bytes\n", GetFileSize(hFile, NULL));

        // Read the PE file into memory
        LPVOID peFileData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, GetFileSize(hFile, NULL));
        if (peFileData == NULL) {
            printf("[!] Failed to allocate memory for the file.\n");
            CloseHandle(hFile);
            return 1;
        }

        DWORD bytesRead = 0;
        if (!ReadFile(hFile, peFileData, GetFileSize(hFile, NULL), &bytesRead, NULL) &&
            bytesRead != GetFileSize(hFile, NULL)) {
            printf("[!] Failed to read the file.\n");
            HeapFree(GetProcessHeap(), 0, peFileData);
            CloseHandle(hFile);
            return 1;
        } else {
            printf("[+] File read successfully.\n");
        }

        // Proceed safely to check the magic number
        WORD magicNumber = *(WORD*)((BYTE*)peFileData + 0x00);
        if (magicNumber != 0x5A4D) {
            printf("[!] Invalid PE file. The first 2 bytes were %04X.\n", magicNumber);
            HeapFree(GetProcessHeap(), 0, peFileData);
            CloseHandle(hFile);
            return 1;
        } else {
            printf("[+] Valid PE file.\n");
        }

        parse(peFileData);

        // Free the allocated memory before exiting
        HeapFree(GetProcessHeap(), 0, peFileData);
        CloseHandle(hFile);
	}

	return 0;
}
/**
 * @file main.c
 * @brief Main file for the simple PE parser
 */

#include <stdio.h>
#include <Windows.h>
#include "peParser.h"

 // ANSI escape codes for colors
#define RESET   "\x1b[0m"
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define BOLD    "\x1b[1m"

int main(int argc, char* argv[]) {
	if (argc != 2) {
		printf(BOLD RED "[!] Usage: %s <PE file>\n" RESET, argv[0]);
		return 1;
	}

    const char* filename = argv[1];

	HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf(BOLD RED "[!] Failed to open the file.\n" RESET);
		return 1;
	} else {
		printf(BOLD GREEN "[+] File \"%s\" opened successfully.\n" RESET, filename);
		printf(BOLD "[+] File size: %d bytes\n" RESET, GetFileSize(hFile, NULL));

        // Read the PE file into memory
        LPVOID peFileData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, GetFileSize(hFile, NULL));
        if (peFileData == NULL) {
            printf(BOLD RED "[!] Failed to allocate memory for the file.\n" RESET);
            CloseHandle(hFile);
            return 1;
        }

        DWORD bytesRead = 0;
        if (!ReadFile(hFile, peFileData, GetFileSize(hFile, NULL), &bytesRead, NULL) &&
            bytesRead != GetFileSize(hFile, NULL)) {
            printf(BOLD RED "[!] Failed to read the file.\n" RESET);
            HeapFree(GetProcessHeap(), 0, peFileData);
            CloseHandle(hFile);
            return 1;
        } else {
            printf(BOLD GREEN "[+] File read successfully.\n" RESET);
        }

        // Proceed safely to check the magic number
        WORD magicNumber = *(WORD*)((BYTE*)peFileData + 0x00);
        if (magicNumber != 0x5A4D) {
            printf(BOLD RED "[!] Invalid PE file. The first 2 bytes were %04X.\n" RESET, magicNumber);
            HeapFree(GetProcessHeap(), 0, peFileData);
            CloseHandle(hFile);
            return 1;
        } else {
            printf(BOLD GREEN "[+] Valid PE file.\n" RESET);
        }

        parse(peFileData);

        // Free the allocated memory before exiting
        HeapFree(GetProcessHeap(), 0, peFileData);
        CloseHandle(hFile);
	}

	return 0;
}
/**
 * @file peParserUtils.h
 * @brief Utility functions for the PE parser
 */

#ifndef PE_PARSER_UTILS_H
#define PE_PARSER_UTILS_H

#include <stdio.h>
#include <windows.h>

char* convertUnixTimeToHumanReadable(DWORD unixTime);
DWORD rvaToFileOffset(PIMAGE_NT_HEADERS ntHeader, DWORD rva);
DWORD readDwordFromMemory(LPVOID peFileData, DWORD offset);

#endif // PE_PARSER_UTILS_H
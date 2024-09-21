/**
 * @file peParser.h
 * @brief Header file for the PE parser
 */

#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <stdio.h>
#include <Windows.h>

void parse(LPVOID peFileData);
void readDosHeader(LPVOID peFileData);
void readNTHeader(LPVOID peFileData);
void readNTFileHeader(LPVOID peFileData);
void readNTFileOptionalHeader32(LPVOID peFileData);
void readNTFileOptionalHeader64(LPVOID peFileData);
void readNTFileDataDirectoryEntries(LPVOID peFileData);
void readNTFileSectionHeaders(LPVOID peFileData);

#endif // PE_PARSER_H
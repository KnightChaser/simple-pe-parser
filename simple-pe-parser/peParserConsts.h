/**
 * @file peParserConsts.h
 * @brief Constants for the PE parser
 */

#ifndef PE_PARSER_CONSTS_H
#define PE_PARSER_CONSTS_H

#include <stdio.h>
#include <Windows.h>

char* getNTImageFileHeaderMachineType(WORD machineType);
void dissectNTImageCharacteristics(DWORD characteristics);
char* getNTImageOptionalHeaderOSVersion(DWORD majorVersion, DWORD minorVersion);
char* getNTImageOptionalHeaderSubsystemDefinition(DWORD subsystem);
char* dissectNTImageOptionalHeaderDLLCharacteristics(DWORD characteristics);
char* getNTImageOptionalHeaderDataDirectoryName(DWORD dataDirectoryIndex);
void dissectNTImageSectionHeaderCharacteristics(DWORD characteristics);
char* getNTImageRelocationType(WORD type);

#endif // PE_PARSER_CONSTS_H
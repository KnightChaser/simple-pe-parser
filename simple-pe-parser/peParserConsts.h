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

#endif // PE_PARSER_CONSTS_H
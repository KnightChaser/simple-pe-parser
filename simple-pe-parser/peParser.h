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

#endif // PE_PARSER_H
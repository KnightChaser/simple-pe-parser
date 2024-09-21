/**
 * @file peParserUtils.c
 * @brief Utility functions for the PE parser
 */

#include <stdio.h>
#include <windows.h>
#include <time.h>

char* convertUnixTimeToHumanReadable(DWORD unixTime) {
	time_t timestamp = unixTime;
	char* timeString = ctime(&timestamp);
	timeString[strlen(timeString) - 1] = '\0'; // Remove newline character

	return timeString;
}
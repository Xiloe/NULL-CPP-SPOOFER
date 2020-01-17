#pragma once
#include <windows.h>
#include <iostream>
#include <memory>
#include <string>
#include <cstdio>
#include <ctime>

// Different Log Types
struct S_LogType
{
	int Default = 15;
	int Warning = 6;
	int Success = 2;
	int Error = 4;
	int Info = 11;
};

// Log a message in the console with a timestamp. LogType changes the color of the text.
void Log(std::string Message, int LogType);

// Return the diskdrive serialnumber.
std::string GetHWID();
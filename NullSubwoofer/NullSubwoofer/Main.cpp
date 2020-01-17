#include "Utils.h"		// Utilities.

int main()
{
	SetConsoleTitleA("Null 1.0 | 0x00#3042 | Build: nIvU2VHR0cDovL3d3dy5kZXYtc3RvcmUuZnIv4ZURlQ2hldmFaHR0cDovL3d3dy5kHR0cDovL3d3dy5kZXYtc3RvcmUuZnIvZXYtc3RvcmUuZn");

	S_LogType LogType;

	Log("Default.", LogType.Default);
	Log("Warning.", LogType.Warning);
	Log("Success.", LogType.Success);
	Log("Error.", LogType.Error);
	Log("Info.\n", LogType.Info);

	Log("Custom.", 3);
	Log("Custom.", 5);
	Log("Custom.\n", 23);

	CHAR SERIAL[] = "----------";
	CHAR CUSTOM[] = "NULL-";

	Log("SERIAL = " + std::to_string(((DWORD)strlen(SERIAL))), LogType.Info);
	Log("CUSTOM = " + std::to_string(((DWORD)strlen(CUSTOM))), LogType.Info);
	Log("SUM    = " + std::to_string(((DWORD)strlen(SERIAL) + (DWORD)strlen(CUSTOM))), LogType.Success);

	Beep(3000, 100);
	Sleep(60000);
	return 0;
}
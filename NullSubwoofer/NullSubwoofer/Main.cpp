#include "Utils.h"		// Utils functions.
#include "Main.h"		// Main functions.


// TODO: Finish this shit I want money ffs
// UPDATE: Fuck memory protection.


int main()
{
	SetConsoleTitleA("Null 1.0 | 0x00#3042 | Build: idk");

	S_LogType LogType;
	std::string HWID = GetHWID();

	Log("Getting latest version", LogType.Info);

	// Download here / or RunPE shit ?

	Log("Done\n", LogType.Success);
	Sleep(2000);

	Log("Press a key to start\n", LogType.Info);
	getchar();

	if (HWID.find("NULL") != std::string::npos)
	{
		Log("Already Spoofed, please restart your computer\n", LogType.Default);
		Beep(230, 200);
		Sleep(2000);
		return -1;
	}

	Log("Cleaning Traces", LogType.Default); Sleep(3000);

	// Clean here you fag

	Log("Cleaned Traces\n", LogType.Success);

	Log("Resetting Adapters", LogType.Default);

	// Reset here you fag

	Log("Skipped Reset Adapters\n", LogType.Success);

	Log("Spoofing DiskDrive(s), Volume ID(s), NIC, SMBIOS, GPU, CPU, BaseBoard", LogType.Default); Sleep(5000);
	Log("Old C: Serial: " + HWID, LogType.Warning);

	// Spoof here you fag

	Log("New C: Serial: " + HWID, LogType.Warning);
	Log("Spoofed DiskDrive(s), Volume ID(s), NIC, SMBIOS, GPU, CPU, BaseBoard\n", LogType.Success);

	Log("Spoofer done.", LogType.Default);

	Beep(523, 100);
	Sleep(3000);
	return 0;
}
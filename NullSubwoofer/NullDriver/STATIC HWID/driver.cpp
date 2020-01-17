#include "stdafx.h"

static uintptr_t get_kernel_address(const char* name, size_t& size) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	ZwQuerySystemInformation(
		SystemModuleInformation,
		&neededSize,
		0,
		&neededSize
	);

	PSYSTEM_MODULE_INFORMATION pModuleList;

	pModuleList = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, neededSize);

	if (!pModuleList) {
		return 0;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation,
		pModuleList,
		neededSize,
		0
	);

	ULONG i = 0;
	uintptr_t address = 0;

	for (i = 0; i < pModuleList->ulModuleCount; i++)
	{
		SYSTEM_MODULE mod = pModuleList->Modules[i];

		address = uintptr_t(pModuleList->Modules[i].Base);
		size = uintptr_t(pModuleList->Modules[i].Size);
		if (strstr(mod.ImageName, name) != NULL)
			break;
	}

	ExFreePool(pModuleList);

	return address;
}

template <typename t = void*>
t find_pattern(void* start, size_t length, const char* pattern, const char* mask) {
	const auto data = static_cast<const char*>(start);
	const auto pattern_length = strlen(mask);

	for (size_t i = 0; i <= length - pattern_length; i++)
	{
		bool accumulative_found = true;

		for (size_t j = 0; j < pattern_length; j++)
		{
			if (!MmIsAddressValid(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(data) + i + j)))
			{
				accumulative_found = false;
				break;
			}

			if (data[i + j] != pattern[j] && mask[j] != '?')
			{
				accumulative_found = false;
				break;
			}
		}

		if (accumulative_found)
		{
			return (t)(reinterpret_cast<uintptr_t>(data) + i);
		}
	}

	return (t)nullptr;
}

uintptr_t dereference(uintptr_t address, unsigned int offset) {
	if (address == 0)
		return 0;

	return address + (int)((*(int*)(address + offset) + offset) + sizeof(int));
}

void spoof_drives()
{
	INT count = 0;

	size_t storportSize = 0;
	UINT64 storportBase = get_kernel_address("storport.sys", storportSize);

	RTL_OSVERSIONINFOW osVersion = { 0 };
	osVersion.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	RtlGetVersion(&osVersion);

	PDEVICE_OBJECT pObject = NULL;
	PFILE_OBJECT pFileObj = NULL;

	UNICODE_STRING DestinationString;
	RtlInitUnicodeString(&DestinationString, L"\\Device\\RaidPort0");

	NTSTATUS status = IoGetDeviceObjectPointer(&DestinationString, FILE_READ_DATA, &pFileObj, &pObject);

	PDRIVER_OBJECT pDriver = pObject->DriverObject;

	PDEVICE_OBJECT pDevice = pDriver->DeviceObject;

	// 1909
	if (osVersion.dwBuildNumber >= 18363) {
		RaidUnitRegisterInterfaces1909 pRegDevInt = find_pattern<RaidUnitRegisterInterfaces1909>((void*)storportBase, storportSize, "\x48\x89\x5C\x24\x00\x55\x56\x57\x48\x83\xEC\x50", "xxxx?xxxxxxx");

		while (pDevice->NextDevice != NULL)
		{
			if (pDevice->DeviceType == FILE_DEVICE_DISK)
			{
				PHDD_EXTENSION1909 pDeviceHDD = (PHDD_EXTENSION1909)pDevice->DeviceExtension;

				CHAR HDDSPOOFED_TMP[32] = { 0x0 };
				randstring(HDDSPOOFED_TMP, SERIAL_MAX_LENGTH - 1);

				for (int i = 1; i <= SERIAL_MAX_LENGTH + 1; i = i + 2)
				{
					memcpy(&HDDORG_BUFFER[count][i - 1], &pDeviceHDD->pHDDSerial[i], sizeof(CHAR));
					memcpy(&HDDORG_BUFFER[count][i], &pDeviceHDD->pHDDSerial[i - 1], sizeof(CHAR));

					memcpy(&HDDSPOOF_BUFFER[count][i - 1], &HDDSPOOFED_TMP[i], sizeof(CHAR));
					memcpy(&HDDSPOOF_BUFFER[count][i], &HDDSPOOFED_TMP[i - 1], sizeof(CHAR));
				}

				RtlStringCchPrintfA(pDeviceHDD->pHDDSerial, SERIAL_MAX_LENGTH + 1, "%s", &HDDSPOOFED_TMP);

				pRegDevInt(pDeviceHDD);

				count++;
			}

			pDevice = pDevice->NextDevice;
		}
	}

	// 1903
	else if (osVersion.dwBuildNumber >= 18362) {
		RaidUnitRegisterInterfaces1903 pRegDevInt = find_pattern<RaidUnitRegisterInterfaces1903>((void*)storportBase, storportSize, "\x48\x89\x5C\x24\x00\x55\x56\x57\x48\x83\xEC\x50", "xxxx?xxxxxxx");

		while (pDevice->NextDevice != NULL)
		{
			if (pDevice->DeviceType == FILE_DEVICE_DISK)
			{
				PHDD_EXTENSION1903 pDeviceHDD = (PHDD_EXTENSION1903)pDevice->DeviceExtension;

				CHAR HDDSPOOFED_TMP[32] = { 0x0 };
				randstring(HDDSPOOFED_TMP, SERIAL_MAX_LENGTH - 1);

				for (int i = 1; i <= SERIAL_MAX_LENGTH + 1; i = i + 2)
				{
					memcpy(&HDDORG_BUFFER[count][i - 1], &pDeviceHDD->pHDDSerial[i], sizeof(CHAR));
					memcpy(&HDDORG_BUFFER[count][i], &pDeviceHDD->pHDDSerial[i - 1], sizeof(CHAR));

					memcpy(&HDDSPOOF_BUFFER[count][i - 1], &HDDSPOOFED_TMP[i], sizeof(CHAR));
					memcpy(&HDDSPOOF_BUFFER[count][i], &HDDSPOOFED_TMP[i - 1], sizeof(CHAR));
				}

				RtlStringCchPrintfA(pDeviceHDD->pHDDSerial, SERIAL_MAX_LENGTH + 1, "%s", &HDDSPOOFED_TMP);

				pRegDevInt(pDeviceHDD);

				count++;
			}

			pDevice = pDevice->NextDevice;
		}
	}

	// 1809
	else if (osVersion.dwBuildNumber >= 17763) {
		RaidUnitRegisterInterfaces1809 pRegDevInt = find_pattern<RaidUnitRegisterInterfaces1809>((void*)storportBase, storportSize, "\x48\x89\x5C\x24\x00\x55\x56\x57\x48\x83\xEC\x50", "xxxx?xxxxxxx");

		while (pDevice->NextDevice != NULL)
		{
			if (pDevice->DeviceType == FILE_DEVICE_DISK)
			{
				PHDD_EXTENSION1809 pDeviceHDD = (PHDD_EXTENSION1809)pDevice->DeviceExtension;

				CHAR HDDSPOOFED_TMP[32] = { 0x0 };
				randstring(HDDSPOOFED_TMP, SERIAL_MAX_LENGTH - 1);

				for (int i = 1; i <= SERIAL_MAX_LENGTH + 1; i = i + 2)
				{
					memcpy(&HDDORG_BUFFER[count][i - 1], &pDeviceHDD->pHDDSerial[i], sizeof(CHAR));
					memcpy(&HDDORG_BUFFER[count][i], &pDeviceHDD->pHDDSerial[i - 1], sizeof(CHAR));

					memcpy(&HDDSPOOF_BUFFER[count][i - 1], &HDDSPOOFED_TMP[i], sizeof(CHAR));
					memcpy(&HDDSPOOF_BUFFER[count][i], &HDDSPOOFED_TMP[i - 1], sizeof(CHAR));
				}

				RtlStringCchPrintfA(pDeviceHDD->pHDDSerial, SERIAL_MAX_LENGTH + 1, "%s", &HDDSPOOFED_TMP);

				pRegDevInt(pDeviceHDD);

				count++;
			}

			pDevice = pDevice->NextDevice;
		}
	}

	// 1803
	else if (osVersion.dwBuildNumber >= 17134) {
		RaidUnitRegisterInterfaces1803 pRegDevInt = find_pattern<RaidUnitRegisterInterfaces1803>((void*)storportBase, storportSize, "\x48\x89\x5C\x24\x00\x55\x56\x57\x48\x83\xEC\x50", "xxxx?xxxxxxx");

		while (pDevice->NextDevice != NULL)
		{
			if (pDevice->DeviceType == FILE_DEVICE_DISK)
			{
				PHDD_EXTENSION1803 pDeviceHDD = (PHDD_EXTENSION1803)pDevice->DeviceExtension;

				CHAR HDDSPOOFED_TMP[32] = { 0x0 };
				randstring(HDDSPOOFED_TMP, SERIAL_MAX_LENGTH - 1);

				for (int i = 1; i <= SERIAL_MAX_LENGTH + 1; i = i + 2)
				{
					memcpy(&HDDORG_BUFFER[count][i - 1], &pDeviceHDD->pHDDSerial[i], sizeof(CHAR));
					memcpy(&HDDORG_BUFFER[count][i], &pDeviceHDD->pHDDSerial[i - 1], sizeof(CHAR));

					memcpy(&HDDSPOOF_BUFFER[count][i - 1], &HDDSPOOFED_TMP[i], sizeof(CHAR));
					memcpy(&HDDSPOOF_BUFFER[count][i], &HDDSPOOFED_TMP[i - 1], sizeof(CHAR));
				}

				RtlStringCchPrintfA(pDeviceHDD->pHDDSerial, SERIAL_MAX_LENGTH + 1, "%s", &HDDSPOOFED_TMP);

				pRegDevInt(pDeviceHDD);

				count++;
			}

			pDevice = pDevice->NextDevice;
		}
	}
}

extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	spoof_drives();

	return STATUS_SUCCESS;
}


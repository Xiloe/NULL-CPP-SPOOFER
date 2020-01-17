#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <intrin.h>
#include <stdlib.h>
#include <Ntstrsafe.h>

#define MAX_HDDS 10
#define SERIAL_MAX_LENGTH 15

CHAR HDDSPOOF_BUFFER[MAX_HDDS][32] = { 0x20 };
CHAR HDDORG_BUFFER[MAX_HDDS][32] = { 0 };

typedef NTSTATUS(__fastcall* DISK_FAIL_PREDICTION)(PVOID device_extension, BYTE enable);
typedef NTSTATUS(__fastcall* RU_REGISTER_INTERFACES)(PVOID device_extension);
extern POBJECT_TYPE* IoDriverObjectType;
NTKERNELAPI NTSTATUS ObReferenceObjectByName(IN PUNICODE_STRING ObjectName, IN ULONG Attributes, IN PACCESS_STATE PassedAccessState, IN ACCESS_MASK DesiredAccess, IN POBJECT_TYPE ObjectType, IN KPROCESSOR_MODE AccessMode, IN OUT PVOID ParseContext, OUT PVOID* Object);
NTSTATUS NTAPI ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

// 1909 - NEED UPDATE
typedef struct _VendorInfo1909
{
	char pad_0x0000[0x8];
	char Info[64];
} VendorInfo1909;

typedef struct _HDD_EXTENSION1909
{
	char pad_0x0000[0x68];
	VendorInfo1909* pVendorInfo;
	char pad_0x0068[0x8];
	char* pHDDSerial;
} *PHDD_EXTENSION1909;

// 1903
typedef struct _VendorInfo1903
{
	char pad_0x0000[0x8];
	char Info[64];
} VendorInfo1903;

typedef struct _HDD_EXTENSION1903
{
	char pad_0x0000[0x68];
	VendorInfo1903* pVendorInfo;
	char pad_0x0068[0x8];
	char* pHDDSerial;
} *PHDD_EXTENSION1903;

// 1809
typedef struct _VendorInfo1809
{
	char pad_0x0000[0x8];
	char Info[64];
} VendorInfo1809;

typedef struct _HDD_EXTENSION1809
{
	char pad_0x0000[0x60];
	VendorInfo1809* pVendorInfo;
	char pad_0x0068[0x8];
	char* pHDDSerial;
	char pad_0x0078[0x30];
} *PHDD_EXTENSION1809;

// 1803
typedef struct _VendorInfo1803
{
	char pad_0x0000[0x8];
	char Info[64];
} VendorInfo1803;

typedef struct _HDD_EXTENSION1803
{
	char pad_0x0000[0x58];
	VendorInfo1803* pVendorInfo;
	char pad_0x0068[0x8];
	char* pHDDSerial;
	char pad_0x0078[0x30];
} *PHDD_EXTENSION1803;

typedef __int64(__fastcall* RaidUnitRegisterInterfaces1909)(PHDD_EXTENSION1909 a1);
typedef __int64(__fastcall* RaidUnitRegisterInterfaces1903)(PHDD_EXTENSION1903 a1);
typedef __int64(__fastcall* RaidUnitRegisterInterfaces1809)(PHDD_EXTENSION1809 a1);
typedef __int64(__fastcall* RaidUnitRegisterInterfaces1803)(PHDD_EXTENSION1803 a1);

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemInformationClassMin = 0,
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemNotImplemented1 = 4,
	SystemProcessInformation = 5,
	SystemProcessesAndThreadsInformation = 5,
	SystemCallCountInfoInformation = 6,
	SystemCallCounts = 6,
	SystemDeviceInformation = 7,
	SystemConfigurationInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemProcessorTimes = 8,
	SystemFlagsInformation = 9,
	SystemGlobalFlag = 9,
	SystemCallTimeInformation = 10,
	SystemNotImplemented2 = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemLockInformation = 12,
	SystemStackTraceInformation = 13,
	SystemNotImplemented3 = 13,
	SystemPagedPoolInformation = 14,
	SystemNotImplemented4 = 14,
	SystemNonPagedPoolInformation = 15,
	SystemNotImplemented5 = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemPagefileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemInstructionEmulationCounts = 19,
	SystemVdmBopInformation = 20,
	SystemInvalidInfoClass1 = 20,
	SystemFileCacheInformation = 21,
	SystemCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemProcessorStatistics = 23,
	SystemDpcBehaviourInformation = 24,
	SystemDpcInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemNotImplemented6 = 25,
	SystemLoadImage = 26,
	SystemUnloadImage = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemTimeAdjustment = 28,
	SystemSummaryMemoryInformation = 29,
	SystemNotImplemented7 = 29,
	SystemNextEventIdInformation = 30,
	SystemNotImplemented8 = 30,
	SystemEventIdsInformation = 31,
	SystemNotImplemented9 = 31,
	SystemCrashDumpInformation = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemLoadAndCallImage = 38,
	SystemPrioritySeparation = 39,
	SystemPlugPlayBusInformation = 40,
	SystemNotImplemented10 = 40,
	SystemDockInformation = 41,
	SystemNotImplemented11 = 41,
	/* SystemPowerInformation = 42, Conflicts with POWER_INFORMATION_LEVEL 1 */
	SystemInvalidInfoClass2 = 42,
	SystemProcessorSpeedInformation = 43,
	SystemInvalidInfoClass3 = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemSetTimeSlipEvent = 46,
	SystemCreateSession = 47,
	SystemDeleteSession = 48,
	SystemInvalidInfoClass4 = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemAddVerifier = 52,
	SystemSessionProcessesInformation = 53,
	SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_BASIC_INFORMATION
{
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	KAFFINITY ActiveProcessorsAffinityMask;
	CHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_MODULE   // Information Class 11
{
	ULONG_PTR Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION   // Information Class 11
{
	ULONG_PTR ulModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

extern "C"
{
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
		IN PEPROCESS		SourceProcess,
		IN PVOID			SourceAddress,
		IN PEPROCESS		TargetProcess,
		IN PVOID			TargetAddress,
		IN SIZE_T			BufferSize,
		IN KPROCESSOR_MODE  PreviousMode,
		OUT PSIZE_T			ReturnSize
	);

	NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
		IN HANDLE			ProcessId,
		OUT PEPROCESS* Process
	);

	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(
		IN PEPROCESS		Process
	);

	NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);

	NTSYSAPI ULONG RtlRandomEx(
		PULONG Seed
	);
}

void randstring(char* randomString, size_t length) {

	static char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; // abcdefghijklmnopqrstuvwxyz
	static char custom[]  = "NULL-"; // len = 5 - 1 (4)

	ULONG seed = KeQueryTimeIncrement();

	if (randomString)
	{
		for (int n = 0; n <= 4; n++)
		{
			randomString[n] = custom[n];
		}

		for (int n = 0; n <= length; n++)
		{
			int key = RtlRandomEx(&seed) % (int)(sizeof(charset) - 1);
			randomString[n + 5] = charset[key];
		}
	}
}
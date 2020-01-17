#include "stdafx.h"

struct {
	DWORD Length;
	NIC_DRIVER Drivers[0xFF];
} NICs = { 0 };

PDRIVER_DISPATCH DiskControlOriginal = 0, MountControlOriginal = 0, PartControlOriginal = 0, NsiControlOriginal = 0, GpuControlOriginal = 0;

/**** DISKS ****/
NTSTATUS PartInfoIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(PARTITION_INFORMATION_EX)) {
			PPARTITION_INFORMATION_EX info = (PPARTITION_INFORMATION_EX)request.Buffer;
			if (PARTITION_STYLE_GPT == info->PartitionStyle) {
				memset(&info->Gpt.PartitionId, 0, sizeof(GUID));
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS PartLayoutIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(DRIVE_LAYOUT_INFORMATION_EX)) {
			PDRIVE_LAYOUT_INFORMATION_EX info = (PDRIVE_LAYOUT_INFORMATION_EX)request.Buffer;
			if (PARTITION_STYLE_GPT == info->PartitionStyle) {
				memset(&info->Gpt.DiskId, 0, sizeof(GUID));
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS PartControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_DISK_GET_PARTITION_INFO_EX:
			ChangeIoc(ioc, irp, PartInfoIoc);
			break;
		case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
			ChangeIoc(ioc, irp, PartLayoutIoc);
			break;
	}

	return PartControlOriginal(device, irp);
}

NTSTATUS StorageQueryIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
			PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)request.Buffer;
			ULONG offset = desc->SerialNumberOffset;
			if (offset && offset < request.BufferLength) {
				strcpy((PCHAR)desc + offset, SERIAL);

				KdPrint("handled StorageQueryIoc\n");
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS AtaPassIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(ATA_PASS_THROUGH_EX) + sizeof(PIDENTIFY_DEVICE_DATA)) {
			PATA_PASS_THROUGH_EX pte = (PATA_PASS_THROUGH_EX)request.Buffer;
			ULONG offset = (ULONG)pte->DataBufferOffset;
			if (offset && offset < request.BufferLength) {
				PCHAR serial = (PCHAR)((PIDENTIFY_DEVICE_DATA)((PBYTE)request.Buffer + offset))->SerialNumber;
				SwapEndianess(serial, SERIAL);

				KdPrint("handled AtaPassIoc\n");
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS SmartDataIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(SENDCMDOUTPARAMS)) {
			PCHAR serial = ((PIDSECTOR)((PSENDCMDOUTPARAMS)request.Buffer)->bBuffer)->sSerialNumber;
			SwapEndianess(serial, SERIAL);

			KdPrint("handled SmartDataIoc\n");
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS DiskControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_STORAGE_QUERY_PROPERTY:
			if (StorageDeviceProperty == ((PSTORAGE_PROPERTY_QUERY)irp->AssociatedIrp.SystemBuffer)->PropertyId) {
				ChangeIoc(ioc, irp, StorageQueryIoc);
			}
			break;
		case IOCTL_ATA_PASS_THROUGH:
			ChangeIoc(ioc, irp, AtaPassIoc);
			break;
		case SMART_RCV_DRIVE_DATA:
			ChangeIoc(ioc, irp, SmartDataIoc);
			break;
	}

	return DiskControlOriginal(device, irp);
}

VOID SpoofRaidUnits(RU_REGISTER_INTERFACES RaidUnitRegisterInterfaces, BYTE RaidUnitExtension_SerialNumber_offset) {
	UNICODE_STRING storahci_str = RTL_CONSTANT_STRING(L"\\Driver\\storahci");
	PDRIVER_OBJECT storahci_object = 0;
	
	// Enumerate RaidPorts in storahci
	NTSTATUS status = ObReferenceObjectByName(&storahci_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &storahci_object);
	if (NT_SUCCESS(status)) {
		ULONG length = 0;
		if (STATUS_BUFFER_TOO_SMALL == (status = IoEnumerateDeviceObjectList(storahci_object, 0, 0, &length)) && length) {
			ULONG size = length * sizeof(PDEVICE_OBJECT);
			PDEVICE_OBJECT *devices = ExAllocatePool(NonPagedPool, size);
			if (devices) {
				if (NT_SUCCESS(status = IoEnumerateDeviceObjectList(storahci_object, devices, size, &length)) && length) {
					for (ULONG i = 0; i < length; ++i) {
						PDEVICE_OBJECT raidport_object = devices[i];
						
						BYTE buffer[MAX_PATH] = { 0 };
						if (NT_SUCCESS(ObQueryNameString(raidport_object, (POBJECT_NAME_INFORMATION)buffer, sizeof(buffer), &size))) {
							PUNICODE_STRING raidport_str = (PUNICODE_STRING)buffer;

							// Enumerate devices for each RaidPort
							if (wcsstr(raidport_str->Buffer, L"\\RaidPort")) {
								DWORD total = 0, success = 0;
								for (PDEVICE_OBJECT device = raidport_object->DriverObject->DeviceObject; device; device = device->NextDevice) {
									if (FILE_DEVICE_DISK == device->DeviceType) {
										PSTRING serial = (PSTRING)((PBYTE)device->DeviceExtension + RaidUnitExtension_SerialNumber_offset);
										strcpy(serial->Buffer, SERIAL);
										serial->Length = (USHORT)strlen(SERIAL);

										if (NT_SUCCESS(status = RaidUnitRegisterInterfaces(device->DeviceExtension))) {
											++success;
										} else {
											KdPrint("! RaidUnitRegisterInterfaces failed: %p !\n", status);
										}

										++total;
									}
								}

								KdPrint("%wZ: RaidUnitRegisterInterfaces succeeded for %d/%d\n", raidport_str, success, total);
							}
						}

						ObDereferenceObject(raidport_object);
					}
				} else {
					KdPrint("! failed to get storahci devices (got %d): %p !\n", length, status);
				}

				ExFreePool(devices);
			} else {
				KdPrint("! failed to allocated %d storahci devices !\n", length);
			}
		} else {
			KdPrint("! failed to get storahci device list size (got %d): %p !\n", length, status);
		}

		ObDereferenceObject(storahci_object);
	} else {
		KdPrint("! failed to get %wZ: %p !\n", &storahci_object, status);
	}
}

VOID SpoofDisks() {
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\partmgr"), PartControl, PartControlOriginal);

	UNICODE_STRING disk_str = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
	PDRIVER_OBJECT disk_object = 0;

	NTSTATUS status = ObReferenceObjectByName(&disk_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &disk_object);
	if (!NT_SUCCESS(status)) {
		KdPrint("! failed to get %wZ: %p !\n", &disk_str, status);
		return;
	}

	AppendSwap(disk_str, &disk_object->MajorFunction[IRP_MJ_DEVICE_CONTROL], DiskControl, DiskControlOriginal);

	DISK_FAIL_PREDICTION DiskEnableDisableFailurePrediction = (DISK_FAIL_PREDICTION)FindPatternImage(disk_object->DriverStart, "\x48\x89\x00\x24\x10\x48\x89\x74\x24\x18\x57\x48\x81\xEC\x90\x00", "xx?xxxxxxxxxxxxx");
	if (DiskEnableDisableFailurePrediction) {
		ULONG length = 0;
		if (STATUS_BUFFER_TOO_SMALL == (status = IoEnumerateDeviceObjectList(disk_object, 0, 0, &length)) && length) {
			ULONG size = length * sizeof(PDEVICE_OBJECT);
			PDEVICE_OBJECT *devices = ExAllocatePool(NonPagedPool, size);
			if (devices) {
				if (NT_SUCCESS(status = IoEnumerateDeviceObjectList(disk_object, devices, size, &length)) && length) {
					ULONG success = 0, total = 0;

					for (ULONG i = 0; i < length; ++i) {
						PDEVICE_OBJECT device = devices[i];

						// Update disk properties for disk ID
						PDEVICE_OBJECT disk = IoGetAttachedDeviceReference(device);
						if (disk) {
							KEVENT event = { 0 };
							KeInitializeEvent(&event, NotificationEvent, FALSE);

							PIRP irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_UPDATE_PROPERTIES, disk, 0, 0, 0, 0, 0, &event, 0);
							if (irp) {
								if (STATUS_PENDING == IoCallDriver(disk, irp)) {
									KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, 0);
								}
							} else {
								KdPrint("! failed to build IoControlRequest !\n");
							}

							ObDereferenceObject(disk);
						}

						PFUNCTIONAL_DEVICE_EXTENSION ext = device->DeviceExtension;
						if (ext) {
							strcpy((PCHAR)ext->DeviceDescriptor + ext->DeviceDescriptor->SerialNumberOffset, SERIAL);

							// Disables SMART
							if (NT_SUCCESS(status = DiskEnableDisableFailurePrediction(ext, FALSE))) {
								++success;
							} else {
								KdPrint("! DiskEnableDisableFailurePrediction failed: %p !\n", status);
							}

							++total;
						}
						
						ObDereferenceObject(device);
					}

					KdPrint("disabling smart succeeded for %d/%d\n", success, total);
				} else {
					KdPrint("! failed to get disk devices (got %d): %p !\n", length, status);
				}

				ExFreePool(devices);
			} else {
				KdPrint("! failed to allocated %d disk devices !\n", length);
			}
		} else {
			KdPrint("! failed to get disk device list size (got %d): %p !\n", length, status);
		}
	} else {
		KdPrint("! failed to find DiskEnableDisableFailurePrediction !\n");
	}

	ObDereferenceObject(disk_object);

	// RaidUnitRegisterInterfaces -> Registry
	PVOID storport = GetBaseAddress("storport.sys", 0);
	if (storport) {
		RU_REGISTER_INTERFACES RaidUnitRegisterInterfaces = (RU_REGISTER_INTERFACES)FindPatternImage(storport, "\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x85\xC0", "xxxx????xxxx????xx");
		if (RaidUnitRegisterInterfaces) {
			PBYTE RaidUnitExtension_SerialNumber = FindPatternImage(storport, "\x66\x39\x2C\x41", "xxxx");
			if (RaidUnitExtension_SerialNumber) {
				RaidUnitExtension_SerialNumber = FindPattern((PCHAR)RaidUnitExtension_SerialNumber, 32, "\x4C\x8D\x4F", "xxx");
				if (RaidUnitExtension_SerialNumber) {
					BYTE RaidUnitExtension_SerialNumber_offset = *(RaidUnitExtension_SerialNumber + 3);
					RaidUnitRegisterInterfaces = (RU_REGISTER_INTERFACES)((PBYTE)RaidUnitRegisterInterfaces + 8 + *(PINT)((PBYTE)RaidUnitRegisterInterfaces + 4));

					SpoofRaidUnits(RaidUnitRegisterInterfaces, RaidUnitExtension_SerialNumber_offset);
				} else {
					KdPrint("! failed to find RaidUnitExtension_SerialNumber (1) !\n");
				}
			} else {
				KdPrint("! failed to find RaidUnitExtension_SerialNumber (0) !\n");
			}
		} else {
			KdPrint("! failed to find RaidUnitRegisterInterfaces !\n");
		}
	} else {
		KdPrint("! failed to get \"storport.sys\" !\n");
	}
}

/**** VOLUMES ****/
NTSTATUS MountPointsIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(MOUNTMGR_MOUNT_POINTS)) {
			PMOUNTMGR_MOUNT_POINTS points = (PMOUNTMGR_MOUNT_POINTS)request.Buffer;
			for (DWORD i = 0; i < points->NumberOfMountPoints; ++i) {
				PMOUNTMGR_MOUNT_POINT point = &points->MountPoints[i];
				if (point->UniqueIdOffset) {
					point->UniqueIdLength = 0;
				}

				if (point->SymbolicLinkNameOffset) {
					point->SymbolicLinkNameLength = 0;
				}
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS MountUniqueIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(MOUNTDEV_UNIQUE_ID)) {
			((PMOUNTDEV_UNIQUE_ID)request.Buffer)->UniqueIdLength = 0;
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS MountControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_MOUNTMGR_QUERY_POINTS:
			ChangeIoc(ioc, irp, MountPointsIoc);
			break;
		case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
			ChangeIoc(ioc, irp, MountUniqueIoc);
			break;
	}

	return MountControlOriginal(device, irp);
}

// Volume serial is spoofed from usermode
void SpoofVolumes() {
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\mountmgr"), MountControl, MountControlOriginal);
}

/**** NIC ****/
NTSTATUS NICIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (irp->MdlAddress) {
			SpoofBuffer(SEED, (PBYTE)MmGetSystemAddressForMdl(irp->MdlAddress), 6);

			KdPrint("handled NICIoc\n");
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS NICControl(PDEVICE_OBJECT device, PIRP irp) {
	for (DWORD i = 0; i < NICs.Length; ++i) {
		PNIC_DRIVER driver = &NICs.Drivers[i];

		if (driver->Original && driver->DriverObject == device->DriverObject) {
			PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
			switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
				case IOCTL_NDIS_QUERY_GLOBAL_STATS: {
					switch (*(PDWORD)irp->AssociatedIrp.SystemBuffer) {
						case OID_802_3_PERMANENT_ADDRESS:
						case OID_802_3_CURRENT_ADDRESS:
						case OID_802_5_PERMANENT_ADDRESS:
						case OID_802_5_CURRENT_ADDRESS:
							ChangeIoc(ioc, irp, NICIoc);
							break;
					}

					break;
				}
			}

			return driver->Original(device, irp);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS NsiControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_NSI_PROXY_ARP: {
			DWORD length = ioc->Parameters.DeviceIoControl.OutputBufferLength;
			NTSTATUS ret = NsiControlOriginal(device, irp);

			PNSI_PARAMS params = (PNSI_PARAMS)irp->UserBuffer;
			if (params && NSI_PARAMS_ARP == params->Type) {
				memset(irp->UserBuffer, 0, length);

				KdPrint("handled ARP table\n");
			}

			return ret;
		}
	}

	return NsiControlOriginal(device, irp);
}

VOID SpoofNIC() {
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\nsiproxy"), NsiControl, NsiControlOriginal);

	PVOID base = GetBaseAddress("ndis.sys", 0);
	if (!base) {
		KdPrint("! failed to get \"ndis.sys\" !\n");
		return;
	}

	PNDIS_FILTER_BLOCK ndisGlobalFilterList = FindPatternImage(base, "\x40\x8A\xF0\x48\x8B\x05", "xxxxxx");
	if (ndisGlobalFilterList) {
		PDWORD ndisFilter_IfBlock = FindPatternImage(base, "\x48\x85\x00\x0F\x84\x00\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x33", "xx?xx?????x???xxx");
		if (ndisFilter_IfBlock) {
			DWORD ndisFilter_IfBlock_offset = *(PDWORD)((PBYTE)ndisFilter_IfBlock + 12);

			ndisGlobalFilterList = (PNDIS_FILTER_BLOCK)((PBYTE)ndisGlobalFilterList + 3);
			ndisGlobalFilterList = *(PNDIS_FILTER_BLOCK *)((PBYTE)ndisGlobalFilterList + 7 + *(PINT)((PBYTE)ndisGlobalFilterList + 3));

			DWORD count = 0;
			for (PNDIS_FILTER_BLOCK filter = ndisGlobalFilterList; filter; filter = filter->NextFilter) {
				PNDIS_IF_BLOCK block = *(PNDIS_IF_BLOCK *)((PBYTE)filter + ndisFilter_IfBlock_offset);
				if (block) {
					PWCHAR copy = SafeCopy(filter->FilterInstanceName->Buffer, MAX_PATH);
					if (copy) {
						WCHAR adapter[MAX_PATH] = { 0 };
						swprintf(adapter, L"\\Device\\%ws", TrimGUID(copy, MAX_PATH / 2));
						ExFreePool(copy);

						KdPrint("found NIC %ws\n", adapter);

						UNICODE_STRING name = { 0 };
						RtlInitUnicodeString(&name, adapter);

						PFILE_OBJECT file = 0;
						PDEVICE_OBJECT device = 0;

						NTSTATUS status = IoGetDeviceObjectPointer(&name, FILE_READ_DATA, &file, &device);
						if (NT_SUCCESS(status)) {
							PDRIVER_OBJECT driver = device->DriverObject;
							if (driver) {
								BOOL exists = FALSE;
								for (DWORD i = 0; i < NICs.Length; ++i) {
									if (NICs.Drivers[i].DriverObject == driver) {
										exists = TRUE;
										break;
									}
								}

								if (exists) {
									KdPrint("%wZ already swapped\n", &driver->DriverName);
								} else {
									PNIC_DRIVER nic = &NICs.Drivers[NICs.Length];
									nic->DriverObject = driver;

									AppendSwap(driver->DriverName, &driver->MajorFunction[IRP_MJ_DEVICE_CONTROL], NICControl, nic->Original);

									++NICs.Length;
								}
							}

							// Indirectly dereferences device object
							ObDereferenceObject(file);
						} else {
							KdPrint("! failed to get %wZ: %p !\n", &name, status);
						}
					}

					// Current MAC
					PIF_PHYSICAL_ADDRESS_LH addr = &block->ifPhysAddress;
					SpoofBuffer(SEED, addr->Address, addr->Length);
					addr = &block->PermanentPhysAddress;
					SpoofBuffer(SEED, addr->Address, addr->Length);

					++count;
				}
			}

			KdPrint("handled %d MACs\n", count);
		} else {
			KdPrint("! failed to find ndisFilter_IfBlock !\n");
		}
	} else {
		KdPrint("! failed to find ndisGlobalFilterList !\n");
	}
}

/**** SMBIOS (and boot) ****/
void SpoofSMBIOS() {
	PVOID base = GetBaseAddress("ntoskrnl.exe", 0);
	if (!base) {
		KdPrint("! failed to get \"ntoskrnl.exe\" !\n");
		return;
	}

	PBYTE ExpBootEnvironmentInformation = FindPatternImage(base, "\x0F\x10\x05\x00\x00\x00\x00\x0F\x11\x00\x8B", "xxx????xx?x");
	if (ExpBootEnvironmentInformation) {
		ExpBootEnvironmentInformation = ExpBootEnvironmentInformation + 7 + *(PINT)(ExpBootEnvironmentInformation + 3);
		SpoofBuffer(SEED, ExpBootEnvironmentInformation, 16);

		KdPrint("handled ExpBootEnvironmentInformation\n");
	} else {
		KdPrint("! ExpBootEnvironmentInformation not found !\n");
	}

	PPHYSICAL_ADDRESS WmipSMBiosTablePhysicalAddress = FindPatternImage(base, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15", "xxx????xxxx?xx");
	if (WmipSMBiosTablePhysicalAddress) {
		WmipSMBiosTablePhysicalAddress = (PPHYSICAL_ADDRESS)((PBYTE)WmipSMBiosTablePhysicalAddress + 7 + *(PINT)((PBYTE)WmipSMBiosTablePhysicalAddress + 3));
		memset(WmipSMBiosTablePhysicalAddress, 0, sizeof(PHYSICAL_ADDRESS));

		KdPrint("nulled SMBIOS table physical address\n");
	} else {
		KdPrint("! WmipSMBiosTablePhysicalAddress not found !\n");
	}
}

/**** GPU ****/
NTSTATUS GpuControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_NVIDIA_SMIL: {
			NTSTATUS ret = GpuControlOriginal(device, irp);

			PCHAR buffer = irp->UserBuffer;
			if (buffer) {
				PCHAR copy = SafeCopy(buffer, IOCTL_NVIDIA_SMIL_MAX);
				if (copy) {
					for (DWORD i = 0; i < IOCTL_NVIDIA_SMIL_MAX - 4; ++i) {
						if (0 == memcmp(copy + i, "GPU-", 4)) {
							buffer[i] = 0;

							KdPrint("handled GPU serial\n");
							break;
						}
					}

					ExFreePool(copy);
				}
			}

			return ret;
		}
	}

	return GpuControlOriginal(device, irp);
}

VOID SpoofGPU() {
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\nvlddmkm"), GpuControl, GpuControlOriginal);
}

VOID DriverUnload(PDRIVER_OBJECT driver) {
	UNREFERENCED_PARAMETER(driver);
	KdPrint("-- unloading\n");

	for (DWORD i = 0; i < SWAPS.Length; ++i) {
		PSWAP s = (PSWAP)&SWAPS.Buffer[i];
		if (s->Swap && s->Original) {
			InterlockedExchangePointer(s->Swap, s->Original);
			KdPrint("reverted %wZ swap\n", &s->Name);
		}
	}

	KdPrint("-- unloaded\n");
}

/**** CLEANING ****/
/*PVOID clean_unloaded_drivers() {
	ULONG bytes = 0;
	auto status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	if (!bytes)
		return;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, "s3x");

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(modules, "s3x");
		return;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	uintptr_t ntoskrnlBase = 0;
	size_t ntoskrnlSize = 0;

	ntoskrnlBase = GetBaseAddress("ntoskrnl.exe", ntoskrnlSize);

	ExFreePoolWithTag(modules, "s3x");

	if (ntoskrnlBase <= 0) {
		return;
	}

	//4C 8B ? ? ? ? ? 4C 8B C9 4D 85 ? 74 + 3
	auto mmUnloadedDriversPtr = FindPattern((void*)ntoskrnlBase, ntoskrnlSize, "\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x");

	if (!mmUnloadedDriversPtr) {
		return;
	}

	uintptr_t mmUnloadedDrivers = dereference(mmUnloadedDriversPtr, 3);

	memset(*(uintptr_t**)mmUnloadedDrivers, 0, 0x7D0);
}*/
/*
PVOID clean_piddb_cache() {
	RTL_OSVERSIONINFOW osVersion = { 0 };
	osVersion.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	RtlGetVersion(&osVersion);

	PRTL_AVL_TABLE PiDDBCacheTable;

	size_t size;
	uintptr_t ntoskrnlBase = GetBaseAddress("ntoskrnl.exe", size);

	if (osVersion.dwBuildNumber >= 18363 || osVersion.dwBuildNumber >= 18362)
	{
		PiDDBCacheTable = (PRTL_AVL_TABLE)dereference(FindPattern((void*)ntoskrnlBase, size, "\x48\x8D\x0D\x00\x00\x00\x00\x4C\x89\x35\x00\x00\x00\x00\xBB\x00\x00\x00\x00", "xxx????xxx????x????"), 3);
	}
	else if (osVersion.dwBuildNumber >= 17763 || osVersion.dwBuildNumber >= 17134)
	{
		PiDDBCacheTable = (PRTL_AVL_TABLE)dereference(FindPattern((void*)ntoskrnlBase, size, "\x48\x8D\x0D\x00\x00\x00\x00\x4C\x89\x35\x00\x00\x00\x00\x49\x8B\xE9", "xxx????xxx????xxx"), 3);
	}

	uintptr_t entry_address = (PiDDBCacheTable->BalancedRoot.RightChild) + sizeof(RTL_BALANCED_LINKS);

	PPiDDBCache entry = (PiDDBCache*)(entry_address);

	if (entry->TimeDateStamp == 0x57CD1415 || entry->TimeDateStamp == 0x5284EAC3) {
		entry->TimeDateStamp = 0x69EAC9;
		entry->DriverName = (UNICODE_STRING) RTL_CONSTANT_STRING(L"NullDriver.sys");
	}

	
	ULONG count = 0;
	for (auto link = entry->List.Flink; link != entry->List.Blink; link = link->Flink, count++)
	{
		PPiDDBCache cache_entry = (PPiDDBCache*)(link);

		if (cache_entry->TimeDateStamp == 0x57CD1415 || cache_entry->TimeDateStamp == 0x5284EAC3) {
			cache_entry->TimeDateStamp = 0x69EAC9 + count;
			cache_entry->DriverName = (UNICODE_STRING) RTL_CONSTANT_STRING(L"NullDriver.sys");
		}
	}
}*/

NTSTATUS AnotherOne()
{
	//clean_unloaded_drivers();
	//clean_piddb_cache();

	ULONG64 time = 0;
	KeQuerySystemTime(&time);
	SEED = (DWORD)time;

	CHAR alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

	for (DWORD i = 0, l = (DWORD)strlen(CUSTOM) - 1; i < l; ++i) {
		SERIAL[i] = CUSTOM[i];
	}

	for (DWORD i = ((DWORD)strlen(CUSTOM)), l = ((DWORD)strlen(SERIAL) + i) - 2; i < l; ++i) {
		SERIAL[i] = alphabet[RtlRandomEx(&SEED) % (sizeof(alphabet) - 1)];
	}

	KdPrint("++ loading (serial: %s)\n", SERIAL);

	SpoofDisks();
	SpoofVolumes();
	SpoofNIC();
	SpoofSMBIOS();
	SpoofGPU();

	KdPrint("++ loaded\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driver, _In_ PUNICODE_STRING registry_path) {
	AnotherOne();
	return STATUS_SUCCESS;
}
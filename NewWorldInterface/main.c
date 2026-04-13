#pragma once
// --
#include <ntifs.h>
// System headers
#include <ntdef.h>
#include <ntddk.h>
// Core
#include "DriverCore.h"
// Memory
#include "MemoryManager.h"
#include "VirtualAddressTranslation.h"
// Communication
#include "EventHandling.h"
#include "SharedMemory.h"
// Common
#include "ProtocolDefinitions.h"
#include "SharedConstants.h"
#include "SharedTypes.h"
// Utils
#include "KernelHelpers.h"
// Process
#include "ProcessManager.h"
#include "VADTreeWalker.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pusRegistryPath) {

	NTSTATUS status = STATUS_DEVICE_CONFIGURATION_ERROR;

	if ((status = DriverInitialize(pDriverObject, pusRegistryPath)) == STATUS_SUCCESS) {
		pDriverObject->DriverUnload = DriverUnload;
		gpDeviceContext->gSectionMapped = FALSE;

		// START - Section for Input
		OBJECT_ATTRIBUTES InAttr;
		UNICODE_STRING InSectionName;
		PVOID InSectionObject = NULL;
		LARGE_INTEGER InSecSize;
		InSecSize.QuadPart = 0x2000;

		SECURITY_DESCRIPTOR sdInSecurityDescriptor;
		ACL sdInAcl;
		RtlCreateSecurityDescriptor(&sdInSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
		RtlSetDaclSecurityDescriptor(&sdInSecurityDescriptor, TRUE, NULL, FALSE);
		RtlInitUnicodeString(&InSectionName, MAPPING_NAME_INPUT);
		InitializeObjectAttributes(&InAttr, &InSectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdInSecurityDescriptor);

		//status = ZwOpenSection(&hInSection, SECTION_MAP_READ, &InAttr); // TODO: I think this can stay User-Mode
		status = ZwCreateSection(&hInSection, SECTION_ALL_ACCESS | SECTION_MAP_WRITE,
			&InAttr, &InSecSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL); // why can we not specify maximum sizeLow but only maximum sizeHigh????
		// Restarting the user-mode application our buffer will still be buffered
		// But this requires the kernel driver to start after the SYMBOLS habe been writte to the
		// section. Otherwise the driver will not be able to read the symbols.
		if (!NT_SUCCESS(status) || hInSection == NULL) {
			DbgPrint("[-] Failed to create input section: %08X\n", status);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}

		gSymsViewSize = 0;
		LARGE_INTEGER InSectionOffset = { 0 };

		// END - Section for Input
		// -----------------------------------------------------------------
		// Section for Info from Driver
		// START - Section for Output
		OBJECT_ATTRIBUTES attr;
		UNICODE_STRING sectionName;
		PVOID sectionObject = NULL;
		LARGE_INTEGER sectionSize;
		sectionSize.QuadPart = 0x4000; // or whatever size you want, 4KB * 4 in this case
		SECURITY_DESCRIPTOR sdSecurityDescriptor;
		ACL sdAcl;
		RtlCreateSecurityDescriptor(&sdSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
		RtlSetDaclSecurityDescriptor(&sdSecurityDescriptor, TRUE, NULL, FALSE);

		DbgPrint("[+] Initializing Section Name\n");
		RtlInitUnicodeString(&sectionName, MAPPING_NAME_OUTPUT);
		InitializeObjectAttributes(&attr, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);

		DbgPrint("[+] Creating section for output\n");
		//status = ZwOpenSection(&gpDeviceContext->hSection, SECTION_ALL_ACCESS | SECTION_MAP_WRITE, &attr);
		status = ZwCreateSection(&gpDeviceContext->hSection, SECTION_ALL_ACCESS | SECTION_MAP_WRITE,
			&attr, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL); // why can we not specify maximum sizeLow but only maximum sizeHigh????
		if (!NT_SUCCESS(status) || gpDeviceContext->hSection == NULL) {
			DbgPrint("[-] Failed to open section: %llx\n", status);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}

		gViewSize = 0;
		LARGE_INTEGER SectionOffset = { 0 };

		DbgPrint("[+] Mapping view of section\n");
		status = ZwMapViewOfSection(gpDeviceContext->hSection, ZwCurrentProcess(), &gSection,
			0, 0, NULL, &gViewSize, ViewShare,
			0, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] Failed to map view of section: %llx\n", status);
			ZwClose(gpDeviceContext->hSection);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		DbgPrint("[+] Section size: %zu Bytes | Section Base: 0x%llx\n",
			gViewSize, gSection);

		gpDeviceContext->gSectionMapped = TRUE;
		// -----------------------------------------------------------------
		// Section for FileName-Info from Driver
		OBJECT_ATTRIBUTES attrFileName;
		UNICODE_STRING sectionFileName;
		PVOID sectionFileNameObject = NULL;
		LARGE_INTEGER sectionSizeFILENAMES;
		sectionSizeFILENAMES.QuadPart = 0x4000; // or whatever size you want, 4KB in this case

		DbgPrint("[+] Initializing Section Name for FileName\n");
		RtlInitUnicodeString(&sectionFileName, MAPPING_NAME_FROM_FILENAMES);
		InitializeObjectAttributes(&attrFileName, &sectionFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);

		//status = ZwOpenSection(&gpDeviceContext->hSectionFileName, SECTION_ALL_ACCESS | SECTION_MAP_WRITE, &attrFileName);
		status = ZwCreateSection(&gpDeviceContext->hSectionFileName, SECTION_ALL_ACCESS | SECTION_MAP_WRITE,
			&attrFileName, &sectionSizeFILENAMES, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL); // why can we not specify maximum sizeLow but only maximum sizeHigh????
		if (!NT_SUCCESS(status) || gpDeviceContext->hSectionFileName == NULL) {
			DbgPrint("[-] Failed to open section for FileName: %llx\n", status);
			ZwClose(gpDeviceContext->hSection);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}

		gFileNameViewSize = 0;
		LARGE_INTEGER SectionFileNameOffset = { 0 };

		DbgPrint("[+] Mapping view of section for FileName\n");
		status = ZwMapViewOfSection(gpDeviceContext->hSectionFileName, ZwCurrentProcess(), &gFileNameSection,
			0, 0, NULL, &gFileNameViewSize, ViewShare,
			0, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] Failed to map view of section for FileName: %llx\n", status);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		DbgPrint("[+] Section size for FileName: %zu Bytes | Section Base: 0x%llx\n",
			gFileNameViewSize, gFileNameSection);

		gpDeviceContext->gFileNameSectionMapped = TRUE;
		// -----------------------------------------------------------------
		 // Section for WritePhysical-Request from User-Mode
		OBJECT_ATTRIBUTES attrWritePhys;
		UNICODE_STRING sectionWritePhys;
		PVOID sectionWritePhysObject = NULL;
		LARGE_INTEGER sectionSizeWritePhys;
		sectionSizeWritePhys.QuadPart = sizeof(WRITE_PHYS_REQUEST);

		DbgPrint("[+] Initializing Section Name for WritePhysical\n");
		RtlInitUnicodeString(&sectionWritePhys, MAPPING_NAME_WRITE_PHYS);
		InitializeObjectAttributes(&attrWritePhys, &sectionWritePhys, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);

		status = ZwCreateSection(&hWritePhysSection, SECTION_ALL_ACCESS | SECTION_MAP_WRITE,
			&attrWritePhys, &sectionSizeWritePhys, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
		if (!NT_SUCCESS(status) || hWritePhysSection == NULL) {
			DbgPrint("[-] Failed to create WritePhysical section: %08X\n", status);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}

		gWritePhysViewSize = 0;
		LARGE_INTEGER SectionWritePhysOffset = { 0 };

		DbgPrint("[+] Mapping view of section for WritePhysical\n");
		status = ZwMapViewOfSection(hWritePhysSection, ZwCurrentProcess(), &gWritePhysSection,
			0, 0, NULL, &gWritePhysViewSize, ViewShare,
			0, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] Failed to map view of WritePhysical section: %08X\n", status);
			ZwClose(hWritePhysSection);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		DbgPrint("[+] WritePhysical section size: %zu Bytes | Section Base: 0x%p\n",
			gWritePhysViewSize, gWritePhysSection);

		// Initialize the write request structure
		RtlZeroMemory(gWritePhysSection, gWritePhysViewSize);
		// -----------------------------------------------------------------
		 // Section for ReadPhysical-Request from User-Mode
		OBJECT_ATTRIBUTES attrReadPhys;
		UNICODE_STRING sectionReadPhys;
		PVOID sectionReadPhysObject = NULL;
		LARGE_INTEGER sectionSizeReadPhys;
		sectionSizeReadPhys.QuadPart = sizeof(READ_PHYS_REQUEST);

		DbgPrint("[+] Initializing Section Name for ReadPhysical\n");
		RtlInitUnicodeString(&sectionReadPhys, MAPPING_NAME_READ_PHYS);
		InitializeObjectAttributes(&attrReadPhys, &sectionReadPhys, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);

		status = ZwCreateSection(&hReadPhysSection, SECTION_ALL_ACCESS | SECTION_MAP_WRITE,
			&attrReadPhys, &sectionSizeReadPhys, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
		if (!NT_SUCCESS(status) || hReadPhysSection == NULL) {
			DbgPrint("[-] Failed to create ReadPhysical section: %08X\n", status);
			ZwUnmapViewOfSection(ZwCurrentProcess(), gWritePhysSection);
			ZwClose(hWritePhysSection);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}

		gReadPhysViewSize = 0;
		LARGE_INTEGER SectionReadPhysOffset = { 0 };

		DbgPrint("[+] Mapping view of section for ReadPhysical\n");
		status = ZwMapViewOfSection(hReadPhysSection, ZwCurrentProcess(), &gReadPhysSection,
			0, 0, NULL, &gReadPhysViewSize, ViewShare,
			0, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] Failed to map view of ReadPhysical section: %08X\n", status);
			ZwClose(hReadPhysSection);
			ZwUnmapViewOfSection(ZwCurrentProcess(), gWritePhysSection);
			ZwClose(hWritePhysSection);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		DbgPrint("[+] ReadPhysical section size: %zu Bytes | Section Base: 0x%p\n",
			gReadPhysViewSize, gReadPhysSection);

		// Initialize the read request structure
		RtlZeroMemory(gReadPhysSection, gReadPhysViewSize);
		// -----------------------------------------------------------------
		// MAPPING_NOTIFICATION_USERMODEREADY_EVENT START
		UNICODE_STRING eventNameUSERMODEREADY;
		OBJECT_ATTRIBUTES objAttrUSERMODEREADY;
		HANDLE hThreadUSERMODEREADY;
		PKEVENT pEventUSERMODEREADY;
		RtlInitUnicodeString(&eventNameUSERMODEREADY, MAPPING_NOTIFICATION_USERMODEREADY_EVENT);
		InitializeObjectAttributes(&objAttrUSERMODEREADY, &eventNameUSERMODEREADY, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);
		status = ZwCreateEvent(&hEventUSERMODEREADY, EVENT_ALL_ACCESS | SYNCHRONIZE, &objAttrUSERMODEREADY, NotificationEvent, FALSE);
		if (NT_SUCCESS(status)) {
			DbgPrint("[+] Opened event handle: %llx\n", hEventUSERMODEREADY);
			ObReferenceObjectByHandle(hEventUSERMODEREADY, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID*)&pEventUSERMODEREADY, NULL);
			PsCreateSystemThread(&hThreadUSERMODEREADY, THREAD_ALL_ACCESS, NULL, NULL, NULL, UserModeReadWorkerThread, pEventUSERMODEREADY);
		}
		else {
			DbgPrint("[-] Failed to open event handle: %08X\n", status);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			ZwClose(hEventUSERMODEREADY);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		// MAPPING_NOTIFICATION_USERMODEREADY_EVENT END
		// -----------------------------------------------------------------
		// MAPPING_NOTIFICATION_Unlink_EVENT START
		UNICODE_STRING eventNameUnlink;
		OBJECT_ATTRIBUTES objAttrUnlink;
		HANDLE hThreadUnlink;
		PKEVENT pEventUnlink;
		RtlInitUnicodeString(&eventNameUnlink, MAPPING_NOTIFICATION_Unlink_EVENT);
		InitializeObjectAttributes(&objAttrUnlink, &eventNameUnlink, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);
		status = ZwCreateEvent(&hEventUnlink, EVENT_ALL_ACCESS | SYNCHRONIZE, &objAttrUnlink, NotificationEvent, FALSE);
		if (NT_SUCCESS(status)) {
			DbgPrint("[+] Opened event handle: %llx\n", hEventUnlink);
			ObReferenceObjectByHandle(hEventUnlink, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID*)&pEventUnlink, NULL);
			PsCreateSystemThread(&hThreadUnlink, THREAD_ALL_ACCESS, NULL, NULL, NULL, UnlinkWorkerThread, pEventUnlink);
		}
		else {
			DbgPrint("[-] Failed to open event handle: %08X\n", status);
			ObDereferenceObject(hEventUSERMODEREADY);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			ZwClose(hEventUSERMODEREADY);
			ZwClose(hEventUnlink);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		// MAPPING_NOTIFICATION_Unlink_EVENT END
		// -----------------------------------------------------------------
		// MAPPING_NOTIFICATION_LINK_EVENT START
		UNICODE_STRING eventNameLINK;
		OBJECT_ATTRIBUTES objAttrLINK;
		HANDLE hThreadLINK;
		PKEVENT pEventLINK;
		RtlInitUnicodeString(&eventNameLINK, MAPPING_NOTIFICATION_LINK_EVENT);
		InitializeObjectAttributes(&objAttrLINK, &eventNameLINK, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);
		status = ZwCreateEvent(&hEventLINK, EVENT_ALL_ACCESS | SYNCHRONIZE, &objAttrLINK, NotificationEvent, FALSE);
		if (NT_SUCCESS(status)) {
			DbgPrint("[+] Opened event handle: %llx\n", hEventLINK);
			ObReferenceObjectByHandle(hEventLINK, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID*)&pEventLINK, NULL);
			PsCreateSystemThread(&hThreadLINK, THREAD_ALL_ACCESS, NULL, NULL, NULL, LinkWorkerThread, pEventLINK);
		}
		else {
			DbgPrint("[-] Failed to open event handle: %08X\n", status);
			ObDereferenceObject(hEventUSERMODEREADY);
			ObDereferenceObject(hEventUnlink);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			ZwClose(hEventUSERMODEREADY);
			ZwClose(hEventUnlink);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		// MAPPING_NOTIFICATION_LINK_EVENT END
		// -----------------------------------------------------------------
		// MAPPING_NOTIFICATION_INIT_EVENT START
		UNICODE_STRING eventNameINIT;
		OBJECT_ATTRIBUTES objAttrINIT;
		HANDLE hThreadINIT;
		PKEVENT pEventINIT;
		RtlInitUnicodeString(&eventNameINIT, MAPPING_NOTIFICATION_INIT_EVENT);
		InitializeObjectAttributes(&objAttrINIT, &eventNameINIT, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);
		status = ZwCreateEvent(&hEventINIT, EVENT_ALL_ACCESS | SYNCHRONIZE, &objAttrINIT, NotificationEvent, FALSE);
		if (NT_SUCCESS(status)) {
			DbgPrint("[+] Opened event handle: %llx\n", hEventINIT);
			ObReferenceObjectByHandle(hEventINIT, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID*)&pEventINIT, NULL);
			PsCreateSystemThread(&hThreadINIT, THREAD_ALL_ACCESS, NULL, NULL, NULL, INITWorkerThread, pEventINIT);
		}
		else {
			DbgPrint("[-] Failed to open event handle: %08X\n", status);
			ObDereferenceObject(hEventUSERMODEREADY);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			ZwClose(hEventUSERMODEREADY);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		// MAPPING_NOTIFICATION_INIT_EVENT END
		// -----------------------------------------------------------------
		// MAPPING_NOTIFICATION_WRITE_PHYS_EVENT START
		UNICODE_STRING eventNameWRITE_PHYS;
		OBJECT_ATTRIBUTES objAttrWRITE_PHYS;
		HANDLE hThreadWRITE_PHYS;
		PKEVENT pEventWRITE_PHYS;
		RtlInitUnicodeString(&eventNameWRITE_PHYS, MAPPING_NOTIFICATION_WRITE_PHYS_EVENT);
		InitializeObjectAttributes(&objAttrWRITE_PHYS, &eventNameWRITE_PHYS, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);
		status = ZwCreateEvent(&hEventWRITE_PHYS, EVENT_ALL_ACCESS | SYNCHRONIZE, &objAttrWRITE_PHYS, NotificationEvent, FALSE);
		if (NT_SUCCESS(status)) {
			DbgPrint("[+] Opened WritePhysical event handle: %p\n", hEventWRITE_PHYS);
			ObReferenceObjectByHandle(hEventWRITE_PHYS, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID*)&pEventWRITE_PHYS, NULL);
			PsCreateSystemThread(&hThreadWRITE_PHYS, THREAD_ALL_ACCESS, NULL, NULL, NULL, WritePhysicalWorkerThread, pEventWRITE_PHYS);
		}
		else {
			DbgPrint("[-] Failed to create WritePhysical event handle: %08X\n", status);
			// Cleanup existing resources
			ZwUnmapViewOfSection(ZwCurrentProcess(), gWritePhysSection);
			ZwClose(hWritePhysSection);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			ZwClose(hEventUSERMODEREADY);
			ZwClose(hEventUnlink);
			ZwClose(hEventLINK);
			ZwClose(hEventINIT);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		// MAPPING_NOTIFICATION_WRITE_PHYS_EVENT END
		// -----------------------------------------------------------------
		// MAPPING_NOTIFICATION_READ_PHYS_EVENT START
		UNICODE_STRING eventNameREAD_PHYS;
		OBJECT_ATTRIBUTES objAttrREAD_PHYS;
		HANDLE hThreadREAD_PHYS;
		PKEVENT pEventREAD_PHYS;
		RtlInitUnicodeString(&eventNameREAD_PHYS, MAPPING_NOTIFICATION_READ_PHYS_EVENT);
		InitializeObjectAttributes(&objAttrREAD_PHYS, &eventNameREAD_PHYS, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);
		status = ZwCreateEvent(&hEventREAD_PHYS, EVENT_ALL_ACCESS | SYNCHRONIZE, &objAttrREAD_PHYS, NotificationEvent, FALSE);
		if (NT_SUCCESS(status)) {
			DbgPrint("[+] Opened ReadPhysical event handle: %p\n", hEventREAD_PHYS);
			ObReferenceObjectByHandle(hEventREAD_PHYS, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID*)&pEventREAD_PHYS, NULL);
			PsCreateSystemThread(&hThreadREAD_PHYS, THREAD_ALL_ACCESS, NULL, NULL, NULL, ReadPhysicalWorkerThread, pEventREAD_PHYS);
		}
		else {
			DbgPrint("[-] Failed to create ReadPhysical event handle: %08X\n", status);
			// Cleanup existing resources
			ZwUnmapViewOfSection(ZwCurrentProcess(), gReadPhysSection);
			ZwClose(hReadPhysSection);
			ZwUnmapViewOfSection(ZwCurrentProcess(), gWritePhysSection);
			ZwClose(hWritePhysSection);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			ZwClose(hEventUSERMODEREADY);
			ZwClose(hEventUnlink);
			ZwClose(hEventLINK);
			ZwClose(hEventINIT);
			ZwClose(hEventWRITE_PHYS);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		// MAPPING_NOTIFICATION_READ_PHYS_EVENT END
		// -----------------------------------------------------------------
		status = STATUS_SUCCESS;
		return status;
		// END - Section for Output
	}
	else {
		DbgPrint("[-] Failed to initialize driver: %llx\n", status);
		IoDeleteSymbolicLink(&usSymbolicLinkName);
		IoDeleteDevice(gpDeviceObject);
		return status;
	}
}
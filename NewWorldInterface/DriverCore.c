#include "DriverCore.h"


// Global variable definitions
PRESET_UNICODE_STRING(usDeviceName, CSTRING(DRV_DEVICE));
PRESET_UNICODE_STRING(usSymbolicLinkName, CSTRING(DRV_LINK));

PDEVICE_OBJECT gpDeviceObject = NULL;
PDEVICE_CONTEXT gpDeviceContext = NULL;
BOOL g_StopRequested = FALSE;
SIZE_T gViewSize = 0;
SIZE_T gFileNameViewSize = 0;
SIZE_T gCurrFileNameOffset = 1;
SIZE_T gSecVADIndex = 0;
PVOID gSection = 0;
PVOID gFileNameSection = 0;
SIZE_T gSymsViewSize = 0;
INIT gInit = { 0 };
SYM_INFO gSymInfo = { 0 };
HANDLE hInSection;
PVOID pInSection = NULL;
PEPROCESS gSourceProcess = NULL;
PHYSICAL_ADDRESS gOrigPhys = { 0 };
unsigned long long gOrigVal = 0x0;

HANDLE hEventLINK;
HANDLE hEventUnlink;
HANDLE hEventUSERMODEREADY;
HANDLE hEventINIT;
HANDLE hEventWRITE_PHYS = NULL;
PVOID gWritePhysSection = NULL;
SIZE_T gWritePhysViewSize = 0;
HANDLE hWritePhysSection = NULL;
HANDLE hEventREAD_PHYS = NULL;
PVOID gReadPhysSection = NULL;
SIZE_T gReadPhysViewSize = 0;
HANDLE hReadPhysSection = NULL;

NTSTATUS DriverInitialize(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pusRegistryPath) {
	PDEVICE_OBJECT pDeviceObject = NULL;
	NTSTATUS status = STATUS_DEVICE_CONFIGURATION_ERROR;

	if ((status = IoCreateDevice(
		pDriverObject, DEVICE_CONTEXT_,
		//&usDeviceName, FILE_DEVICE_NW_INTERFACE,
		&usDeviceName, FILE_DEVICE_UNKNOWN,
		0, FALSE, &pDeviceObject)) == STATUS_SUCCESS) {
		// ---
		gpDeviceObject = pDeviceObject;
		gpDeviceContext = pDeviceObject->DeviceExtension;

		gpDeviceContext->pDriverObject = pDriverObject;
		gpDeviceContext->pDeviceObject = pDeviceObject;
	}
	else {
		DbgPrint("[-] Failed to create device object: %08X\n", status);
		return status;
	}
	DbgPrint("[+] Device object created: %d\n", status);
	return status;
}

void DriverUnload(PDRIVER_OBJECT pDriverObject) {
	g_StopRequested = TRUE;
	DbgPrint("[+] Unloading driver...\n");
	IoDeleteSymbolicLink(&usSymbolicLinkName);
	IoDeleteDevice(gpDeviceObject);
	return;
}
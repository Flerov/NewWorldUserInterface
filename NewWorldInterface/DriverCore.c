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
// VAD tree modification
HANDLE hEventVAD_INSERT  = NULL;
HANDLE hEventVAD_REMOVE  = NULL;
HANDLE hVadModifySection = NULL;
PVOID  gVadModifySection = NULL;
SIZE_T gVadModifyViewSize = 0;

// Thread handles (global so DriverUnload can wait on them)
HANDLE hThreadUSERMODEREADY = NULL;
HANDLE hThreadUnlink         = NULL;
HANDLE hThreadLINK           = NULL;
HANDLE hThreadINIT           = NULL;
HANDLE hThreadWRITE_PHYS     = NULL;
HANDLE hThreadREAD_PHYS      = NULL;
HANDLE hThreadVAD_INSERT     = NULL;
HANDLE hThreadVAD_REMOVE     = NULL;

// KEVENT object pointers (global so DriverUnload can signal and dereference them)
PKEVENT pEventUSERMODEREADY  = NULL;
PKEVENT pEventUnlink          = NULL;
PKEVENT pEventLINK            = NULL;
PKEVENT pEventINIT            = NULL;
PKEVENT pEventWRITE_PHYS      = NULL;
PKEVENT pEventREAD_PHYS       = NULL;
PKEVENT pEventVAD_INSERT      = NULL;
PKEVENT pEventVAD_REMOVE      = NULL;

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
	DBG_UNREFERENCED_PARAMETER(pDriverObject);
	DbgPrint("[+] DriverUnload: beginning shutdown sequence\n");

	// 1. Tell all threads to stop
	g_StopRequested = TRUE;

	// 2. Wake every thread that is blocked in KeWaitForSingleObject
	if (pEventUSERMODEREADY) KeSetEvent(pEventUSERMODEREADY, IO_NO_INCREMENT, FALSE);
	if (pEventUnlink)         KeSetEvent(pEventUnlink,         IO_NO_INCREMENT, FALSE);
	if (pEventLINK)           KeSetEvent(pEventLINK,           IO_NO_INCREMENT, FALSE);
	if (pEventINIT)           KeSetEvent(pEventINIT,           IO_NO_INCREMENT, FALSE);
	if (pEventWRITE_PHYS)     KeSetEvent(pEventWRITE_PHYS,     IO_NO_INCREMENT, FALSE);
	if (pEventREAD_PHYS)      KeSetEvent(pEventREAD_PHYS,      IO_NO_INCREMENT, FALSE);
	if (pEventVAD_INSERT)     KeSetEvent(pEventVAD_INSERT,     IO_NO_INCREMENT, FALSE);
	if (pEventVAD_REMOVE)     KeSetEvent(pEventVAD_REMOVE,     IO_NO_INCREMENT, FALSE);

	// 3. Wait for each thread to finish (5 s timeout per thread), then close its handle
	// Drivers MUST NOT return from DriverUnload while any thread still references driver code/data.
	LARGE_INTEGER timeout;
	timeout.QuadPart = -10000000LL * 5; // 5 s in 100-ns units (negative = relative)
	HANDLE threads[8] = {
		hThreadUSERMODEREADY, hThreadUnlink, hThreadLINK,       hThreadINIT,
		hThreadWRITE_PHYS,    hThreadREAD_PHYS, hThreadVAD_INSERT, hThreadVAD_REMOVE
	};
	for (int i = 0; i < 8; i++) {
		if (!threads[i]) continue;
		NTSTATUS ws = ZwWaitForSingleObject(threads[i], FALSE, &timeout);
		if (ws == STATUS_TIMEOUT)
			DbgPrint("[-] DriverUnload: thread[%d] did not exit within 5 s\n", i);
		ZwClose(threads[i]);
	}
	hThreadUSERMODEREADY = hThreadUnlink = hThreadLINK = hThreadINIT = NULL;
	hThreadWRITE_PHYS = hThreadREAD_PHYS = hThreadVAD_INSERT = hThreadVAD_REMOVE = NULL;

	// 4. Release KEVENT object references taken via ObReferenceObjectByHandle
#define DEREF_EVENT(p) do { if (p) { ObDereferenceObject(p); (p) = NULL; } } while(0)
	DEREF_EVENT(pEventUSERMODEREADY);
	DEREF_EVENT(pEventUnlink);
	DEREF_EVENT(pEventLINK);
	DEREF_EVENT(pEventINIT);
	DEREF_EVENT(pEventWRITE_PHYS);
	DEREF_EVENT(pEventREAD_PHYS);
	DEREF_EVENT(pEventVAD_INSERT);
	DEREF_EVENT(pEventVAD_REMOVE);
#undef DEREF_EVENT

	// 5. Unmap the symbol input view
	if (pInSection) { ZwUnmapViewOfSection(ZwCurrentProcess(), pInSection); pInSection = NULL; }

	// 6. Unmap all output section views
#define UNMAP(v) do { if (v) { ZwUnmapViewOfSection(ZwCurrentProcess(), (v)); (v) = NULL; } } while(0)
	UNMAP(gSection);
	UNMAP(gFileNameSection);
	UNMAP(gWritePhysSection);
	UNMAP(gReadPhysSection);
	UNMAP(gVadModifySection);
#undef UNMAP

	// 7. Close all section handles
#define CLOSE(h) do { if (h) { ZwClose(h); (h) = NULL; } } while(0)
	CLOSE(hInSection);
	if (gpDeviceContext) {
		CLOSE(gpDeviceContext->hSection);
		CLOSE(gpDeviceContext->hSectionFileName);
	}
	CLOSE(hWritePhysSection);
	CLOSE(hReadPhysSection);
	CLOSE(hVadModifySection);

	// 8. Close all event handles
	CLOSE(hEventUSERMODEREADY);
	CLOSE(hEventUnlink);
	CLOSE(hEventLINK);
	CLOSE(hEventINIT);
	CLOSE(hEventWRITE_PHYS);
	CLOSE(hEventREAD_PHYS);
	CLOSE(hEventVAD_INSERT);
	CLOSE(hEventVAD_REMOVE);
#undef CLOSE

	// 9. Free any MDLs allocated by UserModeReadWorkerThread
	if (gpDeviceContext) {
		if (gpDeviceContext->pMdl)         { IoFreeMdl(gpDeviceContext->pMdl);         gpDeviceContext->pMdl         = NULL; }
		if (gpDeviceContext->pFileNameMdl) { IoFreeMdl(gpDeviceContext->pFileNameMdl); gpDeviceContext->pFileNameMdl = NULL; }
	}

	// 10. Remove the symbolic link and delete the device object
	IoDeleteSymbolicLink(&usSymbolicLinkName);
	IoDeleteDevice(gpDeviceObject);
	gpDeviceObject  = NULL;
	gpDeviceContext = NULL;

	DbgPrint("[+] DriverUnload: complete\n");
}
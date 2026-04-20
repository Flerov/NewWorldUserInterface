#pragma once
//// System headers
//#include <ntdef.h>
//#include <ntddk.h>
#include <ntifs.h>

// Common
#include "ProtocolDefinitions.h"
#include "SharedConstants.h"
#include "SharedTypes.h"

// Macro definitions
#define DEVICE_CONTEXT_ sizeof (DEVICE_CONTEXT)

// Macro for creating Unicode strings
#define _CSTRING(_text) #_text
#define CSTRING(_text) _CSTRING (_text)
#define _USTRING(_text) L##_text
#define USTRING(_text) _USTRING (_text)

#define PRESET_UNICODE_STRING(_symbol,_buffer) \
        UNICODE_STRING _symbol = \
            { \
            sizeof (USTRING (_buffer)) - sizeof (WORD), \
            sizeof (USTRING (_buffer)), \
            USTRING (_buffer) \
            };

// Device and driver definitions
#define DRV_MODULE          NewWorldInterface
#define DRV_NAME            NW Windows 2025 _INTERACE
#define DRV_DEVICE          \\Device\\NewWorldInterface
#define DRV_LINK            \\DosDevices\\NewWorldInterface

// Function declarations
NTSTATUS DriverInitialize(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pusRegistryPath);
void DriverUnload(PDRIVER_OBJECT pDriverObject);

// Global variable declarations (extern)
extern UNICODE_STRING usDeviceName;
extern UNICODE_STRING usSymbolicLinkName;
extern PDEVICE_OBJECT gpDeviceObject;
extern PDEVICE_CONTEXT gpDeviceContext;
extern BOOL g_StopRequested;
extern SIZE_T gViewSize;
extern SIZE_T gFileNameViewSize;
extern SIZE_T gCurrFileNameOffset;
extern SIZE_T gSecVADIndex;
extern PVOID gSection;
extern PVOID gFileNameSection;
extern SIZE_T gSymsViewSize;
extern INIT gInit;
extern SYM_INFO gSymInfo;
extern HANDLE hInSection;
extern PVOID pInSection;
extern PEPROCESS gSourceProcess;
extern PHYSICAL_ADDRESS gOrigPhys;
extern unsigned long long gOrigVal;
extern HANDLE hEventLINK;
extern HANDLE hEventUnlink;
extern HANDLE hEventUSERMODEREADY;
extern HANDLE hEventINIT;
extern HANDLE hEventWRITE_PHYS;
extern PVOID gWritePhysSection;
extern SIZE_T gWritePhysViewSize;
extern HANDLE hWritePhysSection;
extern HANDLE hEventREAD_PHYS;
extern PVOID gReadPhysSection;
extern SIZE_T gReadPhysViewSize;
extern HANDLE hReadPhysSection;
// VAD tree modification
extern HANDLE hEventVAD_INSERT;
extern HANDLE hEventVAD_REMOVE;
extern HANDLE hVadModifySection;
extern PVOID  gVadModifySection;
extern SIZE_T  gVadModifyViewSize;

// Thread handles — saved globally so DriverUnload can wait for each thread to exit
extern HANDLE hThreadUSERMODEREADY;
extern HANDLE hThreadUnlink;
extern HANDLE hThreadLINK;
extern HANDLE hThreadINIT;
extern HANDLE hThreadWRITE_PHYS;
extern HANDLE hThreadREAD_PHYS;
extern HANDLE hThreadVAD_INSERT;
extern HANDLE hThreadVAD_REMOVE;

// KEVENT object pointers — used to signal threads on shutdown and to release references
extern PKEVENT pEventUSERMODEREADY;
extern PKEVENT pEventUnlink;
extern PKEVENT pEventLINK;
extern PKEVENT pEventINIT;
extern PKEVENT pEventWRITE_PHYS;
extern PKEVENT pEventREAD_PHYS;
extern PKEVENT pEventVAD_INSERT;
extern PKEVENT pEventVAD_REMOVE;
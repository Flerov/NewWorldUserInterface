#pragma once
// System headers
//#include <ntdef.h>
//#include <ntddk.h>
#include <ntifs.h>
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
#include "MemoryProtection.h"
// Process
#include "ProcessManager.h"
#include "VADTreeWalker.h"


// From main.c - Worker thread functions
VOID WorkerThread(PVOID Context);
VOID LinkWorkerThread(PVOID Context);
VOID UnlinkWorkerThread(PVOID Context);
VOID UserModeReadWorkerThread(PVOID Context);
VOID INITWorkerThread(PVOID Context);
VOID WritePhysicalWorkerThread(PVOID Context);
VOID ReadPhysicalWorkerThread(PVOID Context);

// Extract event creation/management from DriverEntry
NTSTATUS CreateEventHandlers(void);
NTSTATUS CleanupEventHandlers(void);
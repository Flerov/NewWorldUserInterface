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
// Process
#include "ProcessManager.h"
#include "VADTreeWalker.h"


// From main.c
VOID ChangeRef(unsigned long long SourceVA, PEPROCESS SourceProcess, unsigned long long SourceCR3,
    unsigned long long TargetVA, PEPROCESS TargetProcess, unsigned long long TargetCR3);

ULONG64 VirtToPhys(unsigned long long addr, PEPROCESS TargetProcess, unsigned long long cr3, BOOLEAN log);
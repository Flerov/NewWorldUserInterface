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
PEPROCESS GetProcessByName(const char* FileName, unsigned long long eprocImageFileNameOffset,
    unsigned long long eprocActiveProcessLinks);

unsigned long long GetDirectoryTableBaseByName(const char* FileName,
    unsigned long long eprocImageFileNameOffset,
    unsigned long long eprocActiveProcessLinks,
    unsigned long long kprocDirectoryTableBase);
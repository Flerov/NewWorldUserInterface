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
BOOL InsertVADNode(int Level, PVOID VADNode, unsigned long long StartingVpn,
    unsigned long long EndingVpn, UNICODE_STRING* FileName, unsigned long Protection);
UNICODE_STRING* GetFileObjectFromVADLeaf(unsigned long long Leaf, DWORD MMVADSubsection,
    DWORD MMVADControlArea, DWORD MMVADCAFilePointer,
    DWORD FILEOBJECTFileName);
VOID WalkVADRecursive(PVOID VADNode, unsigned long StartingVpnOffset, DWORD EndingVpnOffset,
    DWORD Left, DWORD Right, int Level, PULONG TotalVADs, PULONG TotalLevels,
    PULONG MaxDepth, DWORD MMVADSubsection, DWORD MMVADControlArea,
    DWORD MMVADCAFilePointer, DWORD FILEOBJECTFileName, unsigned long long targetAdr);
VOID WalkVAD(PEPROCESS TargetProcess, DWORD VADRootOffset, DWORD StartingVpnOffset,
    DWORD EndingVpnOffset, DWORD Left, DWORD Right, DWORD MMVADSubsection,
    DWORD MMVADControlArea, DWORD MMVADCAFilePointer, DWORD FILEOBJECTFileName,
    unsigned long long targetAdr);
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
NTSTATUS WritePhysicalAddress(PVOID PhysTargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten);
NTSTATUS ReadPhysicalAddress(PVOID PhysSourceAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead);
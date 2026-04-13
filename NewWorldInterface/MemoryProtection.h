#pragma once
// System headers
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

//
// Memory Protection Function Typedefs
//

typedef NTSTATUS(*ZwProtectVirtualMemory_t)(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);

//
// Memory Protection Functions
//

// Core protection functions
NTSTATUS ChangeMemoryProtection(_In_ PEPROCESS Process, _In_ PVOID Address, _In_ SIZE_T SizeOfMem, _In_ ULONG NewProtection);

NTSTATUS QueryMemoryProtection(_In_ PEPROCESS Process, _In_ PVOID Address, _Out_ PMEMORY_BASIC_INFORMATION MemoryInfo);

NTSTATUS RestoreMemoryProtection( _In_ PEPROCESS Process, _In_ PVOID Address, _In_ SIZE_T SizeOfMem, _In_ ULONG OriginalProtection);

// Validation functions
BOOLEAN IsValidProtectionFlags(_In_ ULONG Protection);
BOOLEAN IsValidMemoryAddress(_In_ PEPROCESS Process, _In_ PVOID Address);

// Utility functions
NTSTATUS GetZwProtectVirtualMemoryAddress(_Out_ ZwProtectVirtualMemory_t* FunctionAddress);
NTSTATUS ValidateMemoryRegion(_In_ PEPROCESS Process, _In_ PVOID Address, _In_ SIZE_T Size);

// Process context management
NTSTATUS AttachToProcessSafely(_In_ PEPROCESS Process, _Out_ PKAPC_STATE ApcState);
VOID DetachFromProcessSafely(_In_ PKAPC_STATE ApcState);

// Protection constants and helpers
#define MEMORY_PROTECTION_READ_ONLY     PAGE_READONLY
#define MEMORY_PROTECTION_READ_WRITE    PAGE_READWRITE
#define MEMORY_PROTECTION_EXECUTE       PAGE_EXECUTE
#define MEMORY_PROTECTION_EXECUTE_READ  PAGE_EXECUTE_READ
#define MEMORY_PROTECTION_NO_ACCESS     PAGE_NOACCESS

// Protection helper macros
#define IS_READABLE_PROTECTION(prot)    ((prot) & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ))
#define IS_WRITABLE_PROTECTION(prot)    ((prot) & (PAGE_READWRITE | PAGE_WRITECOPY))
#define IS_EXECUTABLE_PROTECTION(prot)  ((prot) & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
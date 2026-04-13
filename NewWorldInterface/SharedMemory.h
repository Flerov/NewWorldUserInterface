#pragma once

// System headers
//#include <ntdef.h>
//#include <ntddk.h>
#include <ntifs.h>

// Core
#include "DriverCore.h"

// Common
#include "SharedConstants.h"
#include "SharedTypes.h"

//
// Shared Memory Management Functions
//

// Section creation and management
NTSTATUS CreateInputSection(VOID);
NTSTATUS CreateOutputSection(VOID);
NTSTATUS CreateFileNameSection(VOID);

// Section mapping functions
NTSTATUS MapInputSection(VOID);
NTSTATUS MapOutputSection(VOID);
NTSTATUS MapFileNameSection(VOID);

// Section unmapping functions
NTSTATUS UnmapInputSection(VOID);
NTSTATUS UnmapOutputSection(VOID);
NTSTATUS UnmapFileNameSection(VOID);

// Section cleanup functions
NTSTATUS CleanupInputSection(VOID);
NTSTATUS CleanupOutputSection(VOID);
NTSTATUS CleanupFileNameSection(VOID);
NTSTATUS CleanupAllSections(VOID);

// Utility functions
NTSTATUS InitializeSharedMemory(VOID);
NTSTATUS CleanupSharedMemory(VOID);
VOID ZeroSharedMemorySections(VOID);

// Helper functions for section operations
NTSTATUS CreateNamedSection(
    _In_ PCWSTR SectionName,
    _In_ SIZE_T SectionSize,
    _In_ ULONG Protection,
    _Out_ PHANDLE SectionHandle
);

NTSTATUS MapNamedSection(
    _In_ HANDLE SectionHandle,
    _Out_ PVOID* MappedBase,
    _Inout_ PSIZE_T ViewSize
);

NTSTATUS UnmapNamedSection(
    _In_ PVOID MappedBase
);
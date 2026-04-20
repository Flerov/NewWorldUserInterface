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


// From main.c
BOOL InsertVADNode(int Level, PVOID VADNode, unsigned long long StartingVpn,
    unsigned long long EndingVpn, UNICODE_STRING* FileName, ULONG VadFlagsRaw,
    ULONG ControlAreaFlags, ULONG MappedViews, ULONG UserReferences, BOOLEAN IsVadShort);
UNICODE_STRING* GetFileObjectFromVADLeaf(unsigned long long Leaf, DWORD MMVADSubsection,
    DWORD MMVADControlArea, DWORD MMVADCAFilePointer, DWORD MMCAFlags,
    DWORD FILEOBJECTFileName, PULONG pControlAreaFlags, PULONG pMappedViews, PULONG pUserReferences);
VOID WalkVADIterative(PVOID Root, unsigned long StartingVpnOffset, DWORD EndingVpnOffset,
    DWORD Left, DWORD Right, PULONG TotalVADs, PULONG TotalLevels,
    PULONG MaxDepth, DWORD MMVADSubsection, DWORD MMVADControlArea,
    DWORD MMVADCAFilePointer, DWORD MMCAFlags, DWORD FILEOBJECTFileName, unsigned long long targetAdr);
VOID WalkVAD(PEPROCESS TargetProcess, DWORD VADRootOffset, DWORD StartingVpnOffset,
    DWORD EndingVpnOffset, DWORD Left, DWORD Right, DWORD MMVADSubsection,
    DWORD MMVADControlArea, DWORD MMVADCAFilePointer, DWORD MMCAFlags, DWORD FILEOBJECTFileName,
    unsigned long long targetAdr);

// VadCheckConflict: acquires AddressCreationLock shared internally. Use when holding NO lock.
BOOLEAN VadCheckConflict(PEPROCESS Process, PSYM_INFO Syms,
    unsigned long long startVpn, unsigned long long endVpn);

// VadConflictWalkUnlocked: lock-free BST overlap walk.
// Caller MUST already hold AddressCreationLock (any mode). Use inside the
// check+insert critical section to avoid a deadlock with VadCheckConflict.
BOOLEAN VadConflictWalkUnlocked(PVOID root, PSYM_INFO Syms,
    unsigned long long startVpn, unsigned long long endVpn);

// VadTreeInsert: link a fully-initialised MMVAD node into the process VAD tree and rebalance.
//   NewNode's StartingVpn must already be encoded at Syms->StartingVpnOffset.
//   Does NOT allocate the node. Caller owns the allocation.
NTSTATUS VadTreeInsert(PEPROCESS Process, PSYM_INFO Syms, PVOID NewNode);

// VadTreeRemove: find the node with StartingVpn == targetVpn, unlink it, and rebalance.
//   Does NOT free the node allocation. On success *pRemovedNode is set (may be NULL if not needed).
NTSTATUS VadTreeRemove(PEPROCESS Process, PSYM_INFO Syms, unsigned long long targetVpn,
    PVOID* pRemovedNode);

// VadFindNodeByVpn: BST search for a node by StartingVpn. Returns NULL if not found.
PVOID VadFindNodeByVpn(PEPROCESS Process, PSYM_INFO Syms, unsigned long long targetVpn);

// Optional pool helpers — use only when the node was allocated with VadAllocateNode.
// Callers that manage their own allocations can ignore these entirely.
NTSTATUS VadAllocateNode(SIZE_T size, PVOID* pNode);
VOID     VadFreeNode(PVOID node);

// =================================================================
// Mi* kernel MM helper function pointer typedefs
// Signatures derived from ntoskrnl disassembly (x64 fastcall).
// =================================================================
// MiCheckForConflictingVad: rcx=EPROCESS*, rdx=StartVA (raw, NOT VPN), r8=EndVA (raw, NOT VPN)
// The function shifts rdx and r8 right by 12 itself — caller must pass VAs.
typedef PVOID  (*PFN_MiCheckForConflictingVad)(PEPROCESS Process, ULONG_PTR StartVA, ULONG_PTR EndVA);
typedef VOID   (*PFN_MiInsertVad)(PVOID Vad, PEPROCESS Process, ULONG Flags);
typedef NTSTATUS (*PFN_MiInsertVadCharges)(PVOID Vad, PEPROCESS Process);
typedef VOID   (*PFN_MiRemoveVad)(PVOID Vad, PEPROCESS Process);
typedef VOID   (*PFN_MiRemoveVadCharges)(PVOID Vad, PEPROCESS Process);
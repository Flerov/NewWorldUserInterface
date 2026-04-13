#pragma once
//#include <ntdef.h>
//#include <ntddk.h>
#include <ntifs.h>

#include "SharedConstants.h"

// Disable nameless struct/union warnings for this header
#pragma warning(push)
#pragma warning(disable: 4201)


// =================================================================
// BASIC TYPES
// =================================================================
typedef unsigned char       BYTE, * PBYTE, ** PPBYTE;
typedef unsigned short      WORD, * PWORD, ** PPWORD;
typedef unsigned long       DWORD, * PDWORD, ** PPDWORD;
typedef unsigned __int64    QWORD, * PQWORD, ** PPQWORD;
typedef int                 BOOL, * PBOOL, ** PPBOOL;
typedef void** PPVOID;

typedef struct _DEVICE_CONTEXT
{
	PDRIVER_OBJECT  pDriverObject;        // driver object ptr
	PDEVICE_OBJECT  pDeviceObject;        // device object ptr
	HANDLE			hSection;             // section handle
	HANDLE			hSectionFileName;	  // section handle for FileName
	MDL* pMdl;                 // memory descriptor list
	MDL* pFileNameMdl;         // memory descriptor list for FileName
	BOOLEAN			gSectionMapped;
	BOOLEAN			gFileNameSectionMapped;
}
DEVICE_CONTEXT, * PDEVICE_CONTEXT, ** PPDEVICE_CONTEXT;

typedef struct _VAD_NODE {
	int Level;
	PVOID VADNode;
	unsigned long long StartingVpn;
	unsigned long long EndingVpn;
	unsigned long Protection;
	//WCHAR FileName[MAX_FILENAME_SIZE];
	//CHAR FileName[MAX_FILENAME_SIZE];
	UCHAR FileOffset;
	LIST_ENTRY ListEntry;
} VAD_NODE, * PVAD_NODE;

// -----------------------------------------------------------------

typedef struct _VAD_NODE_FILE {
	CHAR FileName[MAX_FILENAME_SIZE];
} VAD_NODE_FILE, * PVAD_NODE_FILE;

// -----------------------------------------------------------------

typedef struct _INIT {
	CHAR identifier[4];
	CHAR sourceProcess[15];
	CHAR targetProcess[15];
	unsigned long long sourceVA;
	unsigned long long targetVPN;
	unsigned long long NtBaseOffset;
	DWORD KPROCDirectoryTableBaseOffset;
	DWORD EPROCActiveProcessLinksOfsset;
	DWORD EPROCUniqueProcessIdOffset;
	ULONG requestedProtection;
} INIT, * PINIT;

// -----------------------------------------------------------------

typedef struct _SYMBOL {
CHAR name[32];
unsigned long long offset;
LIST_ENTRY ListEntry;
} SYMBOL, * PSYMBOL;

// -----------------------------------------------------------------

typedef struct _SYM_INFO {
	unsigned long long ZwProtectVirtualMemory;
	unsigned long long EProcUniqueProcessId;
	unsigned long long EProcActiveProcessLinks;
	unsigned long long KPROCDirectoryTableBase;
	unsigned long long sourceVA;
	unsigned long long targetVPN;
	DWORD VADRoot;
	DWORD StartingVpnOffset;
	DWORD EndingVpnOffset;
	DWORD Left;
	DWORD Right;
	DWORD MMVADSubsection;
	DWORD MMVADControlArea;
	DWORD MMVADCAFilePointer;
	DWORD FILEOBJECTFileName;
	DWORD EProcImageFileName;
	DWORD PEB;
	DWORD PEBLdr;
	DWORD LdrListHead;
	DWORD LdrListEntry;
	DWORD LdrBaseDllName;
	DWORD LdrBaseDllBase;
} SYM_INFO, * PSYM_INFO;

// -----------------------------------------------------------------

typedef struct _PML4E
{
	union
	{
		struct
		{
			// Basic control bits (same across all page table levels)
			ULONG64 Present : 1;              // [0] Must be 1 if entry is valid
			ULONG64 ReadWrite : 1;            // [1] 0 = Read-only, 1 = Read/Write
			ULONG64 UserSupervisor : 1;       // [2] 0 = Kernel-only, 1 = User-mode accessible
			ULONG64 PageWriteThrough : 1;     // [3] Write-through caching enabled (part of PAT index)
			ULONG64 PageCacheDisable : 1;     // [4] Caching disabled (part of PAT index)
			ULONG64 Accessed : 1;             // [5] Set by hardware when entry is accessed
			ULONG64 Ignored1 : 1;             // [6] Ignored by hardware
			ULONG64 PageSize : 1;             // [7] Must be 0 for PML4E (reserved in this level)
			ULONG64 Ignored2 : 4;             // [8-11] Ignored by hardware
			ULONG64 PageFrameNumber : 36;     // [12-47] Physical page number (points to PDPT)
			ULONG64 Reserved1 : 4;            // [48-51] Reserved for system use
			ULONG64 Ignored3 : 7;             // [52-58] Ignored by hardware
			ULONG64 ProtectionKey : 4;        // [59-62] Protection key (if enabled)
			ULONG64 ExecuteDisable : 1;       // [63] If 1, prevents instruction fetches (NX bit)
		};
		ULONG64 Value;                        // Raw 64-bit value for direct access
	};
} PML4E, * PPML4E;
static_assert(sizeof(PML4E) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

// -----------------------------------------------------------------

typedef struct _PDPTE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;              // [0] Must be 1, region invalid if 0.
			ULONG64 ReadWrite : 1;            // [1] If 0, writes not allowed.
			ULONG64 UserSupervisor : 1;       // [2] If 0, user-mode accesses not allowed.
			ULONG64 PageWriteThrough : 1;     // [3] Determines the memory type used to access PD.
			ULONG64 PageCacheDisable : 1;     // [4] Determines the memory type used to access PD.
			ULONG64 Accessed : 1;             // [5] If 0, this entry has not been used for translation.
			ULONG64 Ignored1 : 1;			  // [6]
			ULONG64 PageSize : 1;             // [7] If 1, this entry maps a 1GB page.
			ULONG64 Ignored2 : 3;			  // [8..11] AVL
			ULONG64 PAT : 1;                  // [11] Page Attribute Table bit (Only valid for 1GB pages).
			ULONG64 PageFrameNumber : 36;     // [12..M-1] The page frame number of the PD of this PDPTE.
			ULONG64 Reserved : 4;			  // [M..51] Reserved (0)
			ULONG64 Ignored3 : 11;			  // [52..62] AVL
			ULONG64 ExecuteDisable : 1;       // [63] If 1, instruction fetches not allowed.
		};
		ULONG64 Value;
	};
} PDPTE, * PPDPTE;
static_assert(sizeof(PDPTE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

// -----------------------------------------------------------------

typedef struct _PDE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;              // [0] Must be 1, region invalid if 0.
			ULONG64 ReadWrite : 1;            // [1] If 0, writes not allowed.
			ULONG64 UserSupervisor : 1;       // [2] If 0, user-mode accesses not allowed.
			ULONG64 PageWriteThrough : 1;     // [3] Determines the memory type used to access PT.
			ULONG64 PageCacheDisable : 1;     // [4] Determines the memory type used to access PT.
			ULONG64 Accessed : 1;             // [5] If 0, this entry has not been used for translation.
			ULONG64 AVL : 1;			      // [6] Available to programmer.
			ULONG64 PageSize : 1;             // [7] If 1, this entry maps a 2MB page.
			ULONG64 Ignored2 : 3;			  // [8..11] AVL
			ULONG64 PAT : 1;			      // [11] Available to programmer
			ULONG64 PageFrameNumber : 36;     // [12..M-1] The page frame number of the PT of this PDE.
			ULONG64 Reserved : 4;			  // [M..51] Reserved (0)
			ULONG64 Ignored3 : 11;			  // [52..62] AVL
			ULONG64 ExecuteDisable : 1;       // [63] If 1, instruction fetches not allowed.
		};
		ULONG64 Value;
	};
} PDE, * PPDE;
static_assert(sizeof(PDE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

// -----------------------------------------------------------------

typedef struct _PTE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;              // [0] Must be 1, region invalid if 0.
			ULONG64 ReadWrite : 1;            // [1] If 0, writes not allowed.
			ULONG64 UserSupervisor : 1;       // [2] If 0, user-mode accesses not allowed.
			ULONG64 PageWriteThrough : 1;     // [3] Determines the memory type used to access the memory.
			ULONG64 PageCacheDisable : 1;     // [4] Determines the memory type used to access the memory.
			ULONG64 Accessed : 1;             // [5] If 0, this entry has not been used for translation.
			ULONG64 Dirty : 1;                // [6] If 0, the memory backing this page has not been written to.
			ULONG64 PAT : 1;				  // [7] Determines the memory type used to access the memory.
			ULONG64 Global : 1;               // [8] If 1 and the PGE bit of CR4 is set, translations are global.
			//ULONG64 Ignored2 : 3;			  // [8..11] AVL
			ULONG64 Ignored2 : 2;			  // [8..10] AVL
			ULONG64 COW : 1;				  // [11] Copy-on-write bit (if set, page is copy-on-write).
			ULONG64 PageFrameNumber : 36;     // [12..M-1] The page frame number of the backing physical page.
			ULONG64 Reserved : 4;			  // [M..51] Reserved (0)
			ULONG64 Ignored3 : 7;
			ULONG64 ProtectionKey : 4;         // If the PKE bit of CR4 is set, determines the protection key.
			ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
		};
		ULONG64 Value;
	};
} PTE, * PPTE;
static_assert(sizeof(PTE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

// -----------------------------------------------------------------

typedef struct _PHYSICAL_1GB {
	union {
		struct {
			ULONG64 Offset : 30;      // Offset within a 1GB page
			ULONG64 PageNumber : 18;  // Page Frame Number (PFN)
			ULONG64 Reserved : 16;    // Reserved bits
		};
		ULONG64 Value;
	};
} PHYSICAL_1GB, * PPHYSICAL_1GB;

// -----------------------------------------------------------------

typedef struct _PHYSICAL_2MB {
	union {
		struct {
			ULONG64 Offset : 21; // Offset within a 2 MB page
			ULONG64 PageNumber : 27; // Page Frame Number (PFN)
			ULONG64 Reserved : 16; // Unused or reserved bits
		};
		ULONG64 Value;
	};
} PHYSICAL_2MB, * PPHYSICAL_2MB;

// -----------------------------------------------------------------

typedef struct _PHYSICAL_4KB {
	union {
		struct {
			ULONG64 Offset : 12;         // Offset within a 4 KB page
			ULONG64 PageNumber : 36;     // Page Frame Number (PFN), supports 64-bit systems
			ULONG64 Reserved : 16;       // Reserved bits, may be used for future extensions
		};
		ULONG64 Value;
	};
} PHYSICAL_4KB, * PPHYSICAL_4KB;

// -----------------------------------------------------------------
// The Windows Header Flags for Protections are wrong WTF. So we reverse and redefine them.

typedef enum _PROTECTION
{
	_PAGE_READONLY = 0x01, // Read-only access to the page
	_PAGE_READWRITE = 0x04, // Read and write access to the page
	_PAGE_WRITECOPY = 0x07, // Copy-on-write access to the page
	_PAGE_EXECUTE = 0x10, // Execute access to the page
	_PAGE_NOACCESS = 0x18, // No access to the page
	_PAGE_EXECUTE_READ = 0x20  // Execute and read access to the page
} PROTECTION;

// -----------------------------------------------------------------

typedef union _MMVAD_FLAGS {
	struct {
		unsigned long Lock : 1; // Bit 0:0
		unsigned long LockContended : 1; // Bit 1:1
		unsigned long DeleteInProgress : 1; // Bit 2:2
		unsigned long NoChange : 1; // Bit 3:3
		unsigned long VadType : 3; // Bit 4:6
		unsigned long Protection : 5; // Bit 7:11
		unsigned long PreferredNode : 6; // Bit 12:17
		unsigned long PageSize : 20; // Bit 18:19
		unsigned long PrivateMemory : 1; // Bit 20:20
	};
	unsigned long LongFlags;
} MMVAD_FLAGS;

// -----------------------------------------------------------------
// Ref: https://github.com/reactos/reactos/blob/c03d7794b8a378001d8f15873a61ee108ba18a4b/sdk/include/ndk/arm64/mmtypes.h#L63
// Page-related Macros

#ifndef PAGE_SIZE
#define PAGE_SIZE                         0x1000
#endif
#define PAGE_SHIFT                        12L
#define MM_ALLOCATION_GRANULARITY         0x10000
#define MM_ALLOCATION_GRANULARITY_SHIFT   16L
#define MM_PAGE_FRAME_NUMBER_SIZE         20

// -----------------------------------------------------------------
/* Following structs are based on WoA symbols */

typedef struct _HARDWARE_PTE
{
	/* 8 Byte struct */
	ULONG64 Valid : 1;
	ULONG64 NotLargePage : 1;
	ULONG64 CacheType : 2;
	ULONG64 OsAvailable2 : 1;
	ULONG64 NonSecure : 1;
	ULONG64 Owner : 1;
	ULONG64 NotDirty : 1;
	ULONG64 Shareability : 2;
	ULONG64 Accessed : 1;
	ULONG64 NonGlobal : 1;
	ULONG64 PageFrameNumber : 36;
	ULONG64 RsvdZ1 : 4;
	ULONG64 ContigousBit : 1;
	ULONG64 PrivilegedNoExecute : 1;
	ULONG64 UserNoExecute : 1;
	ULONG64 Writable : 1;
	ULONG64 CopyOnWrite : 1;
	ULONG64 OsAvailable : 2;
	ULONG64 PxnTable : 1;
	ULONG64 UxnTable : 1;
	ULONG64 ApTable : 2;
	ULONG64 NsTable : 1;
} HARDWARE_PTE, * PHARDWARE_PTE;

// -----------------------------------------------------------------

typedef struct _MMPTE_SOFTWARE
{
	/* 8 Byte struct */
	ULONG64 Valid : 1;
	ULONG64 Protection : 5;
	ULONG64 PageFileLow : 4;
	ULONG64 Prototype : 1;
	ULONG64 Transition : 1;
	ULONG64 PageFileReserved : 1;
	ULONG64 PageFileAllocated : 1;
	ULONG64 UsedPageTableEntries : 10;
	ULONG64 ColdPage : 1;
	ULONG64 OnStandbyLookaside : 1;
	ULONG64 RsvdZ1 : 6;
	ULONG64 PageFileHigh : 32;
} MMPTE_SOFTWARE;

// -----------------------------------------------------------------

typedef struct _MMPTE_TRANSITION
{
	/* 8 Byte struct */
	ULONG64 Valid : 1;
	ULONG64 Protection : 5;
	ULONG64 Spare : 2;
	ULONG64 OnStandbyLookaside : 1;
	ULONG64 IoTracker : 1;
	ULONG64 Prototype : 1;
	ULONG64 Transition : 1;
	ULONG64 PageFrameNumber : 40;
	ULONG64 RsvdZ1 : 12;
} MMPTE_TRANSITION;

// -----------------------------------------------------------------

typedef struct _MMPTE_PROTOTYPE
{
	/* 8 Byte struct */
	ULONG64 Valid : 1;
	ULONG64 Protection : 5;
	ULONG64 HiberVerifyConverted : 1;
	ULONG64 Unused1 : 1;
	ULONG64 ReadOnly : 1;
	ULONG64 Combined : 1;
	ULONG64 Prototype : 1;
	ULONG64 DemandFillProto : 1;
	ULONG64 RsvdZ1 : 4;
	ULONG64 ProtoAddress : 48;
} MMPTE_PROTOTYPE;

// -----------------------------------------------------------------

typedef struct _MMPTE_SUBSECTION
{
	/* 8 Byte struct */
	ULONG64 Valid : 1;
	ULONG64 Protection : 5;
	ULONG64 OnStandbyLookaside : 1;
	ULONG64 RsvdZ1 : 3;
	ULONG64 Prototype : 1;
	ULONG64 ColdPage : 1;
	ULONG64 RsvdZ2 : 4;
	ULONG64 SubsectionAddress : 48;
} MMPTE_SUBSECTION;

// -----------------------------------------------------------------

typedef struct _MMPTE_TIMESTAMP
{
	/* 8 Byte struct */
	ULONG64 MustBeZero : 1;
	ULONG64 Protection : 5;
	ULONG64 PageFileLow : 4;
	ULONG64 Prototype : 1;
	ULONG64 Transition : 1;
	ULONG64 RsvdZ1 : 20;
	ULONG64 GlobalTimeStamp : 32;
} MMPTE_TIMESTAMP;

// -----------------------------------------------------------------

typedef struct _MMPTE_LIST
{
	/* 8 Byte struct */
	ULONG64 Valid : 1;
	ULONG64 Protection : 5;
	ULONG64 OneEntry : 1;
	ULONG64 RsvdZ1 : 3;
	ULONG64 Prototype : 1;
	ULONG64 Transition : 1;
	ULONG64 RsvdZ2 : 16;
	ULONG64 NextEntry : 36;
} MMPTE_LIST;

// -----------------------------------------------------------------

typedef struct _MMPTE
{
	union
	{
		ULONG_PTR Long;
		HARDWARE_PTE Flush;
		HARDWARE_PTE Hard;
		MMPTE_PROTOTYPE Proto;
		MMPTE_SOFTWARE Soft;
		MMPTE_TRANSITION Trans;
		MMPTE_SUBSECTION Subsect;
		MMPTE_LIST List;
	} u;
} MMPTE, * PMMPTE;

// -----------------------------------------------------------------

typedef struct _MMPFNENTRY
{
	USHORT Modified : 1;
	USHORT ReadInProgress : 1;                 // StartOfAllocation
	USHORT WriteInProgress : 1;                // EndOfAllocation
	USHORT PrototypePte : 1;
	USHORT PageColor : 4;
	USHORT PageLocation : 3;
	USHORT RemovalRequested : 1;
	USHORT CacheAttribute : 2;
	USHORT Rom : 1;
	USHORT ParityError : 1;
} MMPFNENTRY;

// -----------------------------------------------------------------

typedef struct _MM_RMAP_ENTRY
{
	struct _MM_RMAP_ENTRY* Next;
	PEPROCESS Process;
	PVOID Address;
#if DBG
	PVOID Caller;
#endif
}
MM_RMAP_ENTRY, * PMM_RMAP_ENTRY;

// -----------------------------------------------------------------

typedef ULONG_PTR SWAPENTRY;

// -----------------------------------------------------------------

typedef enum _MI_PFN_USAGES
{
	MI_USAGE_NOT_SET = 0,
	MI_USAGE_PAGED_POOL,
	MI_USAGE_NONPAGED_POOL,
	MI_USAGE_NONPAGED_POOL_EXPANSION,
	MI_USAGE_KERNEL_STACK,
	MI_USAGE_KERNEL_STACK_EXPANSION,
	MI_USAGE_SYSTEM_PTE,
	MI_USAGE_VAD,
	MI_USAGE_PEB_TEB,
	MI_USAGE_SECTION,
	MI_USAGE_PAGE_TABLE,
	MI_USAGE_PAGE_DIRECTORY,
	MI_USAGE_LEGACY_PAGE_DIRECTORY,
	MI_USAGE_DRIVER_PAGE,
	MI_USAGE_CONTINOUS_ALLOCATION,
	MI_USAGE_MDL,
	MI_USAGE_DEMAND_ZERO,
	MI_USAGE_ZERO_LOOP,
	MI_USAGE_CACHE,
	MI_USAGE_PFN_DATABASE,
	MI_USAGE_BOOT_DRIVER,
	MI_USAGE_INIT_MEMORY,
	MI_USAGE_PAGE_FILE,
	MI_USAGE_COW,
	MI_USAGE_WSLE,
	MI_USAGE_FREE_PAGE
} MI_PFN_USAGES;

// -----------------------------------------------------------------
// Memory Manager Working Set Structures

typedef struct _MMWSLENTRY
{
	ULONG_PTR Valid : 1;
	ULONG_PTR LockedInWs : 1;
	ULONG_PTR LockedInMemory : 1;
	ULONG_PTR Protection : 5;
	ULONG_PTR Hashed : 1;
	ULONG_PTR Direct : 1;
	ULONG_PTR Age : 2;
	ULONG_PTR VirtualPageNumber : MM_PAGE_FRAME_NUMBER_SIZE;
} MMWSLENTRY, * PMMWSLENTRY;

// -----------------------------------------------------------------

typedef struct _MMWSLE_FREE_ENTRY
{
	ULONG MustBeZero : 1;
	ULONG PreviousFree : 31;
	LONG NextFree;
#define MMWSLE_PREVIOUS_FREE_MASK 0x7FFFFFFF
} MMWSLE_FREE_ENTRY, * PMMWSLE_FREE_ENTRY;

// -----------------------------------------------------------------

typedef struct _MMWSLE
{
	union
	{
		PVOID VirtualAddress;
		ULONG_PTR Long;
		MMWSLENTRY e1;
		MMWSLE_FREE_ENTRY Free;
	} u1;
} MMWSLE, * PMMWSLE;

// -----------------------------------------------------------------

#define MI_PTE_FRAME_BITS 57

// -----------------------------------------------------------------

typedef struct _MMPFN
{
	union
	{
		PFN_NUMBER Flink;
		ULONG WsIndex;
		PKEVENT Event;
		NTSTATUS ReadStatus;
		SINGLE_LIST_ENTRY NextStackPfn;

		// HACK for ROSPFN
		SWAPENTRY SwapEntry;
	} u1;
	PMMPTE PteAddress;
	union
	{
		PFN_NUMBER Blink;
		ULONG_PTR ShareCount;
	} u2;
	union
	{
		struct
		{
			USHORT ReferenceCount;
			MMPFNENTRY e1;
		};
		struct
		{
			USHORT ReferenceCount;
			USHORT ShortFlags;
		} e2;
	} u3;
	ULONG UsedPageTableEntries;
	union
	{
		MMPTE OriginalPte;
		LONG AweReferenceCount;

		// HACK for ROSPFN
		PMM_RMAP_ENTRY RmapListHead;
	};
	union
	{
		ULONG_PTR EntireFrame;
		struct
		{
			ULONG_PTR PteFrame : MI_PTE_FRAME_BITS;
			ULONG_PTR InPageError : 1;
			ULONG_PTR VerifierAllocation : 1;
			ULONG_PTR AweAllocation : 1;
			ULONG_PTR Priority : 3;
			ULONG_PTR MustBeCached : 1;
		};
	} u4;
	//#if MI_TRACE_PFNS
	MI_PFN_USAGES PfnUsage;
	CHAR ProcessName[16];
#define MI_SET_PFN_PROCESS_NAME(pfn, x) memcpy(pfn->ProcessName, x, min(sizeof(x), sizeof(pfn->ProcessName)))
	PVOID CallSite;
	//#endif

		// HACK until WS lists are supported
	MMWSLE Wsle;
	struct _MMPFN* NextLRU;
	struct _MMPFN* PreviousLRU;
} MMPFN, * PMMPFN;

// -----------------------------------------------------------------

typedef struct _WRITE_PHYS_REQUEST {
    CHAR identifier[4];                         // Identifier "WPHY"
    //PHYSICAL_ADDRESS targetPhysicalAddress;     // Target physical address (base PFN address)
	unsigned long long targetVA;
    ULONG offsetInPage;                        // Offset within the 4KB page (0-4095)
    ULONG dataSize;                            // Size of data to write (must not exceed page boundary)
    UCHAR data[MAX_WRITE_BUFFER_SIZE];         // Data buffer
    BOOLEAN isValid;                           // Request validity flag
    ULONG reserved;                            // Reserved for alignment
} WRITE_PHYS_REQUEST, *PWRITE_PHYS_REQUEST;

// -----------------------------------------------------------------

typedef struct _READ_PHYS_REQUEST {
    CHAR identifier[4];                         // Identifier "RPHY"
    PVOID targetVirtualAddress;                 // Target virtual address to resolve
    BOOLEAN isValid;                           // Request validity flag
    ULONG reserved;                            // Reserved for alignment
    // The 4KB physical page content will be copied starting here
    UCHAR pageData[MAX_READ_BUFFER_SIZE];      // Physical page data (4KB)
} READ_PHYS_REQUEST, *PREAD_PHYS_REQUEST;

// -----------------------------------------------------------------
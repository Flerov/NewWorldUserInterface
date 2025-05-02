#pragma once
#include <ntdef.h>
#include <ntddk.h>
//#include <wdmsec.h> // For SDDL definitions


// =================================================================
// BASIC TYPES
// =================================================================
typedef unsigned char       BYTE, * PBYTE, ** PPBYTE;
typedef unsigned short      WORD, * PWORD, ** PPWORD;
typedef unsigned long       DWORD, * PDWORD, ** PPDWORD;
typedef unsigned __int64    QWORD, * PQWORD, ** PPQWORD;
typedef int                 BOOL, * PBOOL, ** PPBOOL;
typedef void** PPVOID;
// -----------------------------------------------------------------
#define BYTE_               sizeof (BYTE)
#define WORD_               sizeof (WORD)
#define DWORD_              sizeof (DWORD)
#define QWORD_              sizeof (QWORD)
#define BOOL_               sizeof (BOOL)
#define PVOID_              sizeof (PVOID)
#define HANDLE_             sizeof (HANDLE)
#define PHYSICAL_ADDRESS_   sizeof (PHYSICAL_ADDRESS)
// -----------------------------------------------------------------
#define DRV_MODULE          NewWorldInterface
#define DRV_NAME            NW Windows 2025 _INTERACE
#define DRV_COMPANY         Me
#define DRV_AUTHOR          Me
#define DRV_EMAIL           me@me.me
#define DRV_PREFIX          NW
// -----------------------------------------------------------------
#define _DRV_DEVICE(_name)  \\Device\\     ## _name
#define _DRV_LINK(_name)    \\DosDevices\\ ## _name
#define _DRV_PATH(_name)    \\\\.\\        ## _name
// -----------------------------------------------------------------
#define DRV_DEVICE              _DRV_DEVICE (DRV_MODULE)
#define DRV_LINK                _DRV_LINK   (DRV_MODULE)
#define DRV_PATH                _DRV_PATH   (DRV_MODULE)
#define DRV_EXTENSION           sys
// -----------------------------------------------------------------
#define _CSTRING(_text) #_text
#define CSTRING(_text) _CSTRING (_text)
// -----------------------------------------------------------------
#define _USTRING(_text) L##_text
#define USTRING(_text) _USTRING (_text)
// -----------------------------------------------------------------
#define PRESET_UNICODE_STRING(_symbol,_buffer) \
        UNICODE_STRING _symbol = \
            { \
            sizeof (USTRING (_buffer)) - sizeof (WORD), \
            sizeof (USTRING (_buffer)), \
            USTRING (_buffer) \
            };
// -----------------------------------------------------------------
typedef struct _DEVICE_CONTEXT
{
	PDRIVER_OBJECT  pDriverObject;        // driver object ptr
	PDEVICE_OBJECT  pDeviceObject;        // device object ptr
	HANDLE			hSection;             // section handle
	HANDLE			hSectionFileName;	  // section handle for FileName
	MDL*			pMdl;                 // memory descriptor list
	MDL*			pFileNameMdl;         // memory descriptor list for FileName
	BOOLEAN			gSectionMapped;
	BOOLEAN			gFileNameSectionMapped;
}
DEVICE_CONTEXT, * PDEVICE_CONTEXT, ** PPDEVICE_CONTEXT;
#define DEVICE_CONTEXT_ sizeof (DEVICE_CONTEXT)
// -----------------------------------------------------------------
#define FILE_DEVICE_NW_INTERFACE 0x9000
// -----------------------------------------------------------------
#define MAX_FILENAME_SIZE 80
//#define MAX_FILENAME_SIZE 64 // for WCHAR
// -----------------------------------------------------------------
typedef struct _VAD_NODE {
	int Level;
	PVOID VADNode;
	unsigned long long StartingVpn;
	unsigned long long EndingVpn;
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
	DWORD NtBaseOffset;
	DWORD KPROCDirectoryTableBaseOffset;
	DWORD EPROCActiveProcessLinksOfsset;
	DWORD EPROCUniqueProcessIdOffset;
} INIT, * PINIT;
// -----------------------------------------------------------------
typedef struct _SYMBOL {
	CHAR name[32];
	unsigned long long offset;
	LIST_ENTRY ListEntry;
} SYMBOL, * PSYMBOL;
// -----------------------------------------------------------------
typedef struct _SYM_INFO {
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
			ULONG64 Ignored2 : 3;			  // [8..11] AVL
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

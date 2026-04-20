#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")
#include <vector>
#include <iostream>
#include <tchar.h>
#include <Psapi.h>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")
#include <chrono>
#include <conio.h>
// -----------------------------------------------------------------

#define MAPPING_NAME_TO  L"Global\\MySharedMemory"
#define MAPPING_NAME_FROM L"Global\\VADSharedMemory"
#define MAPPING_NAME_FROM_FILENAMES L"Global\\VADSharedMemoryFileNames"
#define MAPPING_NAME_WRITE_PHYS L"Global\\WritePhysicalMemory"
#define MAPPING_NAME_READ_PHYS L"Global\\ReadPhysicalMemory"
#define MAPPING_NOTIFICATION_LINK_EVENT L"Global\\LinkMemory"
#define MAPPING_NOTIFICATION_Unlink_EVENT L"Global\\UnlinkMemory"
#define MAPPING_NOTIFICATION_INIT_EVENT L"Global\\InitializeMemory"
#define MAPPING_NOTIFICATION_USERMODEREADY_EVENT L"Global\\UserModeReadEvent"
#define MAPPING_NOTIFICATION_WRITE_PHYS_EVENT L"Global\\WritePhysicalMemoryEvent"
#define MAPPING_NOTIFICATION_READ_PHYS_EVENT  L"Global\\ReadPhysicalMemoryEvent"
#define MAPPING_NAME_VAD_MODIFY               L"Global\\VADModifyRequest"
#define MAPPING_NOTIFICATION_VAD_INSERT_EVENT L"Global\\VADInsertEvent"
#define MAPPING_NOTIFICATION_VAD_REMOVE_EVENT L"Global\\VADRemoveEvent"
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
	UCHAR walkMode;    // 0=target only  1=source only  2=both
	UCHAR reserved[3]; // padding
} INIT, * PINIT;
// -----------------------------------------------------------------
#define MAX_FILENAME_SIZE 80
#define MAX_WRITE_BUFFER_SIZE 4096
#define MAX_READ_BUFFER_SIZE 4096
// Section sizes — must match the values in NewWorldInterface\main.c
#define VAD_SECTION_SIZE       0x40000   // 256 KB — ~3200 VAD_NODE slots
#define VAD_FILENAME_SEC_SIZE  0x10000   // 64 KB  — ~800 VAD_NODE_FILE slots

// Define PHYSICAL_ADDRESS for user-mode
typedef union _PHYSICAL_ADDRESS {
    struct {
        ULONG LowPart;
        LONG HighPart;
    };
    struct {
        ULONG LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

// -----------------------------------------------------------------
// Must be byte-identical to VAD_NODE in SharedTypes.h (kernel side).
// _MMVAD_FLAGS and _MMSECTION_FLAGS are decoded at runtime using PDB-derived layout tables.
typedef struct _VAD_NODE {
	int                Level;
	PVOID              VADNode;
	PVOID              ParentNode;
	ULONG              Balance;
	unsigned long long StartingVpn;
	unsigned long long EndingVpn;
	unsigned long      Protection;
	ULONG              VadFlagsRaw;
	USHORT             FileOffset;
	ULONG              ControlAreaFlags;
	ULONG              MappedViews;      // _CONTROL_AREA.NumberOfMappedViews  (>1 = shared)
	ULONG              UserReferences;   // _CONTROL_AREA.NumberOfUserReferences
	BOOLEAN            IsVadShort;
	LIST_ENTRY         ListEntry;
} VAD_NODE, * PVAD_NODE;
// -----------------------------------------------------------------
// MMVAD internal protection encoding (NOT Win32 PAGE_* constants).
typedef enum _PROTECTION
{
	_PAGE_NOACCESS          = 0x00, // MM_ZERO_ACCESS
	_PAGE_READONLY          = 0x01, // MM_READONLY
	_PAGE_EXECUTE           = 0x02, // MM_EXECUTE
	_PAGE_EXECUTE_READ      = 0x03, // MM_EXECUTE_READ (RX)
	_PAGE_READWRITE         = 0x04, // MM_READWRITE
	_PAGE_WRITECOPY         = 0x05, // MM_WRITECOPY
	_PAGE_EXECUTE_READWRITE = 0x06, // MM_EXECUTE_READWRITE
	_PAGE_EXECUTE_WRITECOPY = 0x07  // MM_EXECUTE_WRITECOPY (DLL .text sections)
} PROTECTION;
// -----------------------------------------------------------------
typedef struct _VAD_NODE_FILE {
	CHAR FileName[MAX_FILENAME_SIZE];
} VAD_NODE_FILE, * PVAD_NODE_FILE;
// -----------------------------------------------------------------
typedef struct _SYMBOL {
	CHAR name[32];
	unsigned long long offset;
	LIST_ENTRY ListEntry;
} SYMBOL, * PSYMBOL;
// -----------------------------------------------------------------
typedef struct _WRITE_PHYS_REQUEST {
    CHAR identifier[4];                         // Identifier "WPHY"
    unsigned long long targetVirtualAddress;                 // Target virtual address to resolve to physical
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
// Usermode mirror of VAD_MODIFY_REQUEST (kernel side SharedTypes.h)
typedef struct _VAD_MODIFY_REQUEST {
	CHAR               identifier[4];       // "VINS", "VREM", or "QHNT"
	unsigned long long StartingVpn;         // VINS/VREM: region start VPN
	unsigned long long EndingVpn;           // VINS: region end VPN
	ULONG              Protection;          // VINS: MMVAD protection value
	ULONG              VadTypeRaw;          // VINS: raw _MMVAD_FLAGS DWORD
	SIZE_T             NodeSize;            // VINS: alloc size (0 = kernel default 0x80)
	BOOLEAN            FreeOnRemove;        // VREM: driver frees pool after unlink
	BOOLEAN            isValid;             // set by us; cleared by kernel on completion
	LONG               Result;              // NTSTATUS written by kernel
	// QHNT response fields
	unsigned long long SuggestedUserVpn;    // next free VPN in user space  (0 if none)
	unsigned long long SuggestedKernelVpn;  // next free VPN in kernel space (0 if none)
} VAD_MODIFY_REQUEST, *PVAD_MODIFY_REQUEST;

// =================================================================
// GLOBAL VARIABLES
// =================================================================
size_t totalAllocationSize;
size_t totalCopiedSize;

PVOID SymbolsArray;
static int SymbolsArrayIndex = 0;
size_t SymbolsArrayAllocationSize = 0;
// -----------------------------------------------------------------

typedef struct PE_relocation_t {
	DWORD RVA;
	WORD Type : 4;
} PE_relocation;

typedef struct PE_codeview_debug_info_t {
	DWORD signature;
	GUID guid;
	DWORD age;
	CHAR pdbName[1];
} PE_codeview_debug_info;

typedef struct PE_pointers {
	BOOL isMemoryMapped;
	BOOL isInAnotherAddressSpace;
	HANDLE hProcess;
	PVOID baseAddress;
	//headers ptrs
	IMAGE_DOS_HEADER* dosHeader;
	IMAGE_NT_HEADERS* ntHeader;
	IMAGE_OPTIONAL_HEADER* optHeader;
	IMAGE_DATA_DIRECTORY* dataDir;
	IMAGE_SECTION_HEADER* sectionHeaders;
	//export info
	IMAGE_EXPORT_DIRECTORY* exportDirectory;
	LPDWORD exportedNames;
	DWORD exportedNamesLength;
	LPDWORD exportedFunctions;
	LPWORD exportedOrdinals;
	//relocations info
	DWORD nbRelocations;
	PE_relocation* relocations;
	//debug info
	IMAGE_DEBUG_DIRECTORY* debugDirectory;
	PE_codeview_debug_info* codeviewDebugInfo;
} PE;

typedef struct symbol_ctx_t {
	LPWSTR pdb_name_w;
	DWORD64 pdb_base_addr;
	HANDLE sym_handle;
} symbol_ctx;

// -----------------------------------------------------------------
// Bitfield member descriptor: one entry per member of a bitfield struct/union.
typedef struct _BITFIELD_MEMBER {
	char   name[64];   // member name
	DWORD  bitPos;     // absolute bit position within the containing DWORD (byte_offset*8 + bit_position)
	DWORD  bitLen;     // bit width
} BITFIELD_MEMBER;

// Extract a bit-field value from a raw DWORD given position + length.
static inline ULONG ExtractBits(ULONG raw, DWORD bitPos, DWORD bitLen) {
	if (bitLen == 0 || bitLen >= 32) return 0;
	return (raw >> bitPos) & ((1u << bitLen) - 1u);
}

// Find a named member in a BITFIELD_MEMBER array and return a pointer to it, or NULL.
static const BITFIELD_MEMBER* FindBitfieldMember(
	const BITFIELD_MEMBER* arr, DWORD count, const char* name) {
	for (DWORD i = 0; i < count; i++)
		if (_stricmp(arr[i].name, name) == 0) return &arr[i];
	return NULL;
}

// -----------------------------------------------------------------
// Runtime bitfield layout tables, populated from the PDB at startup.
#define MAX_BITFIELD_MEMBERS 64
typedef struct _BITFIELD_LAYOUT {
	BITFIELD_MEMBER members[MAX_BITFIELD_MEMBERS];
	DWORD           count;
	BOOL            valid;  // TRUE once populated from PDB
} BITFIELD_LAYOUT;

// One layout per MMVAD_FLAGS variant + _MMSECTION_FLAGS.
static BITFIELD_LAYOUT g_MmVadFlags;         // _MMVAD_FLAGS  (primary: _MMVAD.Core.u)
static BITFIELD_LAYOUT g_MmVadFlags1;        // _MMVAD_FLAGS1 (supplemental: _MMVAD.u for special types)
static BITFIELD_LAYOUT g_MmVadFlags2;        // _MMVAD_FLAGS2 (supplemental: _MMVAD.u for image)
static BITFIELD_LAYOUT g_MmSectionFlags;     // _MMSECTION_FLAGS

// Convenience: get a decoded field value from any layout.
static inline ULONG GetFlag(const BITFIELD_LAYOUT* layout, ULONG raw, const char* name) {
	const BITFIELD_MEMBER* m = FindBitfieldMember(layout->members, layout->count, name);
	if (!m || m->bitLen == 0) return 0;
	return ExtractBits(raw, m->bitPos, m->bitLen);
}
// -----------------------------------------------------------------

PBYTE ReadFullFileW(LPCWSTR fileName) {
	HANDLE hFile = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	DWORD fileSize = GetFileSize(hFile, NULL);
	PBYTE fileContent = (PBYTE)malloc(fileSize); // cast
	DWORD bytesRead = 0;
	if (!ReadFile(hFile, fileContent, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
		free(fileContent);
		fileContent = NULL;
	}
	CloseHandle(hFile);
	return fileContent;
}

IMAGE_SECTION_HEADER* PE_sectionHeader_fromRVA(PE* pe, DWORD rva) {
	IMAGE_SECTION_HEADER* sectionHeaders = pe->sectionHeaders;
	for (DWORD sectionIndex = 0; sectionIndex < pe->ntHeader->FileHeader.NumberOfSections; sectionIndex++) {
		DWORD currSectionVA = sectionHeaders[sectionIndex].VirtualAddress;
		DWORD currSectionVSize = sectionHeaders[sectionIndex].Misc.VirtualSize;
		if (currSectionVA <= rva && rva < currSectionVA + currSectionVSize) {
			return &sectionHeaders[sectionIndex];
		}
	}
	return NULL;
}

PVOID PE_RVA_to_Addr(PE* pe, DWORD rva) {
	PVOID peBase = pe->dosHeader;
	if (pe->isMemoryMapped) {
		return (PBYTE)peBase + rva;
	}

	IMAGE_SECTION_HEADER* rvaSectionHeader = PE_sectionHeader_fromRVA(pe, rva);
	if (NULL == rvaSectionHeader) {
		return NULL;
	}
	else {
		return (PBYTE)peBase + rvaSectionHeader->PointerToRawData + (rva - rvaSectionHeader->VirtualAddress);
	}
}

PE* PE_create(PVOID imageBase, BOOL isMemoryMapped) {
	PE* pe = (PE*)calloc(1, sizeof(PE));
	if (NULL == pe) {
		exit(1);
	}
	pe->isMemoryMapped = isMemoryMapped;
	pe->isInAnotherAddressSpace = FALSE;
	pe->hProcess = INVALID_HANDLE_VALUE;
	pe->dosHeader = (IMAGE_DOS_HEADER*)imageBase; // cast
	pe->ntHeader = (IMAGE_NT_HEADERS*)(((PBYTE)imageBase) + pe->dosHeader->e_lfanew);
	pe->optHeader = &pe->ntHeader->OptionalHeader;
	if (isMemoryMapped) {
		pe->baseAddress = imageBase;
	}
	else {
		pe->baseAddress = (PVOID)pe->optHeader->ImageBase;
	}
	pe->dataDir = pe->optHeader->DataDirectory;
	pe->sectionHeaders = (IMAGE_SECTION_HEADER*)(((PBYTE)pe->optHeader) + pe->ntHeader->FileHeader.SizeOfOptionalHeader);
	DWORD exportRVA = pe->dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportRVA == 0) {
		pe->exportDirectory = NULL;
		pe->exportedNames = NULL;
		pe->exportedFunctions = NULL;
		pe->exportedOrdinals = NULL;
	}
	else {
		pe->exportDirectory = (IMAGE_EXPORT_DIRECTORY*)PE_RVA_to_Addr(pe, exportRVA);
		pe->exportedNames = (LPDWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfNames);
		pe->exportedFunctions = (LPDWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfFunctions);
		pe->exportedOrdinals = (LPWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfNameOrdinals);
		pe->exportedNamesLength = pe->exportDirectory->NumberOfNames;
	}
	pe->relocations = NULL;
	DWORD debugRVA = pe->dataDir[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
	if (debugRVA == 0) {
		pe->debugDirectory = NULL;
	}
	else {
		pe->debugDirectory = (IMAGE_DEBUG_DIRECTORY*)PE_RVA_to_Addr(pe, debugRVA);
		if (pe->debugDirectory->Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
			pe->debugDirectory = NULL;
		}
		else {
			pe->codeviewDebugInfo = (PE_codeview_debug_info*)PE_RVA_to_Addr(pe, pe->debugDirectory->AddressOfRawData);
			if (pe->codeviewDebugInfo->signature != *((DWORD*)"RSDS")) {
				pe->debugDirectory = NULL;
				pe->codeviewDebugInfo = NULL;
			}
		}
	}
	return pe;
}

VOID PE_destroy(PE* pe)
{
	if (pe->relocations) {
		free(pe->relocations);
		pe->relocations = NULL;
	}
	free(pe);
}

BOOL FileExistsW(LPCWSTR szPath)
{
	DWORD dwAttrib = GetFileAttributesW(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL WriteFullFileW(LPCWSTR fileName, PBYTE fileContent, SIZE_T fileSize) {
	HANDLE hFile = CreateFileW(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	BOOL res = WriteFile(hFile, fileContent, (DWORD)fileSize, NULL, NULL);
	CloseHandle(hFile);
	return res;
}

BOOL HttpsDownloadFullFile(LPCWSTR domain, LPCWSTR uri, PBYTE* output, SIZE_T* output_size) {
	///wprintf_or_not(L"Downloading https://%s%s...\n", domain, uri);
	// Get proxy configuration
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;
	WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig);
	BOOL proxySet = !(proxyConfig.fAutoDetect || proxyConfig.lpszAutoConfigUrl != NULL);
	DWORD proxyAccessType = proxySet ? ((proxyConfig.lpszProxy == NULL) ?
		WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_NAMED_PROXY) : WINHTTP_ACCESS_TYPE_NO_PROXY;
	LPCWSTR proxyName = proxySet ? proxyConfig.lpszProxy : WINHTTP_NO_PROXY_NAME;
	LPCWSTR proxyBypass = proxySet ? proxyConfig.lpszProxyBypass : WINHTTP_NO_PROXY_BYPASS;

	// Initialize HTTP session and request
	HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.0", proxyAccessType, proxyName, proxyBypass, 0);
	if (hSession == NULL) {
		printf("WinHttpOpen failed with error : 0x%x\n", GetLastError());
		return FALSE;
	}
	HINTERNET hConnect = WinHttpConnect(hSession, domain, INTERNET_DEFAULT_HTTPS_PORT, 0);
	if (!hConnect) {
		printf("WinHttpConnect failed with error : 0x%x\n", GetLastError());
		return FALSE;
	}
	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", uri, NULL,
		WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	if (!hRequest) {
		return FALSE;
	}

	// Configure proxy manually
	if (!proxySet)
	{
		WINHTTP_AUTOPROXY_OPTIONS  autoProxyOptions;
		autoProxyOptions.dwFlags = proxyConfig.lpszAutoConfigUrl != NULL ? WINHTTP_AUTOPROXY_CONFIG_URL : WINHTTP_AUTOPROXY_AUTO_DETECT;
		autoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
		autoProxyOptions.fAutoLogonIfChallenged = TRUE;

		if (proxyConfig.lpszAutoConfigUrl != NULL)
			autoProxyOptions.lpszAutoConfigUrl = proxyConfig.lpszAutoConfigUrl;

		WCHAR szUrl[MAX_PATH] = { 0 };
		swprintf_s(szUrl, _countof(szUrl), L"https://%ws%ws", domain, uri);

		WINHTTP_PROXY_INFO proxyInfo;
		WinHttpGetProxyForUrl(
			hSession,
			szUrl,
			&autoProxyOptions,
			&proxyInfo);

		WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo));
		DWORD logonPolicy = WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW;
		WinHttpSetOption(hRequest, WINHTTP_OPTION_AUTOLOGON_POLICY, &logonPolicy, sizeof(logonPolicy));
	}

	// Perform request
	BOOL bRequestSent;
	do {
		bRequestSent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	} while (!bRequestSent && GetLastError() == ERROR_WINHTTP_RESEND_REQUEST);
	if (!bRequestSent) {
		return FALSE;
	}
	BOOL bResponseReceived = WinHttpReceiveResponse(hRequest, NULL);
	if (!bResponseReceived) {
		return FALSE;
	}

	// Read response
	DWORD dwAvailableSize = 0;
	DWORD dwDownloadedSize = 0;
	SIZE_T allocatedSize = 4096;
	if (!WinHttpQueryDataAvailable(hRequest, &dwAvailableSize))
	{
		return FALSE;
	}
	*output = (PBYTE)malloc(allocatedSize);
	*output_size = 0;
	while (dwAvailableSize)
	{
		while (*output_size + dwAvailableSize > allocatedSize) {
			allocatedSize *= 2;
			PBYTE new_output = (PBYTE)realloc(*output, allocatedSize);
			if (new_output == NULL)
			{
				return FALSE;
			}
			*output = new_output;
		}
		if (!WinHttpReadData(hRequest, *output + *output_size, dwAvailableSize, &dwDownloadedSize))
		{
			return FALSE;
		}
		*output_size += dwDownloadedSize;

		WinHttpQueryDataAvailable(hRequest, &dwAvailableSize);
	}
	PBYTE new_output = (PBYTE)realloc(*output, *output_size);
	if (new_output == NULL)
	{
		return FALSE;
	}
	*output = new_output;
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);
	return TRUE;
}

BOOL DownloadPDB(GUID guid, DWORD age, LPCWSTR pdb_name_w, PBYTE* file, SIZE_T* file_size) {
	WCHAR full_pdb_uri[MAX_PATH] = { 0 };
	swprintf_s(full_pdb_uri, _countof(full_pdb_uri), L"/download/symbols/%s/%08X%04hX%04hX%016llX%X/%s", pdb_name_w, guid.Data1, guid.Data2, guid.Data3, _byteswap_uint64(*((DWORD64*)guid.Data4)), age, pdb_name_w);
	return HttpsDownloadFullFile(L"msdl.microsoft.com", full_pdb_uri, file, file_size);
}

BOOL DownloadPDBFromPE(PE* image_pe, PBYTE* file, SIZE_T* file_size) {
	WCHAR pdb_name_w[MAX_PATH] = { 0 };
	GUID guid = image_pe->codeviewDebugInfo->guid;
	DWORD age = image_pe->codeviewDebugInfo->age;
	MultiByteToWideChar(CP_UTF8, 0, image_pe->codeviewDebugInfo->pdbName, -1, pdb_name_w, _countof(pdb_name_w));
	return DownloadPDB(guid, age, pdb_name_w, file, file_size);
}

symbol_ctx* LoadSymbolsFromPE(PE* pe) {
	symbol_ctx* ctx = (symbol_ctx*)calloc(1, sizeof(symbol_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, NULL, 0);
	ctx->pdb_name_w = (LPWSTR)calloc(size_needed, sizeof(WCHAR));
	MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, ctx->pdb_name_w, size_needed);
	if (!FileExistsW(ctx->pdb_name_w)) {
		printf("Symbol file does not exist!\n");
		return NULL;
		PBYTE file;
		SIZE_T file_size;
		BOOL res = DownloadPDBFromPE(pe, &file, &file_size);
		if (!res) {
			free(ctx);
			return NULL;
		}
		WriteFullFileW(ctx->pdb_name_w, file, file_size);
		free(file);
	}
	else {
		//TODO : check if exisiting PDB corresponds to the file version
	}
	DWORD64 asked_pdb_base_addr = 0x140000000; // ntos baseAddress from Debugging at pe = ... -> 0x0000000140000000 ; ci base -> 0x00000001c0000000
	//DWORD64 asked_pdb_base_addr = 0x1337000; // ntos baseAddress from Debugging at pe = ... -> 0x0000000140000000 ; ci base -> 0x00000001c0000000
	//DWORD64 asked_pdb_base_addr = 0x1c0000000; // ntos baseAddress from Debugging at pe = ... -> 0x0000000140000000 ; ci base -> 0x00000001c0000000
	DWORD pdb_image_size = MAXDWORD;
	HANDLE cp = GetCurrentProcess();
	//if (!SymInitialize(cp, NULL, FALSE)) {
	if (!SymInitializeW(cp, ctx->pdb_name_w, FALSE)) {
		//if (!SymInitializeW(cp, ctx->pdb_name_w, FALSE)) {
		printf("[-] Failed SymInitialize\n");
		free(ctx);
		return NULL;
	}
	ctx->sym_handle = cp;

	//DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
	DWORD64 addr = (DWORD64)pe->baseAddress;
	//addr -= 0x13ECC9000;
	//DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, (DWORD64)pe->baseAddress, pdb_image_size, NULL, 0);
	DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, addr, pdb_image_size, NULL, 0);

	//printf("tmp\n");
	while (pdb_base_addr == 0) {
		DWORD err = GetLastError();
		if (err == ERROR_SUCCESS)
			printf("[+] Success\n");
		break;
		if (err == ERROR_FILE_NOT_FOUND) {
			printf("[-] PDB file not found\n");
			SymUnloadModule(cp, asked_pdb_base_addr);//TODO : fix handle leak
			SymCleanup(cp);
			free(ctx);
			return NULL;
		}
		asked_pdb_base_addr += 0x100000;
		//pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
		pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, (DWORD64)pe->baseAddress, pdb_image_size, NULL, 0);
	}
	ctx->pdb_base_addr = pdb_base_addr;
	printf("[*] PDB base address: 0x%llx\n", ctx->pdb_base_addr);
	return ctx;
}

symbol_ctx* LoadSymbolsFromImageFile(LPCWSTR image_file_path) {
	PVOID image_content = ReadFullFileW(image_file_path);
	PE* pe = PE_create(image_content, FALSE);
	symbol_ctx* ctx = LoadSymbolsFromPE(pe);
	PE_destroy(pe);
	free(image_content);
	return ctx;
}

DWORD GetFieldOffset(symbol_ctx* ctx, LPCSTR struct_name, LPCWSTR field_name) {
	SYMBOL_INFO_PACKAGE si = { 0 };
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen = sizeof(si.name);
	BOOL res = SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, struct_name, &si.si);
	if (!res) {
		DWORD err = GetLastError();
		printf("[-] SymGetTypeFromName failed: sym_handle: 0x%llx, pdb_base_addr: 0x%llx, struct_name: %s, Err: %d\n", ctx->sym_handle, ctx->pdb_base_addr, struct_name, err);
		return 0;
	}

	TI_FINDCHILDREN_PARAMS* childrenParam = (TI_FINDCHILDREN_PARAMS*)calloc(1, sizeof(TI_FINDCHILDREN_PARAMS));
	if (childrenParam == NULL) {
		printf("[-] calloc failed\n");
		return 0;
	}

	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_GET_CHILDRENCOUNT, &childrenParam->Count);
	if (!res) {
		printf("[-] SymGetTypeInfo failed\n");
		return 0;
	}
	TI_FINDCHILDREN_PARAMS* ptr = (TI_FINDCHILDREN_PARAMS*)realloc(childrenParam, sizeof(TI_FINDCHILDREN_PARAMS) + childrenParam->Count * sizeof(ULONG));
	if (ptr == NULL) {
		printf("[-] realloc failed\n");
		free(childrenParam);
		return 0;
	}
	childrenParam = ptr;
	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_FINDCHILDREN, childrenParam);
	DWORD offset = 0;
	for (ULONG i = 0; i < childrenParam->Count; i++) {
		ULONG childID = childrenParam->ChildId[i];
		WCHAR* name = NULL;
		SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_SYMNAME, &name);
		if (wcscmp(field_name, name)) {
			continue;
		}
		SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_OFFSET, &offset);
		break;
	}
	free(childrenParam);
	return offset;
}
// Enumerate all members of a struct/union from the PDB, recording byte-offset,
// bit-position and bit-length for each.  Returns the number of members found.
// pOut must point to a buffer of at least maxOut BITFIELD_MEMBER entries.
// Helper: enumerate bitfield members from a type ID, recursing into anonymous nested UDTs.
// In PDB, all direct children of a struct/union are SymTagData.
// An anonymous inner struct is a SymTagData child whose *type* is SymTagUDT — we recurse into it.
static DWORD EnumBitfieldMembersById(HANDLE symHandle, DWORD64 base,
	DWORD typeId, DWORD byteBase,
	BITFIELD_MEMBER* pOut, DWORD maxOut) {

	DWORD count = 0;
	if (!SymGetTypeInfo(symHandle, base, typeId, TI_GET_CHILDRENCOUNT, &count) || count == 0)
		return 0;

	TI_FINDCHILDREN_PARAMS* cp = (TI_FINDCHILDREN_PARAMS*)calloc(
		1, sizeof(TI_FINDCHILDREN_PARAMS) + count * sizeof(ULONG));
	if (!cp) return 0;
	cp->Count = count;
	SymGetTypeInfo(symHandle, base, typeId, TI_FINDCHILDREN, cp);

	DWORD found = 0;
	for (DWORD i = 0; i < count && found < maxOut; i++) {
		ULONG id = cp->ChildId[i];

		// Get the type of this child member
		DWORD childTypeId = 0;
		SymGetTypeInfo(symHandle, base, id, TI_GET_TYPE, &childTypeId);

		// Check if the child's type is a UDT (anonymous nested struct/union)
		DWORD typeTag = 0;
		if (childTypeId)
			SymGetTypeInfo(symHandle, base, childTypeId, TI_GET_SYMTAG, &typeTag);

		if (typeTag == 11 /* SymTagUDT */) {
			// Anonymous nested struct/union — get its byte offset and recurse into its type
			DWORD nestedByteOffset = 0;
			SymGetTypeInfo(symHandle, base, id, TI_GET_OFFSET, &nestedByteOffset);
			DWORD sub = EnumBitfieldMembersById(symHandle, base, childTypeId,
				byteBase + nestedByteOffset, pOut + found, maxOut - found);
			found += sub;
		} else {
			// Regular member (bitfield or plain field) — record it
			WCHAR* wname = NULL;
			SymGetTypeInfo(symHandle, base, id, TI_GET_SYMNAME, &wname);
			if (!wname) continue;

			DWORD memberByteOffset = 0, bitPos = 0;
			ULONGLONG bitLen = 0;
			SymGetTypeInfo(symHandle, base, id, TI_GET_OFFSET,      &memberByteOffset);
			SymGetTypeInfo(symHandle, base, id, TI_GET_BITPOSITION, &bitPos);
			SymGetTypeInfo(symHandle, base, id, TI_GET_LENGTH,      &bitLen);

			WideCharToMultiByte(CP_UTF8, 0, wname, -1,
				pOut[found].name, (int)sizeof(pOut[found].name), NULL, NULL);
			pOut[found].bitPos = (byteBase + memberByteOffset) * 8 + bitPos;
			pOut[found].bitLen = (DWORD)bitLen;
			LocalFree(wname);
			found++;
		}
	}
	free(cp);
	return found;
}

DWORD GetBitfieldMembers(symbol_ctx* ctx, LPCSTR struct_name,
	BITFIELD_MEMBER* pOut, DWORD maxOut) {
	SYMBOL_INFO_PACKAGE si = { 0 };
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen   = sizeof(si.name);
	if (!SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, struct_name, &si.si)) {
		printf("[-] GetBitfieldMembers: SymGetTypeFromName failed for '%s': %d\n",
			struct_name, GetLastError());
		return 0;
	}
	DWORD found = EnumBitfieldMembersById(ctx->sym_handle, ctx->pdb_base_addr,
		si.si.TypeIndex, 0, pOut, maxOut);
	if (found == 0)
		printf("[-] GetBitfieldMembers: no members found for '%s'\n", struct_name);
	return found;
}

void UnloadSymbols(symbol_ctx* ctx, BOOL delete_pdb) {
	if (ctx == NULL) {
		return;
	}

	if (ctx->sym_handle != NULL && ctx->pdb_base_addr != 0) {
		// Only unload this specific module
		if (!SymUnloadModule(ctx->sym_handle, ctx->pdb_base_addr)) {
			printf("[-] SymUnloadModule failed: %d\n", GetLastError());
		}

		// Don't call SymCleanup here - it terminates the symbol handler
		// SymCleanup should only be called when you're completely done with symbols
	}

	// Delete the PDB file if requested
	if (delete_pdb && ctx->pdb_name_w != NULL) {
		DeleteFileW(ctx->pdb_name_w);
	}

	// Free allocated memory
	if (ctx->pdb_name_w != NULL) {
		free(ctx->pdb_name_w);
		ctx->pdb_name_w = NULL;
	}

	// Free the context structure itself
	free(ctx);
}
void CleanupSymbolHandler(HANDLE symHandle) {
	if (symHandle != NULL) {
		if (!SymCleanup(symHandle)) {
			printf("[-] SymCleanup failed: %d\n", GetLastError());
		}
	}
}
DWORD64 GetSymbolOffset(symbol_ctx* ctx, LPCSTR symbol_name) {
	SYMBOL_INFO symbolInfo = { 0 };
	symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
	symbolInfo.MaxNameLen = MAX_SYM_NAME;

	// Use SymFromName to look up symbols (including functions)
	if (SymFromName(ctx->sym_handle, symbol_name, &symbolInfo)) {
		return symbolInfo.Address - ctx->pdb_base_addr;
	}
	else {
		DWORD err = GetLastError();
		printf("[-] SymFromName failed for '%s': error %d (0x%x)\n", symbol_name, err, err);

		// Try as a type (for backward compatibility)
		SYMBOL_INFO_PACKAGE si = { 0 };
		si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
		si.si.MaxNameLen = sizeof(si.name);

		if (SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, symbol_name, &si.si)) {
			return si.si.Address - ctx->pdb_base_addr;
		}

		return 0;
	}
}
// -----------------------------------------------------------------
unsigned long long GetAndInsertSymbol(const char* str, symbol_ctx* symCtx, DWORD64 offset, BOOLEAN useOffset) {
	size_t strLen = strlen(str);
	if (strLen >= 32) {
		printf("[-] Maximum string size reached...\n");
		return 0x0;
	}
	if (SymbolsArrayIndex >= SymbolsArrayAllocationSize) {
		printf("[-] Maximum reached...\n");
		return 0x0;
	}
	// Cast to PBYTE so +sizeof(INIT) is exactly sizeof(INIT) bytes, not sizeof(INIT)² bytes.
	PSYMBOL CurrSymbolInArray = (PSYMBOL)((PBYTE)SymbolsArray + sizeof(INIT));

	if (!useOffset) {
		offset = GetSymbolOffset(symCtx, str);
	}
	memcpy(CurrSymbolInArray[SymbolsArrayIndex].name, std::move(str), strLen);
	CurrSymbolInArray[SymbolsArrayIndex].offset = offset;

	totalCopiedSize += strLen;
	SymbolsArrayIndex++;

	return offset;
}
// -----------------------------------------------------------------
BOOL AddInitData(unsigned long long NtBaseOffset, DWORD KPROCDirectoryTableBaseOffset, DWORD EPROCActiveProcessLinksOfsset, DWORD EPROCUniqueProcessIdOffset, const char* sourceProcess, const char* targetProcess) {
	PINIT Data = (PINIT)SymbolsArray;
	memcpy(Data[0].identifier, "INIT", 4);
	Data[0].NtBaseOffset = NtBaseOffset;
	printf("NTBaseOffset: 0x%llx\n", NtBaseOffset);
	if (sourceProcess != NULL) {
		size_t copyLenSource = min(strlen(sourceProcess), sizeof(Data[0].sourceProcess) - 1);
		memcpy(Data[0].sourceProcess, sourceProcess, copyLenSource);
	}
	if (targetProcess != NULL) {
		size_t copyLenTarget = min(strlen(targetProcess), sizeof(Data[0].targetProcess) - 1);
		memcpy(Data[0].targetProcess, targetProcess, copyLenTarget);
	}
	Data[0].KPROCDirectoryTableBaseOffset = KPROCDirectoryTableBaseOffset;
	Data[0].EPROCActiveProcessLinksOfsset = EPROCActiveProcessLinksOfsset;
	Data[0].EPROCUniqueProcessIdOffset = EPROCUniqueProcessIdOffset;
	return true;
}
// -----------------------------------------------------------------
DWORD64 GetKernelBase(_In_ std::string name) {
	/* Gets the base address (VIRTUAL ADDRESS) of a module in kernel address space */
	// Defining EnumDeviceDrivers() and GetDeviceDriverBaseNameA() parameters
	LPVOID lpImageBase[1024]{};
	DWORD lpcbNeeded{};
	int drivers{};
	char lpFileName[1024]{};
	DWORD64 imageBase{};
	// Grabs an array of all of the device drivers
	BOOL success = EnumDeviceDrivers(
		lpImageBase,
		sizeof(lpImageBase),
		&lpcbNeeded
	);
	// Makes sure that we successfully grabbed the drivers
	if (!success)
	{
		printf("[-] Unable to invoke EnumDeviceDrivers()!\n");
		return 0;
	}
	// Defining number of drivers for GetDeviceDriverBaseNameA()
	drivers = lpcbNeeded / sizeof(lpImageBase[0]);
	// Parsing loaded drivers
	for (int i = 0; i < drivers; i++) {
		// Gets the name of the driver
		GetDeviceDriverBaseNameA(
			lpImageBase[i],
			lpFileName,
			sizeof(lpFileName) / sizeof(char)
		);
		// Compares the indexed driver and with our specified driver name
		if (!strcmp(name.c_str(), lpFileName)) {
			imageBase = (DWORD64)lpImageBase[i];
			break;
		}
	}
	return imageBase;
}
// -----------------------------------------------------------------
void HexDump(void* pMemory, size_t size) {
	unsigned char* p = (unsigned char*)pMemory;

	for (size_t i = 0; i < size; i += 16) {  // Process 16 bytes per line
		printf("%08X  ", (unsigned int)i);   // Print offset

		// Print hex bytes
		for (size_t j = 0; j < 16; j++) {
			if (i + j < size)
				printf("%02X ", p[i + j]);
			else
				printf("   ");  // Padding for alignment
		}

		printf(" | ");  // Separator

		// Print ASCII representation
		for (size_t j = 0; j < 16; j++) {
			if (i + j < size) {
				unsigned char c = p[i + j];
				printf("%c", (c >= 32 && c <= 126) ? c : '.');  // Printable ASCII or dot
			}
		}

		printf(" |\n");
	}
}
// -----------------------------------------------------------------
void CheckModifiedMemory(PVOID address, size_t size) {
	PVOID base = (PVOID)((unsigned long long)address & 0xfffffffffffff000);
	printf("[+] Checking memory at base: 0x%p\n", base);

	// Just read, don't modify permissions with VirtualProtect
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(base, &mbi, sizeof(mbi))) {
		printf("\t.. Memory protection: 0x%lx\n", mbi.Protect);
		printf("\t.. Memory state: %s\n",
			mbi.State == MEM_COMMIT ? "COMMIT" :
			mbi.State == MEM_RESERVE ? "RESERVE" : "FREE");
	}

	// Read directly from memory without changing permissions
	__try {
		printf("\t.. Memory content (first 16 bytes):\n");
		unsigned char* p = (unsigned char*)base;

		for (size_t i = 0; i < size; i += 16) {  // Process 16 bytes per line
			printf("\t\t%08X  ", (unsigned int)i);   // Print offset

			// Print hex bytes
			for (size_t j = 0; j < 16; j++) {
				if (i + j < size)
					printf("%02X ", p[i + j]);
				else
					printf("   ");  // Padding for alignment
			}

			printf(" | ");  // Separator

			// Print ASCII representation
			for (size_t j = 0; j < 16; j++) {
				if (i + j < size) {
					unsigned char c = p[i + j];
					printf("%c", (c >= 32 && c <= 126) ? c : '.');  // Printable ASCII or dot
				}
			}

			printf(" |\n");
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("[-] Exception when reading memory: 0x%lx\n", GetExceptionCode());
	}
}
// -----------------------------------------------------------------
const char* ProtectionToStr(PROTECTION prot) {
	switch (prot) {
	case _PAGE_NOACCESS:          return "PAGE_NOACCESS";
	case _PAGE_READONLY:          return "PAGE_READONLY";
	case _PAGE_EXECUTE:           return "PAGE_EXECUTE";
	case _PAGE_EXECUTE_READ:      return "PAGE_EXECUTE_READ";
	case _PAGE_READWRITE:         return "PAGE_READWRITE";
	case _PAGE_WRITECOPY:         return "PAGE_WRITECOPY";
	case _PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE";
	case _PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
	default:                      return "UNKNOWN_PROTECTION";
	}
}
// -----------------------------------------------------------------
// Build a short type-tag string from VadFlagsRaw + ControlAreaFlags using PDB layouts.
// Tag priority: Private > Image > File > Pagefile > Physical > Global > Shared
static void BuildVadTypeTag(ULONG vf, ULONG ca, BOOLEAN isShort, ULONG mappedViews, ULONG userRefs, char* out, size_t outLen) {
	// _MMVAD_FLAGS is the single primary layout for both _MMVAD_SHORT and _MMVAD
	const BITFIELD_LAYOUT* flagLayout = g_MmVadFlags.valid ? &g_MmVadFlags : NULL;
	if (!flagLayout) { strcpy_s(out, outLen, ""); return; }

	ULONG vadType    = GetFlag(flagLayout, vf, "VadType");
	ULONG isPrivate  = GetFlag(flagLayout, vf, "PrivateMemory");
	ULONG isImage    = GetFlag(&g_MmSectionFlags, ca, "Image");
	ULONG isFile     = GetFlag(&g_MmSectionFlags, ca, "File");
	ULONG isPhys     = GetFlag(&g_MmSectionFlags, ca, "PhysicalMemory");
	ULONG isGlobal   = GetFlag(&g_MmSectionFlags, ca, "GlobalMemory");
	ULONG isNullFP   = GetFlag(&g_MmSectionFlags, ca, "FilePointerNull");
	static const char* vadTypeNames[] = {
		"", "DevPhys", "Image", "AWE", "WrtWatch", "LrgPage", "RotPhys", "LrgPgSec"
	};
	char buf[48] = "";
	if (isPrivate) {
		switch (vadType) {
		case 0: strcpy_s(buf, sizeof(buf), "Private");  break;
		case 3: strcpy_s(buf, sizeof(buf), "AWE");      break;
		case 4: strcpy_s(buf, sizeof(buf), "WrtWatch"); break;
		case 5: strcpy_s(buf, sizeof(buf), "LrgPage");  break;
		default: snprintf(buf, sizeof(buf), "Prv[%u]", vadType); break;
		}
	} else if (ca != 0) {
		if (vadType == 1 || isPhys)         strcpy_s(buf, sizeof(buf), "Physical");
		else if (isImage)                   strcpy_s(buf, sizeof(buf), "Image");
		else if (isFile && !isNullFP)       strcpy_s(buf, sizeof(buf), "File");
		else if (isGlobal && isNullFP)      strcpy_s(buf, sizeof(buf), "Global/Shared");
		else if (isGlobal)                  strcpy_s(buf, sizeof(buf), "Global");
		else if (isNullFP)                  strcpy_s(buf, sizeof(buf), "Pagefile");
		else if (vadType < 8 && vadType > 0) strcpy_s(buf, sizeof(buf), vadTypeNames[vadType]);
		else                                strcpy_s(buf, sizeof(buf), "Section");
	} else {
		if (vadType < 8 && vadType > 0)     strcpy_s(buf, sizeof(buf), vadTypeNames[vadType]);
		else                                strcpy_s(buf, sizeof(buf), "Reserve");
	}
	// Append sharing breakdown: [Nv: Kk+Uu]
	//   N = total mapped views, K = kernel views (MappedViews - UserReferences), U = user views
	// K>0 means the kernel (driver/Mm) has the section mapped too, not just user processes.
	if (mappedViews > 0) {
		ULONG kernelViews = (mappedViews > userRefs) ? (mappedViews - userRefs) : 0;
		ULONG userViews   = mappedViews - kernelViews;
		char suffix[32];
		if (kernelViews > 0)
			snprintf(suffix, sizeof(suffix), " [%uv: %uk+%uu]", mappedViews, kernelViews, userViews);
		else
			snprintf(suffix, sizeof(suffix), " [%uv: %uu]", mappedViews, userViews);
		strncat_s(buf, sizeof(buf), suffix, _TRUNCATE);
	}
	strcpy_s(out, outLen, buf);
}
// -----------------------------------------------------------------
void GetSymOffsets(PVOID SecBase, size_t SecSize,
	PVOID FileNameSecBase,
	SIZE_T FileNameSecSize) {
	if (SecBase == NULL)
		return;

	PVAD_NODE      node         = (PVAD_NODE)SecBase;
	PVAD_NODE_FILE FileNameBase = (PVAD_NODE_FILE)FileNameSecBase;
	size_t maxSymCount  = SecSize / sizeof(VAD_NODE);
	size_t maxFileNames = FileNameSecSize / sizeof(VAD_NODE_FILE);

	printf("\n%-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
		"Lvl", "VADNode", "StartingVpn", "EndingVpn", "4KBs",
		"Protection", "Type", "FileName");
	printf("%-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
		"-----", "-----------------", "-------------", "-------------", "---------",
		"--------------------------", "--------------", "-----------------------------------");

	__try {
		for (size_t i = 0; i < maxSymCount - 1; i++) {
			if (node[i].Level == 0) continue;

			if (node[i].Level == -1 && node[i].StartingVpn == 0xFFFFFFFFFFFFFFFEULL) {
				printf("\n  ---- [ Source Process ] -------------------------------------------------------------------------\n");
				printf("%-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
					"Lvl", "VADNode", "StartingVpn", "EndingVpn", "4KBs",
					"Protection", "Type", "FileName");
				printf("%-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
					"-----", "-----------------", "-------------", "-------------", "---------",
					"--------------------------", "--------------", "-----------------------------------");
				continue;
			}

			PROTECTION prot = (PROTECTION)node[i].Protection;
			const char* fileName = (node[i].FileOffset && node[i].FileOffset < maxFileNames)
				? FileNameBase[node[i].FileOffset].FileName : "-";

			char typeTag[48] = "";
			if (g_MmSectionFlags.valid)
				BuildVadTypeTag(node[i].VadFlagsRaw, node[i].ControlAreaFlags, node[i].IsVadShort,
					node[i].MappedViews, node[i].UserReferences, typeTag, sizeof(typeTag));

			char protBuf[40];
			snprintf(protBuf, sizeof(protBuf), "%-22s [0x%x]",
				ProtectionToStr(prot), node[i].Protection);

			printf("%-5d  0x%-16p  0x%011I64x  0x%011I64x  %-9I64u  %-26s  %-14s  %-35s\n",
				node[i].Level,
				node[i].VADNode,
				node[i].StartingVpn,
				node[i].EndingVpn,
				node[i].EndingVpn - node[i].StartingVpn + 1,
				protBuf,
				typeTag,
				fileName);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("Exception when reading VAD data: 0x%lx\n", GetExceptionCode());
	}
}
// -----------------------------------------------------------------
void UpdateInitData(const char* sourceProcess,
	const char* targetProcess,
	unsigned long long sourceVA,
	unsigned long long targetVPN,
	ULONG newProtection) {
	PINIT Data = (PINIT)SymbolsArray;
	if (sourceProcess != NULL) {
		size_t copyLenSource = min(strlen(sourceProcess), sizeof(Data[0].sourceProcess) - 1);
		memset(Data[0].sourceProcess, 0, sizeof(Data[0].sourceProcess));
		memcpy(Data[0].sourceProcess, sourceProcess, copyLenSource);
	}
	if (targetProcess != NULL) {
		size_t copyLenTarget = min(strlen(targetProcess), sizeof(Data[0].targetProcess) - 1);
		memset(Data[0].targetProcess, 0, sizeof(Data[0].targetProcess));
		memcpy(Data[0].targetProcess, targetProcess, copyLenTarget);
	}
	if (sourceVA != 0x0)
		Data[0].sourceVA = sourceVA;
	if (targetVPN != 0x0)
		Data[0].targetVPN = targetVPN;
	if (newProtection != 0)
		Data[0].requestedProtection = newProtection;
	printf("[*] InitData updated successfully\n");
}
void AddInitDataSection(symbol_ctx* sym_ctxNtskrnl) {
	if (sym_ctxNtskrnl == NULL) {
		printf("Symbols for ntoskrnl.exe not available, download failed, aborting...\n");
		exit(1);
	}
	unsigned long long ntBase = GetKernelBase("ntoskrnl.exe"); // DWORD64
	unsigned long long eprocUniqueProcessId = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"UniqueProcessId");
	unsigned long long eprocActiveProcessLinks = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"ActiveProcessLinks");
	unsigned long long kprocDirectoryTableBase = GetFieldOffset(sym_ctxNtskrnl, "_KPROCESS", L"DirectoryTableBase");// Parse command line arguments]

	if (AddInitData(ntBase, kprocDirectoryTableBase, eprocActiveProcessLinks, eprocUniqueProcessId, 0x0, 0x0))
		printf("[*] InitData added successfully\n");

	GetAndInsertSymbol("ZwProtectVirtualMemory", sym_ctxNtskrnl, 0x0, false);
	GetAndInsertSymbol("eprocUniqueProcessId", sym_ctxNtskrnl, eprocUniqueProcessId, true); // TODO: exceution stops here???
	GetAndInsertSymbol("eprocActiveProcessLinks", sym_ctxNtskrnl, eprocActiveProcessLinks, true);
	GetAndInsertSymbol("kprocDirectoryTableBase", sym_ctxNtskrnl, kprocDirectoryTableBase, true);
	unsigned long long VADRoot = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"VadRoot");
	unsigned long long StartingVpn1 = GetFieldOffset(sym_ctxNtskrnl, "_MMVAD_SHORT", L"StartingVpn");
	unsigned long long EndingVpn1 = GetFieldOffset(sym_ctxNtskrnl, "_MMVAD_SHORT", L"EndingVpn");
	unsigned long long Left = GetFieldOffset(sym_ctxNtskrnl, "_RTL_BALANCED_NODE", L"Left");
	unsigned long long Right = GetFieldOffset(sym_ctxNtskrnl, "_RTL_BALANCED_NODE", L"Right");
	GetAndInsertSymbol("VADRoot", sym_ctxNtskrnl, VADRoot, true);
	GetAndInsertSymbol("StartingVpn", sym_ctxNtskrnl, StartingVpn1, true);
	GetAndInsertSymbol("EndingVpn", sym_ctxNtskrnl, EndingVpn1, true);
	GetAndInsertSymbol("Left", sym_ctxNtskrnl, Left, true);
	GetAndInsertSymbol("Right", sym_ctxNtskrnl, Right, true);
	unsigned long long MMVADSubsection = GetFieldOffset(sym_ctxNtskrnl, "_MMVAD", L"Subsection");
	unsigned long long MMVADControlArea = GetFieldOffset(sym_ctxNtskrnl, "_MMVAD", L"ControlArea"); // actually at Off: 0x0 and its _CONTROL_AREA*
	unsigned long long MMVADCAFilePointer = GetFieldOffset(sym_ctxNtskrnl, "_CONTROL_AREA", L"FilePointer");
	unsigned long long MMCAFlags         = GetFieldOffset(sym_ctxNtskrnl, "_CONTROL_AREA", L"u");
	unsigned long long MMCAMappedViews   = GetFieldOffset(sym_ctxNtskrnl, "_CONTROL_AREA", L"NumberOfMappedViews");
	unsigned long long MMCAUserRefs      = GetFieldOffset(sym_ctxNtskrnl, "_CONTROL_AREA", L"NumberOfUserReferences");
	GetAndInsertSymbol("MMVADSubsection",      sym_ctxNtskrnl, MMVADSubsection,    true);
	GetAndInsertSymbol("MMVADControlArea",     sym_ctxNtskrnl, MMVADControlArea,   true);
	GetAndInsertSymbol("MMVADCAFilePointer",   sym_ctxNtskrnl, MMVADCAFilePointer, true);
	GetAndInsertSymbol("MMCAFlags",            sym_ctxNtskrnl, MMCAFlags,          true);
	GetAndInsertSymbol("MMCAMappedViews",      sym_ctxNtskrnl, MMCAMappedViews,    true);
	GetAndInsertSymbol("MMCAUserReferences",   sym_ctxNtskrnl, MMCAUserRefs,       true);
	unsigned long long FILEOBJECTFileName = GetFieldOffset(sym_ctxNtskrnl, "_FILE_OBJECT", L"FileName");
	GetAndInsertSymbol("FILEOBJECTFileName", sym_ctxNtskrnl, FILEOBJECTFileName, true);
	unsigned long long EPROCImageFileName = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"ImageFileName");
	GetAndInsertSymbol("EPROCImageFileName", sym_ctxNtskrnl, EPROCImageFileName, true);
	unsigned long long PEB = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"Peb");
	unsigned long long PEBLdr = GetFieldOffset(sym_ctxNtskrnl, "_PEB", L"Ldr");
	unsigned long long LdrListHead = GetFieldOffset(sym_ctxNtskrnl, "_PEB_LDR_DATA", L"InMemoryOrderModuleList");
	unsigned long long LdrListEntry = GetFieldOffset(sym_ctxNtskrnl, "_LDR_DATA_TABLE_ENTRY", L"InMemoryOrderLinks");
	unsigned long long LdrBaseDllName = GetFieldOffset(sym_ctxNtskrnl, "_LDR_DATA_TABLE_ENTRY", L"BaseDllName");
	unsigned long long LdrBaseDllBase = GetFieldOffset(sym_ctxNtskrnl, "_LDR_DATA_TABLE_ENTRY", L"DllBase");
	GetAndInsertSymbol("PEB", sym_ctxNtskrnl, PEB, true);
	GetAndInsertSymbol("PEBLdr", sym_ctxNtskrnl, PEBLdr, true);
	GetAndInsertSymbol("LdrListHead", sym_ctxNtskrnl, LdrListHead, true);
	GetAndInsertSymbol("LdrListEntry", sym_ctxNtskrnl, LdrListEntry, true);
	GetAndInsertSymbol("LdrBaseDllName", sym_ctxNtskrnl, LdrBaseDllName, true);
	GetAndInsertSymbol("LdrBaseDllBase", sym_ctxNtskrnl, LdrBaseDllBase, true);

	// AVL tree modification fields
	unsigned long long ParentValue        = GetFieldOffset(sym_ctxNtskrnl, "_RTL_BALANCED_NODE", L"ParentValue");
	unsigned long long AddressCreationLock = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS",          L"AddressCreationLock");
	unsigned long long VadHint            = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS",          L"VadHint");
	unsigned long long VadFreeHint        = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS",          L"VadFreeHint");
	GetAndInsertSymbol("ParentValue",         sym_ctxNtskrnl, ParentValue,         true);
	GetAndInsertSymbol("AddressCreationLock", sym_ctxNtskrnl, AddressCreationLock, true);
	GetAndInsertSymbol("VadHint",             sym_ctxNtskrnl, VadHint,             true);
	GetAndInsertSymbol("VadFreeHint",         sym_ctxNtskrnl, VadFreeHint,         true);

	// Kernel MM internal helpers — absolute addresses (ntBase + PDB RVA)
	unsigned long long MiCheckForConflictingVad = GetSymbolOffset(sym_ctxNtskrnl, "MiCheckForConflictingVad");
	unsigned long long MiInsertVad              = GetSymbolOffset(sym_ctxNtskrnl, "MiInsertVad");
	unsigned long long MiInsertVadCharges       = GetSymbolOffset(sym_ctxNtskrnl, "MiInsertVadCharges");
	unsigned long long MiRemoveVad              = GetSymbolOffset(sym_ctxNtskrnl, "MiRemoveVad");
	unsigned long long MiRemoveVadCharges       = GetSymbolOffset(sym_ctxNtskrnl, "MiRemoveVadCharges");
	if (!MiInsertVad)
		printf("[!] MiInsertVad not found in PDB — Mi* path will be skipped, manual AVL fallback active\n");
	GetAndInsertSymbol("MiCheckForConflictingVad", sym_ctxNtskrnl, MiCheckForConflictingVad, false);
	GetAndInsertSymbol("MiInsertVad",              sym_ctxNtskrnl, MiInsertVad,              false);
	GetAndInsertSymbol("MiInsertVadCharges",       sym_ctxNtskrnl, MiInsertVadCharges,        false);
	GetAndInsertSymbol("MiRemoveVad",              sym_ctxNtskrnl, MiRemoveVad,              false);
	GetAndInsertSymbol("MiRemoveVadCharges",       sym_ctxNtskrnl, MiRemoveVadCharges,        false);

	// ---- PDB-derived bitfield layouts ----------------------------------------
	// Populate global decode tables for all MMVAD_FLAGS variants + _MMSECTION_FLAGS.
	// These are used by ShowTree (usermode) and their bit-positions are also sent
	// to the kernel via SYM_INFO so WalkVADIterative never uses hardcoded offsets.
	g_MmVadFlags.count      = GetBitfieldMembers(sym_ctxNtskrnl, "_MMVAD_FLAGS",  g_MmVadFlags.members,  MAX_BITFIELD_MEMBERS);
	g_MmVadFlags.valid      = g_MmVadFlags.count > 0;
	g_MmVadFlags1.count     = GetBitfieldMembers(sym_ctxNtskrnl, "_MMVAD_FLAGS1", g_MmVadFlags1.members, MAX_BITFIELD_MEMBERS);
	g_MmVadFlags1.valid     = g_MmVadFlags1.count > 0;
	g_MmVadFlags2.count     = GetBitfieldMembers(sym_ctxNtskrnl, "_MMVAD_FLAGS2", g_MmVadFlags2.members, MAX_BITFIELD_MEMBERS);
	g_MmVadFlags2.valid     = g_MmVadFlags2.count > 0;
	g_MmSectionFlags.count  = GetBitfieldMembers(sym_ctxNtskrnl, "_MMSECTION_FLAGS", g_MmSectionFlags.members, MAX_BITFIELD_MEMBERS);
	g_MmSectionFlags.valid  = g_MmSectionFlags.count > 0;

	printf("[*] Bitfield layouts: _MMVAD_FLAGS=%u _MMVAD_FLAGS1=%u _MMVAD_FLAGS2=%u _MMSECTION_FLAGS=%u members\n",
		g_MmVadFlags.count, g_MmVadFlags1.count, g_MmVadFlags2.count, g_MmSectionFlags.count);
	if (g_MmVadFlags.count > 0) {
		printf("[*] _MMVAD_FLAGS members:\n");
		for (DWORD i = 0; i < g_MmVadFlags.count; i++)
			printf("    [%2u] %-24s  bitPos=%2u  bitLen=%u\n", i,
				g_MmVadFlags.members[i].name,
				g_MmVadFlags.members[i].bitPos,
				g_MmVadFlags.members[i].bitLen);
	}
	if (g_MmSectionFlags.count > 0) {
		printf("[*] _MMSECTION_FLAGS members:\n");
		for (DWORD i = 0; i < g_MmSectionFlags.count; i++)
			printf("    [%2u] %-24s  bitPos=%2u  bitLen=%u\n", i,
				g_MmSectionFlags.members[i].name,
				g_MmSectionFlags.members[i].bitPos,
				g_MmSectionFlags.members[i].bitLen);
	}

	// _MMVAD primary flags — _MMVAD_FLAGS contains VadType, Protection, PrivateMemory
	// at the same bit positions for both _MMVAD_SHORT.Core.u and full _MMVAD.Core.u
	unsigned long long MMVADFlagsOffset = GetFieldOffset(sym_ctxNtskrnl, "_MMVAD_SHORT", L"u");
	GetAndInsertSymbol("MMVADFlagsOffset", sym_ctxNtskrnl, MMVADFlagsOffset, true);

	const BITFIELD_LAYOUT* flPrimary = g_MmVadFlags.valid ? &g_MmVadFlags : NULL;
	const BITFIELD_MEMBER* mProt    = flPrimary ? FindBitfieldMember(flPrimary->members, flPrimary->count, "Protection")    : NULL;
	const BITFIELD_MEMBER* mVadType = flPrimary ? FindBitfieldMember(flPrimary->members, flPrimary->count, "VadType")        : NULL;
	const BITFIELD_MEMBER* mPriv    = flPrimary ? FindBitfieldMember(flPrimary->members, flPrimary->count, "PrivateMemory")  : NULL;
	GetAndInsertSymbol("ProtectionBitPos",    sym_ctxNtskrnl, mProt    ? mProt->bitPos    : 7,  true);
	GetAndInsertSymbol("ProtectionBitLen",    sym_ctxNtskrnl, mProt    ? mProt->bitLen    : 5,  true);
	GetAndInsertSymbol("VadTypeBitPos",       sym_ctxNtskrnl, mVadType ? mVadType->bitPos : 4,  true);
	GetAndInsertSymbol("VadTypeBitLen",       sym_ctxNtskrnl, mVadType ? mVadType->bitLen : 3,  true);
	GetAndInsertSymbol("PrivateMemoryBitPos", sym_ctxNtskrnl, mPriv    ? mPriv->bitPos    : 20, true);
}

// -----------------------------------------------------------------
// Converts a hex string (like "41 42 ?? 44") to byte array and mask
// Returns true if conversion successful, false otherwise
bool ParseHexPattern(const char* hexPattern, std::vector<unsigned char>& pattern, std::vector<bool>& mask) {
	pattern.clear();
	mask.clear();

	if (!hexPattern || *hexPattern == '\0')
		return false;

	const char* ptr = hexPattern;
	while (*ptr) {
		// Skip whitespace
		if (isspace(*ptr)) {
			ptr++;
			continue;
		}

		// Handle wildcards
		if (*ptr == '?') {
			pattern.push_back(0);
			mask.push_back(false);  // false = ignore this byte when matching
			ptr++;
			// Skip second question mark if present (for "??" notation)
			if (*ptr == '?')
				ptr++;
		}
		// Process hex byte
		else if (isxdigit(ptr[0]) && isxdigit(ptr[1])) {
			char byteStr[3] = { ptr[0], ptr[1], 0 };
			unsigned char byte = (unsigned char)strtoul(byteStr, nullptr, 16);
			pattern.push_back(byte);
			mask.push_back(true);  // true = check this byte when matching
			ptr += 2;
		}
		else {
			// Invalid character
			return false;
		}
	}

	return !pattern.empty();
}

// -----------------------------------------------------------------
// Searches for pattern in a range of memory
// Returns vector of offsets where pattern was found
std::vector<size_t> ScanMemory(const void* memoryStart, size_t memorySize, const char* hexPattern) {
	std::vector<size_t> results;

	if (!memoryStart || !hexPattern || memorySize == 0)
		return results;

	// Convert hex pattern to bytes and mask
	std::vector<unsigned char> pattern;
	std::vector<bool> mask;

	if (!ParseHexPattern(hexPattern, pattern, mask))
		return results;

	if (pattern.size() > memorySize)
		return results;  // Pattern is larger than scan range

	const unsigned char* memory = static_cast<const unsigned char*>(memoryStart);

	// Scan through memory
	for (size_t i = 0; i <= memorySize - pattern.size(); i++) {
		bool found = true;

		for (size_t j = 0; j < pattern.size(); j++) {
			// If mask[j] is true, check byte; otherwise, it's a wildcard
			if (mask[j] && memory[i + j] != pattern[j]) {
				found = false;
				break;
			}
		}

		if (found) {
			results.push_back(i);
		}
	}

	return results;
}

#define min(a,b)            (((a) < (b)) ? (a) : (b))
// -----------------------------------------------------------------
// Helper function that scans memory and prints results
bool ScanAndPrintMemory(const void* address, const char* hexPattern) {
	//printf("[*] Scanning 4096 bytes at address 0x%p for pattern: %s\n", address, hexPattern);

	// Use Structured Exception Handling to prevent crashes on invalid memory
	//__try {
		// First, convert the pattern to get its size
		std::vector<unsigned char> pattern;
		std::vector<bool> mask;
		if (!ParseHexPattern(hexPattern, pattern, mask)) {
			printf("[-] Invalid hex pattern format\n");
			return 0;
		}

		// Now perform the scan
		std::vector<size_t> matches = ScanMemory(address, 4096, hexPattern);

		if (matches.empty()) {
			printf("[-] No matches found\n");
			return 0;
		}

		if (matches.size() >= 1) {
			printf("[+] Found %zu matches:\n", matches.size());
			// Print each match with surrounding context
			const unsigned char* memory = static_cast<const unsigned char*>(address);
			for (size_t offset : matches) {
				printf("[+] Match at offset 0x%04zx (address 0x%p):\n", offset, static_cast<const unsigned char*>(address) + offset);

				// Display hex dump of found pattern with context
				printf("    ");

				// Determine context range (8 bytes before, 8 bytes after)
				size_t contextStart = offset > 8 ? offset - 8 : 0;
				size_t contextEnd = min(offset + pattern.size() + 8, 4096ULL);

				// Print hex bytes
				for (size_t i = contextStart; i < contextEnd; i++) {
					if (i == offset) printf("[ ");
					printf("%02X ", memory[i]);
					if (i == offset + pattern.size() - 1) printf("] ");
				}

				printf("\n    ");

				// Print ASCII representation
				for (size_t i = contextStart; i < contextEnd; i++) {
					if (i == offset) printf("|");
					char c = memory[i];
					printf("%c", (c >= 32 && c <= 126) ? c : '.');
					if (i == offset + pattern.size() - 1) printf("|");
				}

				printf("\n");
			}
			return 1;
		}
	//}
	//__except (EXCEPTION_EXECUTE_HANDLER) {
	//	printf("[-] Exception occurred while accessing memory: 0x%lx\n");
	//}
}

// -----------------------------------------------------------------
// Prints the VAD tree as a numbered, indented list.
// -----------------------------------------------------------------
size_t ShowTree(PVOID SecBase, size_t SecSize,
	PVOID FileNameSecBase, size_t FileNameSecSize,
	unsigned long long* selectedVpns, size_t maxVpns) {
	if (!SecBase) return 0;

	PVAD_NODE      node     = (PVAD_NODE)SecBase;
	PVAD_NODE_FILE fileBase = (PVAD_NODE_FILE)FileNameSecBase;
	size_t maxNodes   = SecSize / sizeof(VAD_NODE);
	size_t maxNames   = FileNameSecSize / sizeof(VAD_NODE_FILE);
	size_t count      = 0;

	printf("\n%-4s  %-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
		"#", "Lvl", "VADNode", "StartVpn", "EndVpn", "4KBs",
		"Protection", "Type", "FileName");
	printf("%-4s  %-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
		"---", "-----", "-----------------", "-------------", "-------------", "---------",
		"--------------------------", "--------------", "-----------------------------------");

	__try {
		for (size_t i = 0; i < maxNodes - 1; i++) {
			if (node[i].Level == 0) continue;

			// Sentinel written by kernel for mode=2 (both) to separate sections
			if (node[i].Level == -1 && node[i].StartingVpn == 0xFFFFFFFFFFFFFFFEULL) {
				printf("\n  ---- [ Source Process ] -------------------------------------------------------------------------\n");
				printf("%-4s  %-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
					"#", "Lvl", "VADNode", "StartVpn", "EndVpn", "4KBs",
					"Protection", "Type", "FileName");
				printf("%-4s  %-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
					"---", "-----", "-----------------", "-------------", "-------------", "---------",
					"--------------------------", "--------------", "-----------------------------------");
				continue;
			}

			unsigned long long vpn  = node[i].StartingVpn;
			PROTECTION prot         = (PROTECTION)node[i].Protection;
			const char* fileName    = (node[i].FileOffset && node[i].FileOffset < maxNames)
									 ? fileBase[node[i].FileOffset].FileName : "-";

			// Decode type tag from PDB-derived layout maps
			char typeTag[48] = "";
			if (g_MmSectionFlags.valid)
				BuildVadTypeTag(node[i].VadFlagsRaw, node[i].ControlAreaFlags, node[i].IsVadShort,
					node[i].MappedViews, node[i].UserReferences, typeTag, sizeof(typeTag));

			// Protection string with raw value appended
			char protBuf[40];
			snprintf(protBuf, sizeof(protBuf), "%-22s [0x%x]",
				ProtectionToStr(prot), node[i].Protection);

			// indent by level with a leading symbol
			char indent[32] = { 0 };
			int d = (node[i].Level - 1) < 10 ? (node[i].Level - 1) : 10;
			for (int j = 0; j < d; j++) indent[j] = ' ';
			indent[d] = (node[i].Level == 1) ? '*' : (d % 2 == 0 ? '+' : '-');

			printf("%-4zu  %s%-*d  0x%-16p  0x%011llx  0x%011llx  %-9llu  %-26s  %-14s  %-35s\n",
				count,
				indent, (int)(6 - (int)strlen(indent)), node[i].Level,
				node[i].VADNode,
				vpn, node[i].EndingVpn,
				node[i].EndingVpn - vpn + 1,
				protBuf,
				typeTag,
				fileName);

			if (selectedVpns && count < maxVpns)
				selectedVpns[count] = vpn;
			count++;
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		printf("[!] Exception reading VAD data\n");
	}
	printf("\n[%zu nodes]\n", count);
	return count;
}

// -----------------------------------------------------------------
void ShowHelp() {
	printf("---------------------------------------------------------------\n");
	printf("[*] Press '1' to populate VAD-Tree  (T=Target / S=Source / B=Both)\n");
	printf("[*] Press '2' to display VAD-Tree (quick view)\n");
	printf("[*] Press 'T' to display VAD-Tree (indexed, for node selection)\n");
	printf("[*] Press 'N' to insert a new VAD node\n");
	printf("[*] Press 'D' to delete (remove) a VAD node\n");
	printf("[*] Press '3' to check memory at source VA\n");
	printf("[*] Press '4' to link to VAD-Tree Node\n");
	printf("[*] Press '5' to exit with cleanup\n");
	printf("[*] Press '6' to exit silently (no cleanup)\n");
	printf("[*] Press 'U' to update target VPN\n");
	printf("[*] Press 'I' to update source process\n");
	printf("[*] Press 'O' to update target process\n");
	printf("[*] Press 'E' to write memory\n");
	printf("[*] Press 'M' to set memory view size\n");
	printf("[*] Press 'X' to unlink\n");
	printf("[*] Press 'P' to scan memory for a pattern\n");
	printf("[*] Press 'A' to adjust memory protection at source VA\n");
	printf("[*] Press 'W' to write to physical memory\n");
	printf("[*] Press 'R' to read physical memory from target VPN\n");
}

int main(int argc, char* argv[]) {
	// Section to send Symbol Info to Driver
	LPTSTR ntoskrnlPath;
	TCHAR g_ntoskrnlPath[MAX_PATH] = { 0 };
	_tcscat_s(g_ntoskrnlPath, _countof(g_ntoskrnlPath), TEXT("C:\\Windows\\System32\\ntoskrnl.exe")); //ntmarta
	ntoskrnlPath = g_ntoskrnlPath;
	symbol_ctx* sym_ctxNtskrnl = LoadSymbolsFromImageFile(ntoskrnlPath);

	size_t NumSymbols = 38; // total symbols inserted by AddInitDataSection
	SymbolsArrayAllocationSize = sizeof(INIT);
	SymbolsArrayAllocationSize += NumSymbols * sizeof(SYMBOL); // TODO: Change to new Var: TotalAllocationSize

	HANDLE hMapFile = OpenFileMappingW(SECTION_MAP_WRITE, FALSE, MAPPING_NAME_TO);
	if (!hMapFile) {
		printf("[-] Failed to create file mapping: %d", GetLastError());
		return 1;
	}

	SymbolsArray = (VOID*)MapViewOfFile(hMapFile, FILE_MAP_WRITE, 0, 0, 4096 * 2);
	if (!SymbolsArray) {
		printf("[-] Failed to map view of file: %d\n", GetLastError());
		CloseHandle(hMapFile);
		return 1;
	}

	if (SymbolsArray == NULL) {
		printf("[-] Symbols Array could not be allocated\n");
		return 1;
	}
	totalAllocationSize += SymbolsArrayAllocationSize;

	const char* targetProcess = NULL;
	const char* sourceProcess = NULL;
	unsigned long long targetVPN = NULL;
	unsigned long long targetVPNOffset = NULL;
	size_t targetVPNSize = 0;
	volatile PVOID sourceVA = NULL;
	sourceVA = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (sourceVA != NULL) {
		// Force physical allocation by touching every page (here: only one page)
		//VirtualLock(sourceVA, 4096); // Lock the page in memory
		memset(sourceVA, 0x41, 4096); // Fill the page with 'A's
		printf("[*] Force physical allocation at: 0x%llx\n", (unsigned long long)sourceVA);
		// print the first 10 bytes of the allocated memory
		CheckModifiedMemory(sourceVA, 10);
	}
	printf("[*] Allocated memory at: 0x%llx\n", sourceVA);
	for (int i = 1; i < argc; i++) {
		// SET TARGET PROCESS
		if (strcmp(argv[i], "/t") == 0 && i + 1 < argc) {
			// Get the filename parameter that follows /f
			targetProcess = argv[i + 1];
			i++; // Skip the next argument since we consumed it
			printf("[*] Target process set to: %s\n", targetProcess);
		}
	}
	for (int i = 1; i < argc; i++) {
		// SET TARGET VPN
		if (strcmp(argv[i], "/i") == 0 && i + 1 < argc) {
			// Parse hexadecimal value properly
			const char* hexValue = argv[i + 1];

			// Check if it starts with "0x" and use appropriate conversion method
			if (strncmp(hexValue, "0x", 2) == 0 || strncmp(hexValue, "0X", 2) == 0) {
				// Skip "0x" prefix and convert from hex
				targetVPN = strtoull(hexValue + 2, NULL, 16);
			}
			else {
				// Try to convert directly (could be decimal or hex without prefix)
				targetVPN = strtoul(hexValue, NULL, 0);
			}

			i++; // Skip the next argument since we consumed it
			printf("[*] Target VPN set to: 0x%llx\n", targetVPN); // Print as hex for confirmation
		}
	}
	// SET SOURCE PROCESS
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "/s") == 0 && i + 1 < argc) {
			// Get the filename parameter that follows /f
			sourceProcess = argv[i + 1];
			i++; // Skip the next argument since we consumed it
			printf("[*] Source process set to: %s\n", sourceProcess);
		}
	}
	// SET TARGET MEMORY SIZE
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "/m") == 0 && i + 1 < argc) {
			// Get the filename parameter that follows /f
			targetVPNSize = atoi(argv[i + 1]);
			i++; // Skip the next argument since we consumed it
			printf("[*] Target Memory Size set to: %d\n", targetVPNSize);
		}
	}
	// SET TARGET MEMORY OFFSET
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "/o") == 0 && i + 1 < argc) {
			// Parse hexadecimal value properly
			const char* hexValue = argv[i + 1];

			// Check if it starts with "0x" and use appropriate conversion method
			if (strncmp(hexValue, "0x", 2) == 0 || strncmp(hexValue, "0X", 2) == 0) {
				// Skip "0x" prefix and convert from hex
				targetVPNOffset = strtoull(hexValue + 2, NULL, 16);
			}
			else {
				// Try to convert directly (could be decimal or hex without prefix)
				targetVPNOffset = strtoul(hexValue, NULL, 0);
			}

			i++; // Skip the next argument since we consumed it
			printf("[*] Target VPN Offset set to: 0x%llx\n", targetVPNOffset); // Print as hex for confirmation
		}
	}
	if (targetVPN != NULL) {
		targetVPN += targetVPNOffset;
	}
	// -----------------------------------------------------------------
	// Section for Info from Driver
	//HANDLE hVADMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, MAPPING_NAME_FROM);
	HANDLE hVADMapFile = OpenFileMappingW(SECTION_MAP_WRITE, FALSE, MAPPING_NAME_FROM);
	if (!hVADMapFile) {
		printf("[-] Failed to create VAD file mapping: %d\n", GetLastError());
		return 1;
	}
	printf("[*] MAPPING_NAME_FROM VAD file mapping created successfully\n");

	PVOID VADArray = (VOID*)MapViewOfFile(hVADMapFile, FILE_MAP_WRITE, 0, 0, 0);
	if (!VADArray) {
		printf("[-] Failed to map VAD file mapping: %d\n", GetLastError());
		CloseHandle(hVADMapFile);
		return 1;
	}
	// -----------------------------------------------------------------
	// Section for FileName-Info from Driver
	//HANDLE hVADMapFileName = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096 * 2, MAPPING_NAME_FROM_FILENAMES);
	HANDLE hVADMapFileName = OpenFileMappingW(SECTION_MAP_WRITE, FALSE, MAPPING_NAME_FROM_FILENAMES);
	if (!hVADMapFileName) {
		printf("[-] Failed to create VAD file mapping: %d\n", GetLastError());
		return 1;
	}
	printf("[*] MAPPING_NAME_FROM_FILENAMES VAD file mapping created successfully\n");
	PVOID VADArrayFileName = (VOID*)MapViewOfFile(hVADMapFileName, FILE_MAP_WRITE, 0, 0, 0); // should be 2 * 4096??? TODO:
	if (!VADArrayFileName) {
		printf("[-] Failed to map VAD file mapping: %d\n", GetLastError());
		CloseHandle(hVADMapFileName);
		return 1;
	}

	// TEST START
	//HANDLE hEvent = CreateEventW(
	//	NULL, FALSE, FALSE, MAPPING_NOTIFICATION_EVENT);
	HANDLE hEventUSERMODEREADY = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_USERMODEREADY_EVENT);
	if (hEventUSERMODEREADY == NULL) {
		printf("[-] Failed to create event: %d\n", GetLastError());
		return 1;
	}
	printf("[*] MAPPING_NOTIFICATION_USERMODEREADY_EVENT event opened successfully\n");
	// TEST END
	// TEST START
	HANDLE hEventLINK = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_LINK_EVENT);
	if (hEventLINK == NULL) {
		printf("[-] Failed to create event: %d\n", GetLastError());
		return 1;
	}
	printf("[*] MAPPING_NOTIFICATION_LINK_EVENT event opened successfully\n");
	// TEST END
	// TEST START
	HANDLE hEventUnlink = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_Unlink_EVENT);
	if (hEventUnlink == NULL) {
		printf("[-] Failed to create event: %d\n", GetLastError());
		return 1;
	}
	printf("[*] MAPPING_NOTIFICATION_Unlink_EVENT event opened successfully\n");
	// TEST END
	// TEST START
	HANDLE hEventINIT = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_INIT_EVENT);
	if (hEventINIT == NULL) {
		printf("[-] Failed to open event: %d\n", GetLastError());
		return 1;
	}
	printf("[*] MAPPING_NOTIFICATION_INIT_EVENT event opened successfully\n");
	// TEST END

	// TEST START - WritePhysical Event and Shared Memory
	HANDLE hEventWRITE_PHYS = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_WRITE_PHYS_EVENT);
	if (hEventWRITE_PHYS == NULL) {
		printf("[-] Failed to open WritePhysical event: %d\n", GetLastError());
		return 1;
	}
	printf("[*] MAPPING_NOTIFICATION_WRITE_PHYS_EVENT event opened successfully\n");

	// Open WritePhysical shared memory section
	HANDLE hWritePhysMapFile = OpenFileMappingW(SECTION_MAP_WRITE, FALSE, MAPPING_NAME_WRITE_PHYS);
	if (!hWritePhysMapFile) {
		printf("[-] Failed to open WritePhysical file mapping: %d\n", GetLastError());
		return 1;
	}
	printf("[*] MAPPING_NAME_WRITE_PHYS file mapping opened successfully\n");

	PVOID WritePhysArray = (VOID*)MapViewOfFile(hWritePhysMapFile, FILE_MAP_WRITE, 0, 0, 0);
	if (!WritePhysArray) {
		printf("[-] Failed to map WritePhysical file mapping: %d\n", GetLastError());
		CloseHandle(hWritePhysMapFile);
		return 1;
	}
	printf("[*] WritePhysical shared memory mapped successfully\n");
	// TEST END

	// TEST START - ReadPhysical Event and Shared Memory
	HANDLE hEventREAD_PHYS = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_READ_PHYS_EVENT);
	if (hEventREAD_PHYS == NULL) {
		printf("[-] Failed to open ReadPhysical event: %d\n", GetLastError());
		return 1;
	}
	printf("[*] MAPPING_NOTIFICATION_READ_PHYS_EVENT event opened successfully\n");

	// Open ReadPhysical shared memory section
	HANDLE hReadPhysMapFile = OpenFileMappingW(SECTION_MAP_WRITE, FALSE, MAPPING_NAME_READ_PHYS);
	if (!hReadPhysMapFile) {
		printf("[-] Failed to open ReadPhysical file mapping: %d\n", GetLastError());
		return 1;
	}
	printf("[*] MAPPING_NAME_READ_PHYS file mapping opened successfully\n");

	PVOID ReadPhysArray = (VOID*)MapViewOfFile(hReadPhysMapFile, FILE_MAP_WRITE, 0, 0, 0);
	if (!ReadPhysArray) {
		printf("[-] Failed to map ReadPhysical file mapping: %d\n", GetLastError());
		CloseHandle(hReadPhysMapFile);
		return 1;
	}
	printf("[*] ReadPhysical shared memory mapped successfully\n");
	// TEST END

	// VAD Modify section and events
	HANDLE hVadModifyMapFile = OpenFileMappingW(SECTION_MAP_WRITE, FALSE, MAPPING_NAME_VAD_MODIFY);
	if (!hVadModifyMapFile) {
		printf("[-] Failed to open VAD modify mapping: %d\n", GetLastError());
		return 1;
	}
	PVOID VadModifyArray = (VOID*)MapViewOfFile(hVadModifyMapFile, FILE_MAP_WRITE, 0, 0, 0);
	if (!VadModifyArray) {
		printf("[-] Failed to map VAD modify section: %d\n", GetLastError());
		CloseHandle(hVadModifyMapFile);
		return 1;
	}
	printf("[*] VAD modify shared memory mapped\n");

	HANDLE hEventVAD_INSERT = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_VAD_INSERT_EVENT);
	if (!hEventVAD_INSERT) {
		printf("[-] Failed to open VAD insert event: %d\n", GetLastError());
		return 1;
	}
	printf("[*] VAD insert event opened\n");

	HANDLE hEventVAD_REMOVE = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_VAD_REMOVE_EVENT);
	if (!hEventVAD_REMOVE) {
		printf("[-] Failed to open VAD remove event: %d\n", GetLastError());
		return 1;
	}
	printf("[*] VAD remove event opened\n");
	// VAD modify setup END

	printf("\n"
		"[+] ============================================================\n"
		"[+]  Shared memory regions (usermode VA)\n"
		"[+] ============================================================\n"
		"[+]  Input  (symbols/init)  : 0x%p\n"
		"[+]  VAD nodes              : 0x%p  (%u KB)\n"
		"[+]  VAD filenames          : 0x%p  (%u KB)\n"
		"[+]  WritePhys request      : 0x%p\n"
		"[+]  ReadPhys  request      : 0x%p\n"
		"[+]  VAD modify request     : 0x%p\n"
		"[+] ============================================================\n\n",
		SymbolsArray,
		VADArray,         (unsigned)(VAD_SECTION_SIZE      / 1024),
		VADArrayFileName, (unsigned)(VAD_FILENAME_SEC_SIZE / 1024),
		WritePhysArray,
		ReadPhysArray,
		VadModifyArray);

	AddInitDataSection(sym_ctxNtskrnl);
	UpdateInitData(sourceProcess, targetProcess, (unsigned long long)sourceVA, targetVPN, 0);
	if (SetEvent(hEventINIT)) {
		printf("[*] Send User-Mode Update to Kernel\n");
	}
	else {
		printf("[-] Failed to set event: %d\n", GetLastError());
	}

	ShowHelp();

	char buffer[64] = { 0 };
	int index = 1;
	int nextChar;
	char* endPtr = NULL;
	unsigned long long newTargetVPN = 0;

	char procNameBufferSource[32] = { 0 };
	char procNameBufferTarget[32] = { 0 };
	int procNameIndex = 0;
	int inputChar;

	unsigned int offset = 0;
	unsigned char value = 0;
	char inputBuffer[64] = { 0 };
	int inputIndex = 0;
	bool validInput = false;
	bool inNumber = false;
	char tempHexByte[3] = { 0 }; // To store each 2-digit hex value
	int tempIndex = 0;
	std::vector<unsigned char> bytesToWrite;
	unsigned char byteVal;
	unsigned char* memPtr;

	char sizeBuffer[32] = { 0 };
	int sizeIndex = 0;

	char pattern[256] = { 0 };
	int patternIndex;
	int patternChar;
	PVOID SecBase;
	size_t SecSize;
	PVOID FileNameSecBase;
	size_t FileNameSecSize;
	PVAD_NODE node;
	PVAD_NODE_FILE FileNameBase;
	size_t maxSymCount;
	PROTECTION prot;
	const char* protStr;
	DWORD64 rangeSize;
	unsigned long long currentVPN;
	size_t pages;
	bool continueScan = true;

	// VAD tree node index (filled by 'T' command, used by 'D')
#define VAD_MAX_NODES 512
	unsigned long long treeVpns[VAD_MAX_NODES] = { 0 };
	size_t treeCount = 0;

	int protectionChoice;
	ULONG newProtection;
	const char* protectionName;
	// More robust command loop implementation
	bool running = true;
		while (running) {
			printf("\nEnter command: ");
			fflush(stdout);  // Ensure the prompt is displayed

			// Read a single character
			int ch = _getch();  // Use _getch() for single character input without buffering
			printf("%c\n", ch); // Echo the character for user feedback

			// Process the command
			switch (ch) {
			case '1': {
				printf("[*] Walk: T=Target  S=Source  B=Both [T]: ");
				fflush(stdout);
				int wch = _getch();
				printf("%c\n", wch);
				UCHAR wmode = (wch == 's' || wch == 'S') ? 1
							: (wch == 'b' || wch == 'B') ? 2 : 0;
				((PINIT)SymbolsArray)->walkMode = wmode;

				RtlZeroMemory(VADArray, VAD_SECTION_SIZE);
				RtlZeroMemory(VADArrayFileName, VAD_FILENAME_SEC_SIZE);

				BOOL canWalk = (wmode == 1)
					? (sourceProcess != NULL && sourceProcess[0] != '\0')
					: (targetProcess != NULL && targetProcess[0] != '\0');
				if (canWalk) {
					if (SetEvent(hEventUSERMODEREADY))
						printf("[*] Notified driver to populate VAD-Tree (mode=%s)\n",
							wmode == 0 ? "target" : wmode == 1 ? "source" : "both");
					else
						printf("[-] Failed to notify driver: %d\n", GetLastError());
				} else {
					printf("[-] Required process not configured — use 'I' (source) or 'O' (target)\n");
				}
				break;
			}
			case '2':
				printf("[*] VAD offsets:\n");
				GetSymOffsets(VADArray, VAD_SECTION_SIZE, VADArrayFileName, VAD_FILENAME_SEC_SIZE);
				break;
			case '3':
				printf("[*] Memory at source VA:\n");
				if (targetVPNSize == 0) {
					targetVPNSize = 4096; // Default size if not set
				}
				CheckModifiedMemory(sourceVA, targetVPNSize);
				break;
			case '4':
				//if (targetVPN != NULL && sourceProcess != NULL) {
				if (SetEvent(hEventLINK)) { // TODO: Should all be CLI controlled? Like this we will Link
					printf("[*] Notified driver to link to VAD-Tree Node\n");
				}
				else {
					printf("[-] Failed to notified driver to link to VAD-Tree Node: %d\n", GetLastError());
				}
				//}
				break;
			case '5':
				printf("[*] Exiting program with cleanup...\n");
				running = false;
				break;
			case '6':
				// silen exit
				printf("[*] Exiting program silently...\n");
				return 0;
			case 'u':
			case 'U':
				// SCAN FOR TARGET VPN UPDATE

				// Read additional characters for a multi-character hex number
				index = 0;
				printf("Continue entering hex value (press Enter when done): ");

				// Continue reading until Enter is pressed
				nextChar;
				while ((nextChar = _getch()) != '\r' && nextChar != '\n') {
					// Only accept valid hex characters (0-9, a-f, A-F) and control characters
					if ((nextChar >= '0' && nextChar <= '9') ||
						(nextChar >= 'a' && nextChar <= 'f') ||
						(nextChar >= 'A' && nextChar <= 'F') ||
						nextChar == 'x' || nextChar == 'X' ||
						nextChar == '\b') {

						if (nextChar == '\b') {
							// Handle backspace - remove last character
							if (index > 0) {
								buffer[--index] = '\0';
								printf("\b \b"); // Erase last character from display
							}
						}
						else if (index < sizeof(buffer) - 1) {
							// Add character to buffer and echo it
							buffer[index++] = (char)nextChar;
							printf("%c", nextChar);
						}
					}
				}

				printf("\n");
				buffer[index] = '\0';

				// Try to convert the buffer to a number
				endPtr = NULL;
				newTargetVPN = 0;

				// Handle both "0x" prefix and no prefix
				if (strncmp(buffer, "0x", 2) == 0 || strncmp(buffer, "0X", 2) == 0) {
					newTargetVPN = strtoull(buffer + 2, &endPtr, 16);
				}
				else {
					newTargetVPN = strtoull(buffer, &endPtr, 16);
				}

				// Validate the conversion
				if (endPtr != buffer && *endPtr == '\0') {
					// Conversion succeeded
					targetVPN = newTargetVPN;
					printf("[*] Target VPN updated to: 0x%llx\n", targetVPN);

					// Update the kernel with the new targetVPN
					UpdateInitData(sourceProcess, targetProcess, (unsigned long long)sourceVA, targetVPN, 0);
					if (SetEvent(hEventINIT)) {
						printf("[*] Sent updated targetVPN to kernel\n");
					}
					else {
						printf("[-] Failed to notify kernel of targetVPN update: %d\n", GetLastError());
					}
				}
				break;
			case 'i':
			case 'I':
				// copy the input to sourceProcess max 15 chars
				// Buffer to hold the input (extra space for overflow protection)
				RtlZeroMemory(procNameBufferSource, sizeof(procNameBufferSource));
				procNameIndex = 0;

				printf("Enter source process name (max 15 chars): ");
				fflush(stdout);

				// Read characters until Enter is pressed
				inputChar;
				while ((inputChar = _getch()) != '\r' && inputChar != '\n') {
					// Handle backspace
					if (inputChar == '\b') {
						if (procNameIndex > 0) {
							procNameIndex--;
							procNameBufferSource[procNameIndex] = '\0';
							printf("\b \b"); // Erase character from display
						}
					}
					// Only accept printable characters and limit to 14 chars (leaving space for null terminator)
					else if (inputChar >= 32 && inputChar <= 126 && procNameIndex < 15) {
						procNameBufferSource[procNameIndex++] = (char)inputChar;
						printf("%c", inputChar); // Echo the character
					}
				}

				// Null-terminate the string
				procNameBufferSource[procNameIndex] = '\0';
				printf("\n");

				// Only proceed if they entered something
				if (procNameIndex > 0) {
					printf("[*] Source process updated to: %s\n", procNameBufferSource);

					// Update kernel with the new sourceProcess
					sourceProcess = procNameBufferSource;
					UpdateInitData(sourceProcess, targetProcess, (unsigned long long)sourceVA, targetVPN, 0);
					if (SetEvent(hEventINIT)) {
						printf("[*] Sent updated sourceProcess to kernel\n");
					}
					else {
						printf("[-] Failed to notify kernel of sourceProcess update: %d\n", GetLastError());
					}
				}
				else {
					printf("[*] No input provided, sourceProcess not changed\n");
				}
				break;

			case 'o':
			case 'O':
				// copy the input to targetProcess max 15 chars
				// Buffer to hold the input (extra space for overflow protection)
				RtlZeroMemory(procNameBufferTarget, sizeof(procNameBufferTarget));
				procNameIndex = 0;

				printf("Enter target process name (max 15 chars): ");
				fflush(stdout);

				// Read characters until Enter is pressed
				inputChar;
				while ((inputChar = _getch()) != '\r' && inputChar != '\n') {
					// Handle backspace
					if (inputChar == '\b') {
						if (procNameIndex > 0) {
							procNameIndex--;
							procNameBufferTarget[procNameIndex] = '\0';
							printf("\b \b"); // Erase character from display
						}
					}
					// Only accept printable characters and limit to 14 chars (leaving space for null terminator)
					else if (inputChar >= 32 && inputChar <= 126 && procNameIndex < 15) {
						procNameBufferTarget[procNameIndex++] = (char)inputChar;
						printf("%c", inputChar); // Echo the character
					}
				}

				// Null-terminate the string
				procNameBufferTarget[procNameIndex] = '\0';
				printf("\n");

				// Only proceed if they entered something
				if (procNameIndex > 0) {
					printf("[*] Target process updated to: %s\n", procNameBufferTarget);

					// Update kernel with the new targetProcess
					targetProcess = procNameBufferTarget;
					UpdateInitData(sourceProcess, targetProcess, (unsigned long long)sourceVA, targetVPN, 0);
					if (SetEvent(hEventINIT)) {
						printf("[*] Sent updated targetProcess to kernel\n");
					}
					else {
						printf("[-] Failed to notify kernel of targetProcess update: %d\n", GetLastError());
					}
				}
				else {
					printf("[*] No input provided, targetProcess not changed\n");
				}
				break;
			case 'x':
			case 'X':
				printf("Unlink memory at source VA:\n");
				if (SetEvent(hEventUnlink)) {
					printf("[*] Event set successfully\n");
				}
				else {
					printf("[-] Failed to set event: %d\n", GetLastError());
				}
				break;
			case 'e':
			case 'E':
				// Edit the memory at sourceVA. First the user specifies the offset, then the value
				// Edit the memory at sourceVA with variable number of bytes
				// Get offset
				printf("Enter memory offset (hex, max 0xFFF): 0x");
				fflush(stdout);

				memset(inputBuffer, 0, sizeof(inputBuffer));
				inputIndex = 0;
				validInput = false;

				// Read offset input
				while ((inputChar = _getch()) != '\r' && inputChar != '\n') {
					// Handle backspace
					if (inputChar == '\b') {
						if (inputIndex > 0) {
							inputIndex--;
							inputBuffer[inputIndex] = '\0';
							printf("\b \b"); // Erase character from display
						}
					}
					// Only accept hex characters (0-9, a-f, A-F)
					else if (((inputChar >= '0' && inputChar <= '9') ||
						(inputChar >= 'a' && inputChar <= 'f') ||
						(inputChar >= 'A' && inputChar <= 'F')) &&
						inputIndex < sizeof(inputBuffer) - 1) {

						inputBuffer[inputIndex++] = (char)inputChar;
						printf("%c", inputChar); // Echo the character
					}
				}

				inputBuffer[inputIndex] = '\0';
				printf("\n");

				// Convert offset from hex string to integer
				if (inputIndex > 0) {
					offset = (unsigned int)strtoul(inputBuffer, NULL, 16);

					// Ensure offset is within the allocated memory (4096 bytes)
					if (offset < 4096) {
						validInput = true;
					}
					else {
						printf("[-] Offset 0x%X is outside the allocated memory range (0x000 - 0xFFF)\n", offset);
					}
				}

				// If we have a valid offset, get the byte values to write
				if (validInput) {
					// Clear prev values in bytesToWrite
					bytesToWrite.clear();

					printf("Enter byte values to write starting at offset 0x%X (hex, space-separated, e.g. 'FF 01 C3'): ", offset);
					fflush(stdout);

					// Clear buffer for new input
					memset(inputBuffer, 0, sizeof(inputBuffer));
					inputIndex = 0;
					inNumber = false;
					tempIndex = 0;
					memset(tempHexByte, 0, sizeof(tempHexByte));
					byteVal = NULL;
					memPtr = NULL;

					// Read the space-separated byte values
					while ((inputChar = _getch()) != '\r' && inputChar != '\n') {
						// Handle backspace
						if (inputChar == '\b') {
							if (inputIndex > 0) {
								inputIndex--;
								inputBuffer[inputIndex] = '\0';
								printf("\b \b"); // Erase character from display

								// Update the temp hex byte and state
								if (inNumber) {
									if (tempIndex > 0) {
										tempIndex--;
										tempHexByte[tempIndex] = '\0';
									}
									if (tempIndex == 0) {
										inNumber = false;
									}
								}
							}
						}
						else if (inputChar == ' ') {
							inNumber = false;
							if (tempIndex > 0) {
								// Convert and add the current byte
								byteVal = (unsigned char)strtoul(tempHexByte, NULL, 16);
								bytesToWrite.push_back(byteVal);

								// Reset for next byte
								memset(tempHexByte, 0, sizeof(tempHexByte));
								tempIndex = 0;
							}
						}
						else if (((inputChar >= '0' && inputChar <= '9') ||
							(inputChar >= 'a' && inputChar <= 'f') ||
							(inputChar >= 'A' && inputChar <= 'F')) &&
							inputIndex < sizeof(inputBuffer) - 1) {

							// Add to the display buffer
							inputBuffer[inputIndex++] = (char)inputChar;
							printf("%c", inputChar);

							// Add to current byte value (max 2 hex digits)
							if (tempIndex < 2) {
								tempHexByte[tempIndex++] = (char)inputChar;
								inNumber = true;
							}
							// If we already have 2 digits, complete this byte and start a new one
							else {
								byteVal = (unsigned char)strtoul(tempHexByte, NULL, 16);
								bytesToWrite.push_back(byteVal);

								// Reset for next byte and add the current character
								memset(tempHexByte, 0, sizeof(tempHexByte));
								tempHexByte[0] = (char)inputChar;
								tempIndex = 1;
							}
						}
					}

					// Process any remaining bytes
					if (inNumber && tempIndex > 0) {
						byteVal = (unsigned char)strtoul(tempHexByte, NULL, 16);
						bytesToWrite.push_back(byteVal);
					}

					printf("\n");

					// Write the bytes to memory
					if (!bytesToWrite.empty()) {
						// Get pointer to the specified memory location
						memPtr = (unsigned char*)sourceVA + offset;
						size_t bytesCount = bytesToWrite.size();

						// Ensure we don't write beyond allocated memory
						if (offset + bytesCount > 4096) {
							printf("[-] Warning: Attempting to write beyond buffer boundary!\n");
							bytesCount = 4096 - offset; // Limit to available bytes
						}

						// Display original values
						printf("Original values at offset 0x%X:", offset);
						for (size_t i = 0; i < bytesCount; i++) {
							printf(" %02X", memPtr[i]);
						}
						printf("\n");

						// Write the new values
						for (size_t i = 0; i < bytesCount; i++) {
							memPtr[i] = bytesToWrite[i];
						}

						// Display the new values
						printf("New values written at offset 0x%X:", offset);
						for (size_t i = 0; i < bytesCount; i++) {
							printf(" %02X", memPtr[i]);
						}
						printf("\n");
						printf("[+] Successfully wrote %zu bytes\n", bytesCount);
					}
					else {
						printf("[-] No valid byte values entered\n");
					}
				}
				break;
			case 'm':
			case 'M':
				// Set memory view size by assigning the input to targetVPNSize
				// Buffer to hold the input
				sizeIndex = 0;

				printf("Enter memory view size (decimal or hex with 0x prefix): ");
				fflush(stdout);

				// Read characters until Enter is pressed
				inputChar = 0;
				while ((inputChar = _getch()) != '\r' && inputChar != '\n') {
					// Handle backspace
					if (inputChar == '\b') {
						if (sizeIndex > 0) {
							sizeIndex--;
							sizeBuffer[sizeIndex] = '\0';
							printf("\b \b"); // Erase character from display
						}
					}
					// Accept decimal digits and hex characters (for 0x prefix)
					else if ((inputChar >= '0' && inputChar <= '9') ||
						(inputChar >= 'a' && inputChar <= 'f') ||
						(inputChar >= 'A' && inputChar <= 'F') ||
						inputChar == 'x' || inputChar == 'X') {

						if (sizeIndex < sizeof(sizeBuffer) - 1) {
							sizeBuffer[sizeIndex++] = (char)inputChar;
							printf("%c", inputChar); // Echo the character
						}
					}
				}

				// Null-terminate the string
				sizeBuffer[sizeIndex] = '\0';
				printf("\n");

				// Convert the string to a number
				if (sizeIndex > 0) {
					// Handle both decimal and hex inputs
					if (strncmp(sizeBuffer, "0x", 2) == 0 || strncmp(sizeBuffer, "0X", 2) == 0) {
						// Hex input
						targetVPNSize = (size_t)strtoull(sizeBuffer + 2, NULL, 16);
					}
					else {
						// Decimal input
						targetVPNSize = (size_t)strtoull(sizeBuffer, NULL, 10);
					}

					printf("[*] Memory view size set to: %zu bytes\n", targetVPNSize);
				}
				else {
					printf("[*] No input provided, memory view size not changed\n");
				}
				break;

			case '\n':
			case '\r':  // Handle Enter presses
				break;
			// Add this case to your command processing switch statement:
			case 'p':
			case 'P':
				// Get the pattern from the user
				printf("Enter hex pattern to search for (e.g. '90 90 ? ? FF' or '4142??44'): ");

				patternIndex = 0;

				// Read the pattern directly with _getch for consistency with rest of UI
				patternChar = 0;
				while ((patternChar = _getch()) != '\r' && patternChar != '\n' && patternIndex < 255) {
					// Handle backspace
					if (patternChar == '\b') {
						if (patternIndex > 0) {
							patternIndex--;
							pattern[patternIndex] = '\0';
							printf("\b \b"); // Erase character from display
						}
					}
					// Only accept valid hex chars, wildcards, and spaces
					else if (isxdigit(patternChar) || patternChar == '?' || patternChar == ' ') {
						pattern[patternIndex++] = (char)patternChar;
						printf("%c", patternChar); // Echo the character
					}
				}

				printf("\n");
				pattern[patternIndex] = '\0'; // Ensure null termination

				// Verify we have a pattern
				if (strlen(pattern) == 0) {
					printf("[-] No pattern provided\n");
					break;
				}

				// Make sure we have VAD data
				//if (!VADArray || !VADArrayFileName) {
					if (!sourceVA) {
					printf("[-] VAD data not available. Run option 1 first to populate VAD tree\n");
					break;
				}


				SecBase = VADArray;
				SecSize = VAD_SECTION_SIZE;
				FileNameSecBase = VADArrayFileName;
				FileNameSecSize = VAD_FILENAME_SEC_SIZE;
				if (SecBase == NULL)
					break;

				node = (PVAD_NODE)SecBase;
				FileNameBase = (PVAD_NODE_FILE)FileNameSecBase;

				// Calculate maximum symbols based on remaining size
				maxSymCount = SecSize / sizeof(VAD_NODE);

				//__try {
					for (size_t i = 0; i < maxSymCount - 1; i++) {
						if (!continueScan)
							break;
						if (node[i].Level == 0)
							continue; // Skip if Level is 0

						prot = (PROTECTION)node[i].Protection;
						protStr = ProtectionToStr(prot);
						rangeSize = node[i].EndingVpn - node[i].StartingVpn + 1;

						currentVPN = node[i].StartingVpn;
						pages = node[i].EndingVpn - node[i].StartingVpn + 1;

						for (size_t currPage = 0; currPage < pages; currPage++) { // TODO: < or <= ?
							if (!continueScan)
								break;
							// Update the kernel with the new targetVPN
							targetVPN = currentVPN;
							UpdateInitData(sourceProcess, targetProcess, (unsigned long long)sourceVA, targetVPN, 0);

							if (SetEvent(hEventLINK)) { // TODO: Should all be CLI controlled? Like this we will Link
								printf("[*] Notified driver to link to VAD-Tree Node\n");
							}
							else {
								printf("[-] Failed to notified driver to link to VAD-Tree Node: %d\n", GetLastError());
							}
							// Perform the scan
							if (ScanAndPrintMemory(sourceVA, pattern))
								continueScan = false;
							currentVPN += 0x1000; // Increment by 4KB
						}
					}
					continueScan = true; // Reset for next scan
				//}
				//__except (EXCEPTION_EXECUTE_HANDLER) {
				//	printf("Exception when reading memory: 0x%lx\n", GetExceptionCode());
				//}
				break;
			case 'a':
			case 'A':
				printf("[*] Select memory protection for sourceVA:\n");
				printf("  1. PAGE_READONLY         (0x01)\n");
				printf("  2. PAGE_EXECUTE          (0x02)\n");
				printf("  3. PAGE_EXECUTE_READ     (0x03)\n");
				printf("  4. PAGE_READWRITE        (0x04)\n");
				printf("  5. PAGE_NOACCESS         (0x00)\n");
				printf("  6. PAGE_EXECUTE_READWRITE(0x06)\n");

				// Get user selection
				protectionChoice = _getch() - '0';
				printf("%d\n", protectionChoice);

				// Map selection to Windows protection constants
				newProtection = 0;
				protectionName = "";
				switch (protectionChoice) {
				case 1:
					newProtection = PAGE_READONLY;
					protectionName = "PAGE_READONLY";
					break;
				case 2:
					newProtection = PAGE_EXECUTE;
					protectionName = "PAGE_EXECUTE";
					break;
				case 3:
					newProtection = PAGE_EXECUTE_READ;
					protectionName = "PAGE_EXECUTE_READ";
					break;
				case 4:
					newProtection = PAGE_READWRITE;
					protectionName = "PAGE_READWRITE";
					break;
				case 5:
					newProtection = PAGE_NOACCESS;
					protectionName = "PAGE_NOACCESS";
					break;
				case 6:
					newProtection = PAGE_EXECUTE_READWRITE;
					protectionName = "PAGE_EXECUTE_READWRITE";
					break;
				default:
					printf("[-] Invalid selection\n");
					break;
				}

				// Apply the selected protection if valid
				if (newProtection != 0x0) {
					UpdateInitData(sourceProcess, targetProcess, (unsigned long long)sourceVA, targetVPN, newProtection);
					if (SetEvent(hEventINIT)) {
						printf("[*] Send User-Mode Update to Kernel\n");
					}
					else {
						printf("[-] Failed to set event: %d\n", GetLastError());
					}
				}
				break;
			case 'w':
			case 'W': {
				// Write to physical memory functionality
				printf("[*] Write to Physical Memory (via Virtual Address Translation)\n");
				printf("This function allows you to write data to a virtual address in the target process.\n");
				printf("The kernel will translate the virtual address to physical and perform the write.\n");
				printf("WARNING: This is a dangerous operation that can crash the system!\n\n");

				// Check if we have a valid target process
				if (targetProcess == NULL || strlen(targetProcess) == 0) {
					printf("[-] No target process set. Please use 'O' command to set a target process first.\n");
					break;
				}

				printf("[+] Using current target process: %s\n", targetProcess);

				// Get the target virtual address
				printf("Enter target virtual address (hex, e.g., 0x12345000): 0x");
				fflush(stdout);

				memset(inputBuffer, 0, sizeof(inputBuffer));
				inputIndex = 0;

				// Read virtual address input
				while ((inputChar = _getch()) != '\r' && inputChar != '\n') {
					// Handle backspace
					if (inputChar == '\b') {
						if (inputIndex > 0) {
							inputIndex--;
							inputBuffer[inputIndex] = '\0';
							printf("\b \b"); // Erase character from display
						}
					}
					// Only accept hex characters (0-9, a-f, A-F)
					else if (((inputChar >= '0' && inputChar <= '9') ||
						(inputChar >= 'a' && inputChar <= 'f') ||
						(inputChar >= 'A' && inputChar <= 'F')) &&
						inputIndex < sizeof(inputBuffer) - 1) {

						inputBuffer[inputIndex++] = (char)inputChar;
						printf("%c", inputChar); // Echo the character
					}
				}

				inputBuffer[inputIndex] = '\0';
				printf("\n");

				// Convert virtual address from hex string to pointer
				PVOID virtualAddr = NULL;
				if (inputIndex > 0) {
					virtualAddr = (PVOID)strtoull(inputBuffer, NULL, 16);
				} else {
					printf("[-] No virtual address provided\n");
					break;
				}

				printf("[+] Target virtual address: 0x%p\n", virtualAddr);

				// Get offset within the page
				printf("Enter offset within page (hex, 0x000-0xFFF): 0x");
				fflush(stdout);

				memset(inputBuffer, 0, sizeof(inputBuffer));
				inputIndex = 0;

				// Read offset input
				while ((inputChar = _getch()) != '\r' && inputChar != '\n') {
					// Handle backspace
					if (inputChar == '\b') {
						if (inputIndex > 0) {
							inputIndex--;
							inputBuffer[inputIndex] = '\0';
							printf("\b \b"); // Erase character from display
						}
					}
					// Only accept hex characters (0-9, a-f, A-F)
					else if (((inputChar >= '0' && inputChar <= '9') ||
						(inputChar >= 'a' && inputChar <= 'f') ||
						(inputChar >= 'A' && inputChar <= 'F')) &&
						inputIndex < sizeof(inputBuffer) - 1) {

						inputBuffer[inputIndex++] = (char)inputChar;
						printf("%c", inputChar); // Echo the character
					}
				}

				inputBuffer[inputIndex] = '\0';
				printf("\n");

				// Convert offset from hex string to integer
				ULONG pageOffset = 0;
				if (inputIndex > 0) {
					pageOffset = (ULONG)strtoul(inputBuffer, NULL, 16);
				}

				// Validate offset is within page boundary
				if (pageOffset >= 4096) {
					printf("[-] Offset 0x%X is outside page boundary (0x000-0xFFF)\n", pageOffset);
					break;
				}

				// Get the data to write
				bytesToWrite.clear();
				printf("Enter byte values to write (hex, space-separated, e.g., 'FF 01 C3'): ");
				fflush(stdout);

				// Clear buffer for new input
				memset(inputBuffer, 0, sizeof(inputBuffer));
				inputIndex = 0;
				inNumber = false;
				tempIndex = 0;
				memset(tempHexByte, 0, sizeof(tempHexByte));

				// Read the space-separated byte values
				while ((inputChar = _getch()) != '\r' && inputChar != '\n') {
					// Handle backspace
					if (inputChar == '\b') {
						if (inputIndex > 0) {
							inputIndex--;
							inputBuffer[inputIndex] = '\0';
							printf("\b \b"); // Erase character from display

							// Update the temp hex byte and state
							if (inNumber) {
								if (tempIndex > 0) {
									tempIndex--;
									tempHexByte[tempIndex] = '\0';
								}
								if (tempIndex == 0) {
									inNumber = false;
								}
							}
						}
					}
					// Accept space to separate values
					else if (inputChar == ' ') {
						if (inNumber && tempIndex > 0) {
							// Convert and add the current byte
							byteVal = (unsigned char)strtoul(tempHexByte, NULL, 16);
							bytesToWrite.push_back(byteVal);

							// Reset for next byte
							memset(tempHexByte, 0, sizeof(tempHexByte));
							tempIndex = 0;
							inNumber = false;
						}

						// Only add space to display if we're not at the beginning
						if (inputIndex > 0 && inputBuffer[inputIndex - 1] != ' ') {
							inputBuffer[inputIndex++] = ' ';
							printf(" ");
						}
					}
					// Accept hex characters for byte values
					else if (((inputChar >= '0' && inputChar <= '9') ||
						(inputChar >= 'a' && inputChar <= 'f') ||
						(inputChar >= 'A' && inputChar <= 'F')) &&
						inputIndex < sizeof(inputBuffer) - 1) {

						// Add to the display buffer
						inputBuffer[inputIndex++] = (char)inputChar;
						printf("%c", inputChar);

						// Add to current byte value (max 2 hex digits)
						if (tempIndex < 2) {
							tempHexByte[tempIndex++] = (char)inputChar;
							inNumber = true;
						}
						// If we already have 2 digits, complete this byte and start a new one
						else {
							byteVal = (unsigned char)strtoul(tempHexByte, NULL, 16);
							bytesToWrite.push_back(byteVal);

							// Reset for next byte and add the current character
							memset(tempHexByte, 0, sizeof(tempHexByte));
							tempHexByte[0] = (char)inputChar;
							tempIndex = 1;
						}
					}
				}

				// Process any remaining bytes
				if (inNumber && tempIndex > 0) {
					byteVal = (unsigned char)strtoul(tempHexByte, NULL, 16);
					bytesToWrite.push_back(byteVal);
				}

				printf("\n");

				// Validate and send the write request
				if (!bytesToWrite.empty()) {
					size_t dataSize = bytesToWrite.size();

					// Check if write would exceed page boundary
					if (pageOffset + dataSize > 4096) {
						printf("[-] Warning: Write would exceed page boundary!\n");
						dataSize = 4096 - pageOffset; // Limit to available bytes
						printf("[!] Truncating write size to %zu bytes\n", dataSize);
					}

					// Check if write exceeds buffer size
					if (dataSize > MAX_WRITE_BUFFER_SIZE) {
						printf("[-] Warning: Data size exceeds buffer limit!\n");
						dataSize = MAX_WRITE_BUFFER_SIZE;
						printf("[!] Truncating write size to %zu bytes\n", dataSize);
					}

					// Prepare the write request
					PWRITE_PHYS_REQUEST writeRequest = (PWRITE_PHYS_REQUEST)WritePhysArray;

					// Clear the structure
					memset(writeRequest, 0, sizeof(WRITE_PHYS_REQUEST));

					// Fill the request structure
					memcpy(writeRequest->identifier, "WPHY", 4);
					writeRequest->targetVirtualAddress = (unsigned long long)virtualAddr * 0x1000;
					writeRequest->offsetInPage = pageOffset;
					writeRequest->dataSize = (ULONG)dataSize;

					// Copy the data
					for (size_t i = 0; i < dataSize; i++) {
						writeRequest->data[i] = bytesToWrite[i];
					}

					writeRequest->isValid = TRUE;

					// Display the write operation summary
					printf("\n[+] Write Request Summary:\n");
					printf("    Target Process: %s\n", targetProcess);
					printf("    Virtual Address: 0x%p\n", writeRequest->targetVirtualAddress);
					printf("    Page Offset: 0x%X\n", writeRequest->offsetInPage);
					printf("    Data Size: %lu bytes\n", writeRequest->dataSize);
					printf("    Final Target Address: 0x%p\n", (PBYTE)writeRequest->targetVirtualAddress + writeRequest->offsetInPage);
					printf("    Data: ");
					for (ULONG i = 0; i < writeRequest->dataSize; i++) {
						printf("%02X ", writeRequest->data[i]);
					}
					printf("\n");
					printf("    Note: Kernel will translate VA->PA automatically\n");

					// Send the event to trigger the write
					if (SetEvent(hEventWRITE_PHYS)) {
						printf("[+] Write request sent to kernel driver\n");
						printf("[*] Check kernel debug output for write status\n");
					} else {
						printf("[-] Failed to signal write event: %d\n", GetLastError());
					}
				} else {
					printf("[-] No valid byte values entered\n");
				}
				break;
			}
			case 'r':
			case 'R': {
				// Read physical memory from target VPN functionality
				printf("[*] Read Physical Memory from Target VPN\n");
				printf("This function reads the physical memory page that the current target VPN maps to.\n");
				printf("It will display the full 4KB page content.\n\n");

				// Check if we have a valid target VPN
				if (targetVPN == 0) {
					printf("[-] No target VPN set. Please use 'U' command to set a target VPN first.\n");
					break;
				}

				// Check if we have a valid target process
				if (targetProcess == NULL || strlen(targetProcess) == 0) {
					printf("[-] No target process set. Please use 'O' command to set a target process first.\n");
					break;
				}

				printf("[+] Using current target VPN: 0x%llx\n", targetVPN);
				printf("[+] Using current target process: %s\n", targetProcess);

				// Calculate the virtual address from VPN
				PVOID targetVA = (PVOID)(targetVPN * 0x1000);

				// Prepare the read request
				PREAD_PHYS_REQUEST readRequest = (PREAD_PHYS_REQUEST)ReadPhysArray;

				// Clear the structure
				memset(readRequest, 0, sizeof(READ_PHYS_REQUEST));

				// Fill the request structure
				memcpy(readRequest->identifier, "RPHY", 4);
				readRequest->targetVirtualAddress = targetVA;
				readRequest->isValid = TRUE;

				printf("[+] Read Request Summary:\n");
				printf("    Target Virtual Address: 0x%p\n", readRequest->targetVirtualAddress);
				printf("    Target VPN: 0x%llx\n", targetVPN);
				printf("    Target Process: %s\n", targetProcess);

				// Send the event to trigger the read
				if (SetEvent(hEventREAD_PHYS)) {
					printf("[+] Read request sent to kernel driver\n");
					printf("[*] Waiting for kernel to process the request...\n");
					
					// Wait a moment for the driver to process the request
					Sleep(1000);

					// Check if the request was processed (identifier should be cleared)
					if (readRequest->identifier[0] == 0) {
						printf("[+] Read operation completed successfully!\n");
						printf("[+] Displaying 4KB physical page content:\n\n");

						// Display the full 4KB page content in hex dump format
						const unsigned char* pageData = readRequest->pageData;
						
						for (size_t i = 0; i < MAX_READ_BUFFER_SIZE; i += 16) {
							printf("%04zX  ", i);   // Print offset

							// Print hex bytes
							for (size_t j = 0; j < 16 && i + j < MAX_READ_BUFFER_SIZE; j++) {
								printf("%02X ", pageData[i + j]);
							}

							// Padding for alignment if less than 16 bytes
							for (size_t j = 16; j > (MAX_READ_BUFFER_SIZE - i) && (MAX_READ_BUFFER_SIZE - i) < 16; j--) {
								printf("   ");
							}

							printf(" | ");  // Separator

							// Print ASCII representation
							for (size_t j = 0; j < 16 && i + j < MAX_READ_BUFFER_SIZE; j++) {
								unsigned char c = pageData[i + j];
								printf("%c", (c >= 32 && c <= 126) ? c : '.');  // Printable ASCII or dot
							}

							printf(" |\n");
						}

						printf("\n[+] Read operation completed. Displayed %d bytes.\n", MAX_READ_BUFFER_SIZE);
					} else {
						printf("[-] Read operation may have failed or is still processing.\n");
						printf("[-] Check kernel debug output for details.\n");
					}
				} else {
					printf("[-] Failed to signal read event: %d\n", GetLastError());
				}
				break;
			}
			// -------------------------------------------------------
			// 'T' — indexed tree view (enables node selection for 'D')
			// -------------------------------------------------------
			case 't':
			case 'T':
				treeCount = ShowTree(VADArray, VAD_SECTION_SIZE, VADArrayFileName, VAD_FILENAME_SEC_SIZE,
					treeVpns, VAD_MAX_NODES);
				if (treeCount == 0)
					printf("[!] Tree is empty — run '1' first to populate\n");
				break;

			// -------------------------------------------------------
			// 'D' — delete (remove) a VAD node from the target process
			// -------------------------------------------------------
			case 'd':
			case 'D': {
				unsigned long long removeVpn = 0;
				int freeChoice = 'N';

				// If tree index exists let the user pick by number, else enter VPN directly
				if (treeCount > 0) {
					printf("Select node by index (0-%zu) or press Enter to type a VPN: ", treeCount - 1);
					fflush(stdout);
					memset(inputBuffer, 0, sizeof(inputBuffer));
					inputIndex = 0;
					while ((inputChar = _getch()) != '\r' && inputChar != '\n') {
						if (inputChar == '\b' && inputIndex > 0) {
							inputBuffer[--inputIndex] = 0;
							printf("\b \b");
						} else if (inputChar >= '0' && inputChar <= '9' && inputIndex < (int)sizeof(inputBuffer) - 1) {
							inputBuffer[inputIndex++] = (char)inputChar;
							printf("%c", inputChar);
						}
					}
					printf("\n");
					inputBuffer[inputIndex] = 0;
					if (inputIndex > 0) {
						size_t idx = (size_t)strtoull(inputBuffer, NULL, 10);
						if (idx < treeCount) {
							removeVpn = treeVpns[idx];
							printf("[*] Selected node #%zu: StartingVpn 0x%llx\n", idx, removeVpn);
						} else {
							printf("[-] Index out of range\n");
							break;
						}
					}
				}

				if (removeVpn == 0) {
					printf("Enter StartingVpn to remove (hex): 0x");
					fflush(stdout);
					memset(inputBuffer, 0, sizeof(inputBuffer));
					inputIndex = 0;
					while ((inputChar = _getch()) != '\r' && inputChar != '\n') {
						if (inputChar == '\b' && inputIndex > 0) {
							inputBuffer[--inputIndex] = 0;
							printf("\b \b");
						} else if (isxdigit(inputChar) && inputIndex < (int)sizeof(inputBuffer) - 1) {
							inputBuffer[inputIndex++] = (char)inputChar;
							printf("%c", inputChar);
						}
					}
					printf("\n");
					inputBuffer[inputIndex] = 0;
					if (inputIndex == 0) { printf("[-] No VPN entered\n"); break; }
					removeVpn = strtoull(inputBuffer, NULL, 16);
				}

				printf("Free pool allocation after unlink? (Y/N): ");
				fflush(stdout);
				freeChoice = _getch();
				printf("%c\n", freeChoice);

				{
					PVAD_MODIFY_REQUEST vadReq = (PVAD_MODIFY_REQUEST)VadModifyArray;
					memset(vadReq, 0, sizeof(VAD_MODIFY_REQUEST));
					memcpy(vadReq->identifier, "VREM", 4);
					vadReq->StartingVpn  = removeVpn;
					vadReq->FreeOnRemove = (freeChoice == 'Y' || freeChoice == 'y') ? TRUE : FALSE;
					vadReq->isValid      = TRUE;

					if (SetEvent(hEventVAD_REMOVE)) {
						printf("[*] Sent VAD remove request for VPN 0x%llx\n", removeVpn);
						Sleep(300);
						printf("[*] Kernel result: 0x%08lx\n", vadReq->Result);
					} else {
						printf("[-] Failed to signal VAD remove event: %d\n", GetLastError());
					}
				}
				break;
			}

			// -------------------------------------------------------
			// 'N' — insert a new (ghost) VAD node into the target process
			// -------------------------------------------------------
			case 'n':
			case 'N': {
				unsigned long long newStart = 0, newEnd = 0;
				ULONG newProt = 0x04;
				ULONG vadType = 0;

				// ── Step 1: QHNT — query next free VPN in both address spaces ─
				{
					UCHAR curWalkMode = ((PINIT)SymbolsArray)->walkMode;
					const char* activeProc = (curWalkMode == 1)
						? (sourceProcess ? sourceProcess : "(source not set)")
						: (targetProcess ? targetProcess : "(target not set)");

					PVAD_MODIFY_REQUEST qReq = (PVAD_MODIFY_REQUEST)VadModifyArray;
					memset(qReq, 0, sizeof(VAD_MODIFY_REQUEST));
					memcpy(qReq->identifier, "QHNT", 4);
					qReq->isValid = TRUE;

					if (SetEvent(hEventVAD_INSERT)) {
						Sleep(300);
						if (!qReq->isValid) {
							printf("[+] Active process (%s): '%s'\n",
								curWalkMode == 1 ? "source" : "target", activeProc);

							if (qReq->SuggestedUserVpn || qReq->SuggestedKernelVpn) {
								printf("[+] Suggested free VPN slots:\n");
								if (qReq->SuggestedUserVpn)
									printf("    [U] User-mode  : 0x%016llx  (VA 0x%016llx)\n",
										qReq->SuggestedUserVpn,   qReq->SuggestedUserVpn   * 0x1000ULL);
								if (qReq->SuggestedKernelVpn)
									printf("    [K] Kernel-mode: 0x%016llx  (VA 0x%016llx)\n",
										qReq->SuggestedKernelVpn, qReq->SuggestedKernelVpn * 0x1000ULL);
								printf("    [M] Enter manually\n");
								printf("    Choice [U/K/M]: ");
								fflush(stdout);
								int hintChoice = _getch();
								printf("%c\n", hintChoice);
								if ((hintChoice == 'u' || hintChoice == 'U') && qReq->SuggestedUserVpn)
									newStart = qReq->SuggestedUserVpn;
								else if ((hintChoice == 'k' || hintChoice == 'K') && qReq->SuggestedKernelVpn)
									newStart = qReq->SuggestedKernelVpn;
								// else fall through to manual entry
							} else {
								printf("[!] No free VPN suggestion available (result=0x%08lx)\n",
									(ULONG)qReq->Result);
							}
						} else {
							printf("[!] QHNT timed out — no response from driver\n");
						}
					}
				}

				// ── Step 2: manual StartingVpn if no suggestion was chosen ─
				if (newStart == 0) {
					printf("Enter StartingVpn (hex): 0x");
					fflush(stdout);
					memset(inputBuffer, 0, sizeof(inputBuffer));
					inputIndex = 0;
					while ((inputChar = _getch()) != '\r' && inputChar != '\n') {
						if (inputChar == '\b' && inputIndex > 0) {
							inputBuffer[--inputIndex] = 0; printf("\b \b");
						} else if (isxdigit(inputChar) && inputIndex < (int)sizeof(inputBuffer) - 1) {
							inputBuffer[inputIndex++] = (char)inputChar; printf("%c", inputChar);
						}
					}
					printf("\n"); inputBuffer[inputIndex] = 0;
					if (inputIndex == 0) { printf("[-] No StartingVpn\n"); break; }
					newStart = strtoull(inputBuffer, NULL, 16);
					}

					// ── Step 2b: page count (decimal) for both paths ──────────
					{
						printf("Enter region size in pages (decimal, 1 page = 4 KB): ");
						fflush(stdout);
						memset(inputBuffer, 0, sizeof(inputBuffer));
						inputIndex = 0;
						while ((inputChar = _getch()) != '\r' && inputChar != '\n') {
							if (inputChar == '\b' && inputIndex > 0) {
								inputBuffer[--inputIndex] = 0; printf("\b \b");
							} else if (isdigit(inputChar) && inputIndex < (int)sizeof(inputBuffer) - 1) {
								inputBuffer[inputIndex++] = (char)inputChar; printf("%c", inputChar);
							}
						}
						printf("\n"); inputBuffer[inputIndex] = 0;
						unsigned long long sizePgs = (inputIndex > 0) ? strtoull(inputBuffer, NULL, 10) : 0;
						if (sizePgs == 0) sizePgs = 1;
						newEnd = newStart + sizePgs - 1;
						printf("[*] Region: VPN 0x%llx - 0x%llx  (%llu page(s), %llu KB)\n",
							newStart, newEnd, sizePgs, sizePgs * 4);
					}

					// ── Step 3: protection ─────────────────────────────────────
					printf("Protection (hex MMVAD, e.g. 04=RW 01=RO 03=RX 07=RWX) [04]: 0x");
					fflush(stdout);
					memset(inputBuffer, 0, sizeof(inputBuffer));
					inputIndex = 0;
				while ((inputChar = _getch()) != '\r' && inputChar != '\n') {
					if (inputChar == '\b' && inputIndex > 0) {
						inputBuffer[--inputIndex] = 0; printf("\b \b");
					} else if (isxdigit(inputChar) && inputIndex < (int)sizeof(inputBuffer) - 1) {
						inputBuffer[inputIndex++] = (char)inputChar; printf("%c", inputChar);
					}
				}
				printf("\n"); inputBuffer[inputIndex] = 0;
				if (inputIndex > 0) newProt = (ULONG)strtoul(inputBuffer, NULL, 16);
				vadType = ((newProt & 0x1F) << 7) | (1 << 20);

				// ── Step 4: send VINS ──────────────────────────────────────
				{
					UCHAR curWalkMode = ((PINIT)SymbolsArray)->walkMode;
					const char* activeProc = (curWalkMode == 1)
						? (sourceProcess ? sourceProcess : "(source not set)")
						: (targetProcess ? targetProcess : "(target not set)");

					PVAD_MODIFY_REQUEST vadReq = (PVAD_MODIFY_REQUEST)VadModifyArray;
					memset(vadReq, 0, sizeof(VAD_MODIFY_REQUEST));
					memcpy(vadReq->identifier, "VINS", 4);
					vadReq->StartingVpn = newStart;
					vadReq->EndingVpn   = newEnd;
					vadReq->Protection  = newProt;
					vadReq->VadTypeRaw  = vadType;
					vadReq->NodeSize    = 0;
					vadReq->isValid     = TRUE;

					printf("[*] Inserting into %s process: '%s'\n",
						curWalkMode == 1 ? "source" : "target", activeProc);
					printf("[*] VPN 0x%llx-0x%llx  (VA 0x%llx-0x%llx)  prot=0x%lx flags=0x%lx\n",
						newStart, newEnd,
						newStart * 0x1000ULL, (newEnd + 1) * 0x1000ULL - 1,
						newProt, vadType);

					if (SetEvent(hEventVAD_INSERT)) {
						printf("[*] Sent VAD insert request\n");
						Sleep(300);
						LONG insertResult = vadReq->Result;
						printf("[*] Kernel result: 0x%08lx\n", (ULONG)insertResult);
						if (insertResult == 0) {
							// Auto-refresh the same tree the insert went into
							printf("[+] Success — refreshing %s tree\n",
								curWalkMode == 1 ? "source" : "target");
							RtlZeroMemory(VADArray, VAD_SECTION_SIZE);
							RtlZeroMemory(VADArrayFileName, VAD_FILENAME_SEC_SIZE);
							if (SetEvent(hEventUSERMODEREADY))
								printf("[*] Tree refresh triggered\n");
						}
					} else {
						printf("[-] Failed to signal VAD insert event: %d\n", GetLastError());
					}
				}
				break;
			}

			default:
				printf("Unknown command '%c'. Try:\n", ch);
				ShowHelp();
				break;
			}
		}
	
cleanup:
	printf("Unlink memory at source VA:\n");
	if (SetEvent(hEventUnlink)) {
		printf("[*] Event set successfully\n");
	}
	else {
		printf("[-] Failed to set event: %d\n", GetLastError());
	}

	// Cleanup WritePhysical resources
	if (WritePhysArray) {
		UnmapViewOfFile(WritePhysArray);
	}
	if (hWritePhysMapFile) {
		CloseHandle(hWritePhysMapFile);
	}
	if (hEventWRITE_PHYS) {
		CloseHandle(hEventWRITE_PHYS);
	}

	// Cleanup ReadPhysical resources
	if (ReadPhysArray) {
		UnmapViewOfFile(ReadPhysArray);
	}
	if (hReadPhysMapFile) {
		CloseHandle(hReadPhysMapFile);
	}
	if (hEventREAD_PHYS) {
		CloseHandle(hEventREAD_PHYS);
	}

	// Cleanup VAD Modify resources
	if (VadModifyArray) {
		UnmapViewOfFile(VadModifyArray);
	}
	if (hVadModifyMapFile) {
		CloseHandle(hVadModifyMapFile);
	}
	if (hEventVAD_INSERT) {
		CloseHandle(hEventVAD_INSERT);
	}
	if (hEventVAD_REMOVE) {
		CloseHandle(hEventVAD_REMOVE);
	}

	return 0;
}
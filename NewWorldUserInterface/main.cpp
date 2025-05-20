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
#define MAPPING_NOTIFICATION_LINK_EVENT L"Global\\LinkMemory"
#define MAPPING_NOTIFICATION_Unlink_EVENT L"Global\\UnlinkMemory"
#define MAPPING_NOTIFICATION_INIT_EVENT L"Global\\InitializeMemory"
#define MAPPING_NOTIFICATION_USERMODEREADY_EVENT L"Global\\UserModeReadEvent"
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
#define MAX_FILENAME_SIZE 80
// -----------------------------------------------------------------
typedef struct _VAD_NODE {
	int Level;
	PVOID VADNode;
	unsigned long long StartingVpn;
	unsigned long long EndingVpn;
	unsigned long Protection;
	//CHAR FileName[MAX_FILENAME_SIZE];
	UCHAR FileOffset;
	LIST_ENTRY ListEntry;
} VAD_NODE, * PVAD_NODE;
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
typedef struct _VAD_NODE_FILE {
	CHAR FileName[MAX_FILENAME_SIZE];
} VAD_NODE_FILE, * PVAD_NODE_FILE;
// -----------------------------------------------------------------
typedef struct _SYMBOL {
	CHAR name[32];
	unsigned long long offset;
	LIST_ENTRY ListEntry;
} SYMBOL, * PSYMBOL;

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
	PSYMBOL CurrSymbolInArray = (PSYMBOL)((PINIT)SymbolsArray + sizeof(INIT));

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
BOOL AddInitData(DWORD NtBaseOffset, DWORD KPROCDirectoryTableBaseOffset, DWORD EPROCActiveProcessLinksOfsset, DWORD EPROCUniqueProcessIdOffset, const char* sourceProcess, const char* targetProcess) {
	PINIT Data = (PINIT)SymbolsArray;
	memcpy(Data[0].identifier, "INIT", 4);
	Data[0].NtBaseOffset = NtBaseOffset;
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
	case _PAGE_NOACCESS:     return "PAGE_NOACCESS";
	case _PAGE_READONLY:     return "PAGE_READONLY";
	case _PAGE_READWRITE:    return "PAGE_READWRITE";
	case _PAGE_WRITECOPY:    return "PAGE_WRITECOPY";
	case _PAGE_EXECUTE:      return "PAGE_EXECUTE";
	case _PAGE_EXECUTE_READ: return "PAGE_EXECUTE_READ";
	default:                   return "UNKNOWN_PROTECTION";
	}
}
// -----------------------------------------------------------------
void GetSymOffsets(PVOID SecBase, size_t SecSize,
	PVOID FileNameSecBase,
	SIZE_T FileNameSecSize) {
	if (SecBase == NULL)
		return;

	PVAD_NODE node = (PVAD_NODE)SecBase;
	PVAD_NODE_FILE FileNameBase = (PVAD_NODE_FILE)FileNameSecBase;

	// Calculate maximum symbols based on remaining size
	size_t maxSymCount = SecSize / sizeof(VAD_NODE);
	size_t maxFileNames = FileNameSecSize / sizeof(VAD_NODE_FILE);
	PROTECTION prot;

	// Print header with consistent column widths
	printf("\n%-6s %-26s %-12s %-12s %-6s %-35s %-30s\n",
		"Level", "VADNode", "StartingVpn", "EndingVpn", "4KBs", "FileName", "Protection");
	printf("%-6s %-26s %-12s %-12s %-6s %-35s %-30s\n",
		"-----", "-------", "-----------", "---------", "---------", "---------", "----------");

	__try {
		for (size_t i = 0; i < maxSymCount - 1; i++) {
			if (node[i].Level == 0)
				continue; // Skip if Level is 0

			prot = (PROTECTION)node[i].Protection;
			const char* protStr = ProtectionToStr(prot);
			DWORD64 rangeSize = node[i].EndingVpn - node[i].StartingVpn;

			if (node[i].FileOffset == 0 || node[i].FileOffset >= maxFileNames) {
				printf("%-6d 0x%-24p 0x%010I64x 0x%010I64x %-6d %-35s %-15s [0x%lx]\n",
					node[i].Level,
					node[i].VADNode,
					node[i].StartingVpn,
					node[i].EndingVpn,
					node[i].EndingVpn - node[i].StartingVpn,
					"-",  // No filename
					protStr,
					node[i].Protection);
			}
			else {
				printf("%-6d 0x%-24p 0x%010I64x 0x%010I64x %-6d %-35s %-15s [0x%lx]\n",
					node[i].Level,
					node[i].VADNode,
					node[i].StartingVpn,
					node[i].EndingVpn,
					node[i].EndingVpn - node[i].StartingVpn,
					FileNameBase[node[i].FileOffset].FileName,
					protStr,
					node[i].Protection);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("Exception when reading memory: 0x%lx\n", GetExceptionCode());
	}
	//// Print header with consistent column widths
	//printf("\nLevel      VADNode                     StartingVpn        EndingVpn          FileName          Protection\n");
	//printf("-----      -------                     -----------        ---------          --------          --------\n");
	//__try {
	//	for (size_t i = 0; i < maxSymCount - 1; i++) {
	//		if (node[i].Level == 0 || node[i].Level == 0) {
	//			continue; // Skip if Level is 0
	//		}
	//		prot = (PROTECTION)node[i].Protection;
	//		if (node[i].FileOffset == 0) {
	//			printf("%-10d 0x%p          0x%010I64x     0x%010I64x | %d - %s [0x%lx]",
	//				node[i].Level,
	//				node[i].VADNode,
	//				node[i].StartingVpn,
	//				node[i].EndingVpn,
	//				node[i].EndingVpn - node[i].StartingVpn,
	//				ProtectionToStr(prot),
	//				node[i].Protection);
	//		} else {
	//			if (node[i].FileOffset >= maxFileNames) {
	//				printf("FileOffset out of bounds: %d\n", node[i].FileOffset);
	//				continue; // Skip if FileOffset is out of bounds
	//			}
	//			printf("%-10d 0x%p          0x%010I64x     0x%010I64x     %s | %d - %s [0x%lx]",
	//				node[i].Level,
	//				node[i].VADNode,
	//				node[i].StartingVpn,
	//				node[i].EndingVpn,
	//				FileNameBase[node[i].FileOffset].FileName,
	//				node[i].EndingVpn - node[i].StartingVpn,
	//				ProtectionToStr(prot),
	//				node[i].Protection);
	//		}
	//		printf("\n");
	//	}
	//} __except (EXCEPTION_EXECUTE_HANDLER) {
	//	printf("Exception when reading memory: 0x%lx\n", GetExceptionCode());
	//}

	return;
}
// -----------------------------------------------------------------
void UpdateInitData(const char* sourceProcess,
	const char* targetProcess,
	unsigned long long sourceVA,
	unsigned long long targetVPN) {
	PINIT Data = (PINIT)SymbolsArray;
	if (sourceProcess != NULL) {
		size_t copyLenSource = min(strlen(sourceProcess), sizeof(Data[0].sourceProcess) - 1);
		memcpy(Data[0].sourceProcess, sourceProcess, copyLenSource);
		Data[0].sourceProcess[15] = '\0';
	}
	if (targetProcess != NULL) {
		size_t copyLenTarget = min(strlen(targetProcess), sizeof(Data[0].targetProcess) - 1);
		memcpy(Data[0].targetProcess, targetProcess, copyLenTarget);
		Data[0].targetProcess[15] = '\0';
	}
	if (sourceVA != 0x0)
		Data[0].sourceVA = sourceVA;
	if (targetVPN != 0x0)
		Data[0].targetVPN = targetVPN;
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
	unsigned long long FILEOBJECTFileName = GetFieldOffset(sym_ctxNtskrnl, "_FILE_OBJECT", L"FileName");
	GetAndInsertSymbol("MMVADSubsection", sym_ctxNtskrnl, MMVADSubsection, true);
	GetAndInsertSymbol("MMVADControlArea", sym_ctxNtskrnl, MMVADControlArea, true);
	GetAndInsertSymbol("MMVADCAFilePointer", sym_ctxNtskrnl, MMVADCAFilePointer, true);
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
	//	printf("[-] Exception occurred while accessing memory: 0x%lx\n", GetExceptionCode());
	//}
}

void ShowHelp() {
	printf("---------------------------------------------------------------\n");
	printf("[*] Press '1' to populate VAD-Tree\n");
	printf("[*] Press '2' to check VAD offsets\n");
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
}

int main(int argc, char* argv[]) {
	// Section to send Symbol Info to Driver
	LPTSTR ntoskrnlPath;
	TCHAR g_ntoskrnlPath[MAX_PATH] = { 0 };
	_tcscat_s(g_ntoskrnlPath, _countof(g_ntoskrnlPath), TEXT("C:\\Windows\\System32\\ntoskrnl.exe")); //ntmarta
	ntoskrnlPath = g_ntoskrnlPath;
	symbol_ctx* sym_ctxNtskrnl = LoadSymbolsFromImageFile(ntoskrnlPath);

	size_t NumSymbols = 7; // TODO Handle mapping size, currently its so few we'll stay below 1 page 4096 Bytes
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
	AddInitDataSection(sym_ctxNtskrnl);
	UpdateInitData(sourceProcess, targetProcess, (unsigned long long)sourceVA, targetVPN);
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
			case '1':
				RtlZeroMemory(VADArray, 4096 * 4);
				RtlZeroMemory(VADArrayFileName, 4096 * 4);
				if (targetProcess != NULL) {
					if (SetEvent(hEventUSERMODEREADY)) { // TODO: Should all be CLI controlled? Like this we will always buffer the VAD-Tree
						printf("[*] Notified driver to populate VAD-Tree\n");
					}
					else {
						printf("[-] Failed to notified driver to populate VAD-Tree: %d\n", GetLastError());
					}
				}
				break;
			case '2':
				printf("[*] VAD offsets:\n");
				GetSymOffsets(VADArray, 4096 * 4, VADArrayFileName, 4096 * 4);
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
					UpdateInitData(sourceProcess, targetProcess, (unsigned long long)sourceVA, targetVPN);
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

				printf("Enter source process name (max 14 chars): ");
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
					else if (inputChar >= 32 && inputChar <= 126 && procNameIndex < 14) {
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
					UpdateInitData(sourceProcess, targetProcess, (unsigned long long)sourceVA, targetVPN);
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

				printf("Enter target process name (max 14 chars): ");
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
					else if (inputChar >= 32 && inputChar <= 126 && procNameIndex < 14) {
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
					UpdateInitData(sourceProcess, targetProcess, (unsigned long long)sourceVA, targetVPN);
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
				SecSize = 4096 * 4;
				FileNameSecBase = VADArrayFileName;
				FileNameSecSize = 4096 * 4;
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
						rangeSize = node[i].EndingVpn - node[i].StartingVpn;

						currentVPN = node[i].StartingVpn;
						pages = node[i].EndingVpn - node[i].StartingVpn;

						for (size_t currPage = 0; currPage < pages; currPage++) { // TODO: < or <= ?
							if (!continueScan)
								break;
							// Update the kernel with the new targetVPN
							targetVPN = currentVPN;
							UpdateInitData(sourceProcess, targetProcess, (unsigned long long)sourceVA, targetVPN);

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
	return 0;
}
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
	//CHAR FileName[MAX_FILENAME_SIZE];
	UCHAR FileOffset;
	LIST_ENTRY ListEntry;
} VAD_NODE, *PVAD_NODE;
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
		printf("Failed SymInitialize\n");
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
			printf("Success\n");
		break;
		if (err == ERROR_FILE_NOT_FOUND) {
			printf("PDB file not found\n");
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
	printf("PDB base address: 0x%llx\n", ctx->pdb_base_addr);
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
		printf("SymGetTypeFromName failed: sym_handle: 0x%llx, pdb_base_addr: 0x%llx, struct_name: %s, Err: %d\n", ctx->sym_handle, ctx->pdb_base_addr, struct_name, err);
		return 0;
	}

	TI_FINDCHILDREN_PARAMS* childrenParam = (TI_FINDCHILDREN_PARAMS*)calloc(1, sizeof(TI_FINDCHILDREN_PARAMS));
	if (childrenParam == NULL) {
		printf("calloc failed\n");
		return 0;
	}

	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_GET_CHILDRENCOUNT, &childrenParam->Count);
	if (!res) {
		printf("SymGetTypeInfo failed\n");
		return 0;
	}
	TI_FINDCHILDREN_PARAMS* ptr = (TI_FINDCHILDREN_PARAMS*)realloc(childrenParam, sizeof(TI_FINDCHILDREN_PARAMS) + childrenParam->Count * sizeof(ULONG));
	if (ptr == NULL) {
		printf("realloc failed\n");
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
			printf("SymUnloadModule failed: %d\n", GetLastError());
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
			printf("SymCleanup failed: %d\n", GetLastError());
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
		printf("SymFromName failed for '%s': error %d (0x%x)\n", symbol_name, err, err);

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
		printf("Maximum string size reached...\n");
		return 0x0;
	}
	if (SymbolsArrayIndex >= SymbolsArrayAllocationSize) {
		printf("Maximum reached...\n");
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
		printf("Unable to invoke EnumDeviceDrivers()!\n");
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
	printf("Checking memory at base: 0x%p\n", base);

	// Just read, don't modify permissions with VirtualProtect
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(base, &mbi, sizeof(mbi))) {
		printf("Memory protection: 0x%lx\n", mbi.Protect);
		printf("Memory state: %s\n",
			mbi.State == MEM_COMMIT ? "COMMIT" :
			mbi.State == MEM_RESERVE ? "RESERVE" : "FREE");
	}

	// Read directly from memory without changing permissions
	__try {
		printf("Memory content (first 16 bytes):\n");
		unsigned char* p = (unsigned char*)base;

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
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("Exception when reading memory: 0x%lx\n", GetExceptionCode());
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

	// Print header with consistent column widths
	printf("\nLevel      VADNode                     StartingVpn        EndingVpn          FileName\n");
	printf("-----      -------                     -----------        ---------          --------\n");
	__try {
		for (size_t i = 0; i < maxSymCount - 1; i++) {
			if (node[i].Level == 0 || node[i].Level == 0) {
				continue; // Skip if Level is 0
			}
			if (node[i].FileOffset == 0) {
				printf("%-10d 0x%p          0x%010I64x     0x%010I64x | %d",
					node[i].Level,
					node[i].VADNode,
					node[i].StartingVpn,
					node[i].EndingVpn,
					node[i].EndingVpn - node[i].StartingVpn);
			} else {
				if (node[i].FileOffset >= maxFileNames) {
					printf("FileOffset out of bounds: %d\n", node[i].FileOffset);
					continue; // Skip if FileOffset is out of bounds
				}
				printf("%-10d 0x%p          0x%010I64x     0x%010I64x     %s | %d",
					node[i].Level,
					node[i].VADNode,
					node[i].StartingVpn,
					node[i].EndingVpn,
					FileNameBase[node[i].FileOffset].FileName,
					node[i].EndingVpn - node[i].StartingVpn);
			}
			printf("\n");
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		printf("Exception when reading memory: 0x%lx\n", GetExceptionCode());
	}

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
	//GetAndInsertSymbol("sourceVA", sym_ctxNtskrnl, (unsigned long long)sourceVA, true);
	//GetAndInsertSymbol("targetVPN", sym_ctxNtskrnl, targetVPN, true);

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

	//HANDLE hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SymbolsArrayAllocationSize, MAPPING_NAME_TO);
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
		VirtualLock(sourceVA, 4096); // Lock the page in memory
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

	PVOID VADArray = (VOID*)MapViewOfFile(hVADMapFile, FILE_MAP_WRITE, 0, 0, 4096 * 3);
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
	PVOID VADArrayFileName = (VOID*)MapViewOfFile(hVADMapFileName, FILE_MAP_WRITE, 0, 0, 4096 * 2); // should be 2 * 4096??? TODO:
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
	
	printf("\n[*] Press 'c' to check VAD offsets");
	printf("\n[*] Press 'y' to check memory at source VA");
	printf("\n[*] Press 'x' to exit\n");

	// More robust command loop implementation
	bool running = true;
	while (running) {
		printf("\nEnter command (c, y, x): ");
		fflush(stdout);  // Ensure the prompt is displayed

		// Read a single character
		int ch = _getch();  // Use _getch() for single character input without buffering
		printf("%c\n", ch); // Echo the character for user feedback

		// Process the command
		switch (ch) {
		case 'x':
		case 'X':
			printf("Exiting program...\n");
			VirtualUnlock(sourceVA, 4096); // Lock the page in memory
			running = false;
			break;

		case 'a':
		case 'A':
			RtlZeroMemory(VADArray, 4096 * 3);
			RtlZeroMemory(VADArrayFileName, 4096 * 2);
			if (targetProcess != NULL) {
				if (SetEvent(hEventUSERMODEREADY)) { // TODO: Should all be CLI controlled? Like this we will always buffer the VAD-Tree
					printf("[*] Event set successfully\n");
				}
				else {
					printf("[-] Failed to set event: %d\n", GetLastError());
				}
			}
			break;

		case 'b':
		case 'B':
			if (targetVPN != NULL && sourceProcess != NULL) {
				if (SetEvent(hEventLINK)) { // TODO: Should all be CLI controlled? Like this we will Link
					printf("[*] Event set successfully\n");
				}
				else {
					printf("[-] Failed to set event: %d\n", GetLastError());
				}
			}
			break;

		case 'c':
		case 'C':
			printf("Checking VAD offsets:\n");
			GetSymOffsets(VADArray, 4096, VADArrayFileName, 4096 * 2);
			break;

		case 'i':
		case 'I':
			AddInitDataSection(sym_ctxNtskrnl);
			break;
		case 'u':
		case 'U':
			UpdateInitData(sourceProcess, targetProcess, (unsigned long long)sourceVA, targetVPN);
			if (SetEvent(hEventINIT)) {
				printf("[*] Event set successfully\n");
			}
			else {
				printf("[-] Failed to set event: %d\n", GetLastError());
			}
			break;

		case 'y':
		case 'Y':
			printf("Checking memory at source VA:\n");
			CheckModifiedMemory(sourceVA, targetVPNSize);
			break;

		//case 'u':
		//case 'U':
		//	break;

		case '\n':
		case '\r':  // Handle Enter presses
			break;

		default:
			printf("Unknown command '%c'. Try 'c', 'y', or 'x'.\n", ch);
			break;
		}
	}

cleanup:
	// Cleanup code
	//if (VADArray) {
	//	UnmapViewOfFile(VADArray);
	//}
	//if (hVADMapFile) {
	//	CloseHandle(hVADMapFile);
	//}
	//if (VADArrayFileName) {
	//	UnmapViewOfFile(VADArrayFileName);
	//}
	//if (hVADMapFileName) {
	//	CloseHandle(hVADMapFileName);
	//}
	//if (SymbolsArray) {
	//	UnmapViewOfFile(SymbolsArray);
	//}
	//if (hMapFile) {
	//	CloseHandle(hMapFile);
	//}
	//printf("Unlink memory at source VA:\n");
	//if (SetEvent(hEventUnlink)) {
	//	printf("[*] Event set successfully\n");
	//}
	//else {
	//	printf("[-] Failed to set event: %d\n", GetLastError());
	//}
	//printf("[*] Cleanup symbol_ctx (NOT)\n");
	//UnloadSymbols(sym_ctxNtskrnl, false); // TODO: This has to be properly Unloaded

	return 0;
}

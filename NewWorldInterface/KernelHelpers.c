#include "KernelHelpers.h"


BOOL InitData() {
	if (pInSection == NULL)
		return FALSE;

	PINIT initPos = (PINIT)pInSection;

	// Compare as 4 separate characters or use a proper string comparison
	if (initPos->identifier[0] == 'I' &&
		initPos->identifier[1] == 'N' &&
		initPos->identifier[2] == 'I' &&
		initPos->identifier[3] == 'T') {

		gInit = *initPos;
		DbgPrint("[+] gInit.NtBaseOffset: 0x%llx\n", gInit.NtBaseOffset);
		return TRUE;
	}

	return FALSE;
}
UINT64 GetSymOffset(const char* str) {
	if (pInSection == NULL)
		return 0;

	// Calculate the address after the INIT structure
	PSYMBOL syms = (PSYMBOL)((PINIT)pInSection + sizeof(INIT));

	// Calculate maximum symbols based on remaining size
	size_t maxSymCount = (gSymsViewSize - sizeof(INIT)) / sizeof(SYMBOL);

	for (size_t i = 0; i < maxSymCount; i++) {
		if (strcmp(syms[i].name, str) == 0) {
			return syms[i].offset;
		}
	}

	return 0;
}
// -----------------------------------------------------------------
BOOL InitSymInfo() {
	gSymInfo.ZwProtectVirtualMemory = GetSymOffset("ZwProtectVirtualMemory");
	gSymInfo.EProcUniqueProcessId = GetSymOffset("eprocUniqueProcessId");
	gSymInfo.EProcActiveProcessLinks = GetSymOffset("eprocActiveProcessLinks");
	gSymInfo.KPROCDirectoryTableBase = GetSymOffset("kprocDirectoryTableBase");
	//gSymInfo.sourceVA = GetSymOffset("sourceVA");
	//gSymInfo.targetVPN = GetSymOffset("targetVPN");
	gSymInfo.VADRoot = GetSymOffset("VADRoot");
	gSymInfo.StartingVpnOffset = GetSymOffset("StartingVpn");
	gSymInfo.EndingVpnOffset = GetSymOffset("EndingVpn");
	gSymInfo.Left = GetSymOffset("Left");
	gSymInfo.Right = GetSymOffset("Right");
	gSymInfo.MMVADSubsection = GetSymOffset("MMVADSubsection");
	gSymInfo.MMVADControlArea = GetSymOffset("MMVADControlArea");
	gSymInfo.MMVADCAFilePointer = GetSymOffset("MMVADCAFilePointer");
	gSymInfo.FILEOBJECTFileName = GetSymOffset("FILEOBJECTFileName");
	gSymInfo.EProcImageFileName = GetSymOffset("EPROCImageFileName");
	gSymInfo.PEB = GetSymOffset("PEB");
	gSymInfo.PEBLdr = GetSymOffset("PEBLdr");
	gSymInfo.LdrListHead = GetSymOffset("LdrListHead");
	gSymInfo.LdrListEntry = GetSymOffset("LdrListEntry");
	gSymInfo.LdrBaseDllName = GetSymOffset("LdrBaseDllName");
	gSymInfo.LdrBaseDllBase = GetSymOffset("LdrBaseDllBase");
	return TRUE;
}
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
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

	// Cast to PBYTE so +sizeof(INIT) advances by exactly sizeof(INIT) bytes,
	// not sizeof(INIT)*sizeof(INIT) bytes (which is what PINIT pointer arithmetic does).
	PSYMBOL syms = (PSYMBOL)((PBYTE)pInSection + sizeof(INIT));

	// Symbols occupy [sizeof(INIT) .. gSymsViewSize), so subtract the header bytes first.
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
	gSymInfo.MMVADSubsection     = GetSymOffset("MMVADSubsection");
	gSymInfo.MMVADControlArea    = GetSymOffset("MMVADControlArea");
	gSymInfo.MMVADCAFilePointer  = GetSymOffset("MMVADCAFilePointer");
	gSymInfo.MMCAFlags           = GetSymOffset("MMCAFlags");
	gSymInfo.MMCAMappedViews     = GetSymOffset("MMCAMappedViews");
	gSymInfo.MMCAUserReferences  = GetSymOffset("MMCAUserReferences");
	gSymInfo.FILEOBJECTFileName  = GetSymOffset("FILEOBJECTFileName");
	gSymInfo.EProcImageFileName = GetSymOffset("EPROCImageFileName");
	gSymInfo.PEB = GetSymOffset("PEB");
	gSymInfo.PEBLdr = GetSymOffset("PEBLdr");
	gSymInfo.LdrListHead = GetSymOffset("LdrListHead");
	gSymInfo.LdrListEntry = GetSymOffset("LdrListEntry");
	gSymInfo.LdrBaseDllName = GetSymOffset("LdrBaseDllName");
	gSymInfo.LdrBaseDllBase = GetSymOffset("LdrBaseDllBase");
	// AVL tree modification fields
	gSymInfo.ParentValue        = GetSymOffset("ParentValue");
	gSymInfo.AddressCreationLock = GetSymOffset("AddressCreationLock");
	gSymInfo.VadHint            = GetSymOffset("VadHint");
	gSymInfo.VadFreeHint        = GetSymOffset("VadFreeHint");
	// Kernel MM internal helpers — absolute addresses from ntoskrnl base + PDB offset
	gSymInfo.MiCheckForConflictingVad = GetSymOffset("MiCheckForConflictingVad");
	gSymInfo.MiInsertVad              = GetSymOffset("MiInsertVad");
	gSymInfo.MiInsertVadCharges       = GetSymOffset("MiInsertVadCharges");
	gSymInfo.MiRemoveVad              = GetSymOffset("MiRemoveVad");
	gSymInfo.MiRemoveVadCharges       = GetSymOffset("MiRemoveVadCharges");
	// PDB-derived MMVAD flags layout — replaces hardcoded struct offsets
	// All MMVAD types share the same primary flags DWORD at _MMVAD_SHORT.u
	gSymInfo.MMVADFlagsOffset    = GetSymOffset("MMVADFlagsOffset");
	gSymInfo.ProtectionBitPos    = GetSymOffset("ProtectionBitPos");
	gSymInfo.ProtectionBitLen    = GetSymOffset("ProtectionBitLen");
	gSymInfo.VadTypeBitPos       = GetSymOffset("VadTypeBitPos");
	gSymInfo.VadTypeBitLen       = GetSymOffset("VadTypeBitLen");
	gSymInfo.PrivateMemoryBitPos = GetSymOffset("PrivateMemoryBitPos");
	return TRUE;
}
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
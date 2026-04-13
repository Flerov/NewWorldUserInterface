#include "VADTreeWalker.h"


BOOL InsertVADNode(int Level,
	PVOID VADNode,
	unsigned long long StartingVpn,
	unsigned long long EndingVpn,
	UNICODE_STRING* FileName,
	unsigned long Protection) {

	if (gViewSize / sizeof(VAD_NODE) <= gSecVADIndex) {
		DbgPrint("[-] VAD node index out of bounds\n");
		return FALSE;
	}
	if (gFileNameViewSize / sizeof(VAD_NODE_FILE) <= gCurrFileNameOffset) {
		DbgPrint("[-] FileName node index out of bounds\n");
		return FALSE;
	}

	PVAD_NODE CurrVADNode = (PVAD_NODE)gSection;
	PVAD_NODE_FILE FileNameBuffer = (PVAD_NODE_FILE)gFileNameSection;

	CurrVADNode[gSecVADIndex].Level = Level;
	CurrVADNode[gSecVADIndex].VADNode = VADNode;
	CurrVADNode[gSecVADIndex].StartingVpn = StartingVpn;
	CurrVADNode[gSecVADIndex].EndingVpn = EndingVpn;
	CurrVADNode[gSecVADIndex].FileOffset = 0;
	CurrVADNode[gSecVADIndex].Protection = Protection;
	if (FileName != NULL && FileName->Length > 0 && FileName->Length < gViewSize) {
		ANSI_STRING test;
		if (NT_SUCCESS(RtlUnicodeStringToAnsiString(
			&test,
			FileName,
			TRUE))) {
			size_t size = min(test.Length, sizeof(VAD_NODE_FILE));
			memcpy(FileNameBuffer[gCurrFileNameOffset].FileName, test.Buffer, size);
			FileNameBuffer[gCurrFileNameOffset].FileName[min(size, MAX_FILENAME_SIZE - 1)] = '\0';
			CurrVADNode[gSecVADIndex].FileOffset = gCurrFileNameOffset;
			RtlFreeAnsiString(&test);
			gCurrFileNameOffset++;
		}
		else {
			DbgPrint("[-] Failed to convert FileName to ANSI\n");
		}
	}

	gSecVADIndex++;
	return TRUE;
}
UNICODE_STRING* GetFileObjectFromVADLeaf(unsigned long long Leaf, DWORD MMVADSubsection, DWORD MMVADControlArea, DWORD MMVADCAFilePointer, DWORD FILEOBJECTFileName) {
	// Check if Leaf is NULL first
	if (Leaf == 0) {
		return NULL;
	}

	unsigned long long SubsectionPtr = *(PVOID*)(Leaf + MMVADSubsection);
	// MmIsAddressValid is much faster than try-except and achieves similar safety
	if (!MmIsAddressValid((PVOID)SubsectionPtr)) {
		return NULL;
	}

	unsigned long long ControlArea = *(PVOID*)(SubsectionPtr);
	if (!MmIsAddressValid((PVOID)ControlArea)) {
		return NULL;
	}

	unsigned long long FilePointer = (PVOID*)(ControlArea + MMVADCAFilePointer);
	if (!MmIsAddressValid((PVOID)FilePointer)) {
		return NULL;
	}

	unsigned long long FileObject = *(PVOID*)FilePointer;
	if (!MmIsAddressValid((PVOID)FileObject)) {
		return NULL;
	}

	// Apply mask to FileObject
	FileObject = FileObject - (FileObject & 0xF);
	if (!MmIsAddressValid((PVOID)(FileObject + FILEOBJECTFileName))) {
		return NULL;
	}

	UNICODE_STRING* FileName = (UNICODE_STRING*)(FileObject + FILEOBJECTFileName);
	// Additional validation on the UNICODE_STRING structure
	if (!MmIsAddressValid(FileName->Buffer)) {
		return NULL;
	}

	return FileName;
}
VOID WalkVADRecursive(PVOID VADNode, unsigned long StartingVpnOffset, DWORD EndingVpnOffset,
	DWORD Left, DWORD Right, int Level,
	PULONG TotalVADs, PULONG TotalLevels, PULONG MaxDepth,
	DWORD MMVADSubsection, DWORD MMVADControlArea, DWORD MMVADCAFilePointer, DWORD FILEOBJECTFileName,
	unsigned long long targetAdr) {
	// If node is NULL, return
	if (VADNode == NULL) {
		return;
	}
	// Update statistics
	(*TotalVADs)++;
	(*TotalLevels) += Level;
	if (Level > *MaxDepth) {
		*MaxDepth = Level;
	}

	// Get node information
	unsigned long long Vpn;
	unsigned long long VpnStart;
	unsigned long long VpnEnd;
	unsigned long long VpnHigh;
	unsigned long long VpnHighPart0;
	unsigned long long VpnHighPart1;
	unsigned long long StartingVpn;
	unsigned long long EndingVpn;
	Vpn = *(PVOID*)((unsigned long long)VADNode + StartingVpnOffset);
	VpnStart = Vpn & 0xFFFFFFFF;
	VpnEnd = (Vpn >> 32) & 0xFFFFFFFF;

	VpnHigh = *(PVOID*)((unsigned long long)VADNode + 0x20); // StartingVpnHigh
	VpnHighPart0 = VpnHigh & 0xFF; // Mask to get low part
	VpnHighPart1 = (VpnHigh >> 8) & 0xFF;
	VpnHighPart0 = VpnHighPart0 << 32;
	VpnHighPart1 = VpnHighPart1 << 32;

	StartingVpn = VpnStart | VpnHighPart0;
	EndingVpn = VpnEnd | VpnHighPart1;

	// Check if targetAdr is within the range of this VAD
	BOOLEAN isTargetInRange = FALSE;

	UNICODE_STRING* FileName = GetFileObjectFromVADLeaf(VADNode, MMVADSubsection, MMVADControlArea, MMVADCAFilePointer, FILEOBJECTFileName);
	MMVAD_FLAGS Flags = *(MMVAD_FLAGS*)((ULONG_PTR)VADNode + 0x30); // MMVAD_FLAGS <anonymous-tag> ._.
	InsertVADNode(Level, VADNode, StartingVpn, EndingVpn, FileName, Flags.Protection);

	// Get left and right children
	PVOID LeftChild = *(PVOID*)((ULONG_PTR)VADNode + Left);
	PVOID RightChild = *(PVOID*)((ULONG_PTR)VADNode + Right);

	// Recursively traverse left subtree first (smaller addresses)
	WalkVADRecursive(LeftChild, StartingVpnOffset, EndingVpnOffset, Left, Right,
		Level + 1, TotalVADs, TotalLevels, MaxDepth,
		MMVADSubsection, MMVADControlArea, MMVADCAFilePointer, FILEOBJECTFileName,
		targetAdr);

	// Recursively traverse right subtree last (larger addresses)
	WalkVADRecursive(RightChild, StartingVpnOffset, EndingVpnOffset, Left, Right,
		Level + 1, TotalVADs, TotalLevels, MaxDepth,
		MMVADSubsection, MMVADControlArea, MMVADCAFilePointer, FILEOBJECTFileName,
		targetAdr);
}
VOID WalkVAD(PEPROCESS TargetProcess,
	DWORD VADRootOffset,
	DWORD StartingVpnOffset,
	DWORD EndingVpnOffset,
	DWORD Left,
	DWORD Right,
	DWORD MMVADSubsection,
	DWORD MMVADControlArea,
	DWORD MMVADCAFilePointer,
	DWORD FILEOBJECTFileName,
	unsigned long long targetAdr) {

	PVOID* pVADRoot = (PVOID*)((ULONG_PTR)TargetProcess + VADRootOffset);
	DbgPrint("[*] WalkVAD: TargetProcess: 0x%llx | VADRoot: 0x%llx\n", TargetProcess, *pVADRoot);
	if (!MmIsAddressValid(*pVADRoot)) {
		DbgPrint("[-] VAD tree is empty | *pVADRoot: 0x%llx -> TargetProcess: 0x%llx + VADRootOffset: 0x%lx\n", *pVADRoot, TargetProcess, VADRootOffset);
		return;
	}
	// Variables to track statistics
	ULONG totalVADs = 0;
	ULONG totalLevels = 0;
	ULONG maxDepth = 0;
	gSecVADIndex = 0;
	gCurrFileNameOffset = 0;

	// Call recursive function with statistics tracking - passing the targetAdr
	WalkVADRecursive(*pVADRoot, StartingVpnOffset, EndingVpnOffset, Left, Right, 1,
		&totalVADs, &totalLevels, &maxDepth, MMVADSubsection, MMVADControlArea, MMVADCAFilePointer, FILEOBJECTFileName,
		targetAdr);

	// Calculate and print statistics
	ULONG avgLevel = (totalVADs > 0) ? totalLevels / totalVADs : 0;
	ULONG avgLevelFrac = (totalVADs > 0) ? ((totalLevels * 100) / totalVADs) % 100 : 0;
	DbgPrint("Total VADs: %lu, average level: %lu.%02lu, maximum depth: %lu\n\n",
		totalVADs, avgLevel, avgLevelFrac, maxDepth);
}
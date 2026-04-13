#pragma once
#include <ntifs.h>
#include "VirtualAddressTranslation.h"


VOID ChangeRef(
	unsigned long long SourceVA, PEPROCESS SourceProcess, unsigned long long SourceCR3,
	unsigned long long TargetVA, PEPROCESS TargetProcess, unsigned long long TargetCR3) {
	if (SourceVA == 0x0 || TargetVA == 0x0) {
		DbgPrint("[-] ChangeRef: SourceVA or TargetVA is NULL\n");
		return;
	}
	DbgPrint("[*] ChangeRef: SourceVA: 0x%llx | SourceProcess: 0x%llx | SourceCR3: 0x%llx\n", SourceVA, SourceProcess, SourceCR3);
	DbgPrint("[*] ChangeRef: TargetVA: 0x%llx | TargetProcess: 0x%llx | TargetCR3: 0x%llx\n", TargetVA, TargetProcess, TargetCR3);

	unsigned long long TargetPFN = 0x0;
	KAPC_STATE ApcState;
	NTSTATUS status;
	SIZE_T numRec = 0;

	MM_COPY_ADDRESS PhysPML4 = { 0 }; // Physical Page Map Level 4
	MM_COPY_ADDRESS PhysPDPT = { 0 }; // Physical Page Directory Pointer Table
	MM_COPY_ADDRESS PhysPD = { 0 };   // Physical Page Directory
	MM_COPY_ADDRESS PhysPage = { 0 }; // Physical Page Table
	MM_COPY_ADDRESS Phys = { 0 };     // Physical

	unsigned long long PML4Offset;
	unsigned long long PDPTOffset;
	unsigned long long PDOffset;
	unsigned long long PTOffset;
	unsigned long long MaskOffset;

	unsigned long long tmp = 0x0;
	unsigned long long pml4e = 0x0; // Page Map Level 4 Entry (Pointer)
	unsigned long long pdpte = 0x0; // Page Directory Pointer Table Entry (Pointer)
	unsigned long long pde = 0x0;   // Page Directory Entry (Pointer)
	unsigned long long pte = 0x0;   // Page Table Entry (Pointer)
	unsigned long long physAdr = 0x0; // unused

	PML4E* PML4ERaw = 0x0; // Page Map Level 4 Entry
	PDPTE* PDPTERaw = 0x0; // Page Directory Pointer Table Entry
	PDE* PDERaw = 0x0; // Page Directory Entry
	PTE* PTERaw = 0x0; // Page Table Entry
	PHYSICAL_1GB* PHYSRaw1GB = 0x0; // Huge Page
	PHYSICAL_2MB* PHYSRaw2MB = 0x0; // Large Page
	PHYSICAL_4KB* PHYSRaw4KB = 0x0; // Page

	// Target Process
	DbgPrint("Get for Target\n");
	// Extract the PFN
	KeStackAttachProcess(TargetProcess, &ApcState);

	PML4Offset = (TargetVA & 0xFF8000000000) >> 0x27; // Page Map Level 4 Offset
	PDPTOffset = (TargetVA & 0x7FC0000000) >> 0x1E;   // Page Directory Pointer Table Offset
	PDOffset = (TargetVA & 0x3FE00000) >> 0x15;       // Page Directory Offset
	PTOffset = (TargetVA & 0x1FF000) >> 0x0C;         // Page Table Offset
	MaskOffset = (TargetVA & 0xFFF);               // Physical Offset

	// walk PML4 -> Physical
	PhysPML4.PhysicalAddress.QuadPart = TargetCR3 + (PML4Offset * 0x08);
	status = MmCopyMemory(&pml4e, PhysPML4, sizeof(pml4e), MM_COPY_MEMORY_PHYSICAL, &numRec); // sizeof(pml4e) / 2 bei allen
	// TODO: The PFN of !vtop output for PML4E does not match with the pfn of PML4ERaw->PageFrameNumber instead it matches to PhysPML4.PhysicalAddress.QuadPart
	pml4e = pml4e & 0xFFFFFFFFFFFF; // Mask out the upper bits
	PML4ERaw = (PML4E*)&pml4e;
	DbgPrint("[+] PML4E Raw - Virtual: 0x%llx\n", pml4e);

	PhysPDPT.PhysicalAddress.QuadPart = (pml4e & 0xFFFFF000) + (PDPTOffset * 0x08);
	status = MmCopyMemory(&pdpte, PhysPDPT, sizeof(pdpte), MM_COPY_MEMORY_PHYSICAL, &numRec);
	// TODO: The PFN of !vtop output for PML4E does not match with the pfn of PDPTERaw->PageFrameNumber instead it matches to PhysPDPT.PhysicalAddress.QuadPart
	pdpte = pdpte & 0xFFFFFFFFFFFF; // Mask out the upper bits
	PDPTERaw = (PDPTE*)&pdpte;
	DbgPrint("[+] PDPTE Raw - Virtual: 0x%llx\n", pdpte);

	if (PDPTERaw->PageSize == 0) {
		// 1 = Maps a 1GB page, 0 = Points to a page directory.
		PhysPD.PhysicalAddress.QuadPart = (pdpte & 0xFFFFF000) + (PDOffset * 0x08);
		status = MmCopyMemory(&pde, PhysPD, sizeof(pde), MM_COPY_MEMORY_PHYSICAL, &numRec);
		PDERaw = (PDE*)&pde;
		pde = pde & 0xFFFFFFFFFFFF; // Mask out the upper bits
		PDERaw = (PDE*)&pde;
		DbgPrint("[+] PDE Raw - Virtual: 0x%llx\n", pde);
		if (PDERaw->PageSize == 0) {
			// 1 = Maps a 2 MB page, 0 = Points to a page table.
			PhysPage.PhysicalAddress.QuadPart = (pde & 0xFFFFF000) + (PTOffset * 0x08);
			Phys.PhysicalAddress.QuadPart = PhysPage.PhysicalAddress.QuadPart + MaskOffset;
			status = MmCopyMemory(&pte, PhysPage, sizeof(pte), MM_COPY_MEMORY_PHYSICAL, &numRec);
			TargetPFN = pte;
			DbgPrint("[+] PTE Raw - Virtual: 0x%llx\n", pte);
			DbgPrint("Got PT-Base: 0x%llx\n", TargetPFN);
			pte = pte & 0xFFFFFFFFFFFF; // Mask out the upper bits
			DbgPrint("Target PTE: 0x%llx\n", pte);
			PTERaw = (PTE*)&pte;
			PHYSRaw4KB = (PHYSICAL_4KB*)&pte;
		}
		else {
			PHYSRaw2MB = (PHYSICAL_2MB*)&pde;
			DbgPrint("[+] PHYSRaw2MB - Virtual: 0x%llx\n", pde);
		}
	}
	else {
		PHYSRaw1GB = (PHYSICAL_1GB*)&pdpte;
		DbgPrint("[+] PHYSRaw1GB - Virtual: 0x%llx\n", pdpte);
	}
	KeUnstackDetachProcess(&ApcState);

	// Source Process
	DbgPrint("Get for Source\n");
	KeStackAttachProcess(SourceProcess, &ApcState);

	PML4Offset = (SourceVA & 0xFF8000000000) >> 0x27; // Page Map Level 4 Offset
	PDPTOffset = (SourceVA & 0x7FC0000000) >> 0x1E;   // Page Directory Pointer Table Offset
	PDOffset = (SourceVA & 0x3FE00000) >> 0x15;       // Page Directory Offset
	PTOffset = (SourceVA & 0x1FF000) >> 0x0C;         // Page Table Offset
	MaskOffset = (SourceVA & 0xFFF);               // Physical Offset

	// walk PML4 -> Physical
	PhysPML4.PhysicalAddress.QuadPart = SourceCR3 + (PML4Offset * 0x08);
	status = MmCopyMemory(&pml4e, PhysPML4, sizeof(pml4e), MM_COPY_MEMORY_PHYSICAL, &numRec); // sizeof(pml4e) / 2 bei allen
	// TODO: The PFN of !vtop output for PML4E does not match with the pfn of PML4ERaw->PageFrameNumber instead it matches to PhysPML4.PhysicalAddress.QuadPart
	pml4e = pml4e & 0xFFFFFFFFFFFF; // Mask out the upper bits
	PML4ERaw = (PML4E*)&pml4e;

	PhysPDPT.PhysicalAddress.QuadPart = (pml4e & 0xFFFFF000) + (PDPTOffset * 0x08);
	status = MmCopyMemory(&pdpte, PhysPDPT, sizeof(pdpte), MM_COPY_MEMORY_PHYSICAL, &numRec);
	// TODO: The PFN of !vtop output for PML4E does not match with the pfn of PDPTERaw->PageFrameNumber instead it matches to PhysPDPT.PhysicalAddress.QuadPart
	pdpte = pdpte & 0xFFFFFFFFFFFF; // Mask out the upper bits
	PDPTERaw = (PDPTE*)&pdpte;

	if (PDPTERaw->PageSize == 0) {
		// 1 = Maps a 1GB page, 0 = Points to a page directory.
		PhysPD.PhysicalAddress.QuadPart = (pdpte & 0xFFFFF000) + (PDOffset * 0x08);
		status = MmCopyMemory(&pde, PhysPD, sizeof(pde), MM_COPY_MEMORY_PHYSICAL, &numRec);
		pde = pde & 0xFFFFFFFFFFFF; // Mask out the upper bits
		PDERaw = (PDE*)&pde;
		if (PDERaw->PageSize == 0) {
			// 1 = Maps a 2 MB page, 0 = Points to a page table.
			PhysPage.PhysicalAddress.QuadPart = (pde & 0xFFFFF000) + (PTOffset * 0x08);
			Phys.PhysicalAddress.QuadPart = PhysPage.PhysicalAddress.QuadPart + MaskOffset;
			status = MmCopyMemory(&physAdr, Phys, sizeof(physAdr), MM_COPY_MEMORY_PHYSICAL, &numRec);
			gOrigPhys.QuadPart = Phys.PhysicalAddress.QuadPart;
			if (gOrigVal == 0x0) // Check if the original value is not set
				gOrigVal = physAdr;
			physAdr = physAdr & 0xFFFFFFFFFFFF; // Mask out the upper bits
			DbgPrint("Source PTE: 0x%llx\n", physAdr);
			PTERaw = (PTE*)&physAdr;
			PHYSRaw4KB = (PHYSICAL_4KB*)&physAdr;
		}
		else {
			PHYSRaw2MB = (PHYSICAL_2MB*)&pde;
		}
	}
	else {
		PHYSRaw1GB = (PHYSICAL_1GB*)&pdpte;
	}
	// Make sure the Section is not paged-out
	DbgPrint("Test for Change\n");
	DbgPrint("TargetPFN: 0x%llx\n", TargetPFN);
	DbgPrint("SourceVA: 0x%llx\n", SourceVA);
	if (TargetPFN != 0x0 && PTERaw != 0x0) {
		PTE* temp = MmGetVirtualForPhysical(Phys.PhysicalAddress);
		if (MmIsAddressValid(temp) == FALSE) {
			DbgPrint("[-] MmGetVirtualForPhysical returned an invalid address\n");
			KeUnstackDetachProcess(&ApcState);
			return;
		}
		DbgPrint("VirtualForPhysical at: 0x%llx\n", temp);
		DbgPrint("Changing PFN to TargetPFN: 0x%llx - 0x%llx\n", temp->Value, TargetPFN);
		memcpy(temp, &TargetPFN, sizeof(TargetPFN)); // the size should be correct
		DbgPrint("CHANGED\n");
		KeUnstackDetachProcess(&ApcState);
		return;
	}
	else {
		DbgPrint("[-] PTERaw is NULL\n");
		KeUnstackDetachProcess(&ApcState);
	}
	DbgPrint("Returning\n");
	return;
}

ULONG64 VirtToPhys(unsigned long long addr, PEPROCESS TargetProcess, unsigned long long cr3, BOOLEAN log) {
	KAPC_STATE ApcState;
	NTSTATUS status;
	SIZE_T numRec = 0;
	MM_COPY_ADDRESS PhysPML4 = { 0 }; // Physical Page Map Level 4
	MM_COPY_ADDRESS PhysPDPT = { 0 }; // Physical Page Directory Pointer Table
	MM_COPY_ADDRESS PhysPD = { 0 };   // Physical Page Directory
	MM_COPY_ADDRESS PhysPage = { 0 }; // Physical Page Table
	MM_COPY_ADDRESS Phys = { 0 };     // Physical

	unsigned long long PML4Offset = (addr & 0xFF8000000000) >> 0x27; // Page Map Level 4 Offset
	unsigned long long PDPTOffset = (addr & 0x7FC0000000) >> 0x1E;   // Page Directory Pointer Table Offset
	unsigned long long PDOffset = (addr & 0x3FE00000) >> 0x15;       // Page Directory Offset
	unsigned long long PTOffset = (addr & 0x1FF000) >> 0x0C;         // Page Table Offset
	unsigned long long MaskOffset = (addr & 0x1FFFFF);               // Physical Offset

	unsigned long long tmp = 0x0;
	unsigned long long pml4e = 0x0; // Page Map Level 4 Entry (Pointer)
	unsigned long long pdpte = 0x0; // Page Directory Pointer Table Entry (Pointer)
	unsigned long long pde = 0x0;   // Page Directory Entry (Pointer)
	unsigned long long pte = 0x0;   // Page Table Entry (Pointer)
	unsigned long long physAdr = 0x0; // unused
	unsigned long long IA32_PAT_MSR = __readmsr(0x277); // Read PAT (Page Attribute Table)

	PML4E* PML4ERaw = 0x0; // Page Map Level 4 Entry
	PDPTE* PDPTERaw = 0x0; // Page Directory Pointer Table Entry
	PDE* PDERaw = 0x0; // Page Directory Entry
	PTE* PTERaw = 0x0; // Page Table Entry
	PHYSICAL_1GB* PHYSRaw1GB = 0x0; // Huge Page
	PHYSICAL_2MB* PHYSRaw2MB = 0x0; // Large Page
	PHYSICAL_4KB* PHYSRaw4KB = 0x0; // Page

	KeStackAttachProcess(TargetProcess, &ApcState);
	//MDL* pMdl = IoAllocateMdl(addr, 4096, FALSE, FALSE, NULL);
	//MmProbeAndLockPages(pMdl, UserMode, IoReadAccess);

	// walk PML4 -> Physical
	PhysPML4.PhysicalAddress.QuadPart = cr3 + (PML4Offset * 0x08);
	status = MmCopyMemory(&pml4e, PhysPML4, sizeof(pml4e), MM_COPY_MEMORY_PHYSICAL, &numRec); // sizeof(pml4e) / 2 bei allen
	// TODO: The PFN of !vtop output for PML4E does not match with the pfn of PML4ERaw->PageFrameNumber instead it matches to PhysPML4.PhysicalAddress.QuadPart
	pml4e = pml4e & 0xFFFFFFFFFFFF; // Mask out the upper bits
	PML4ERaw = (PML4E*)&pml4e;

	PhysPDPT.PhysicalAddress.QuadPart = (pml4e & 0xFFFFF000) + (PDPTOffset * 0x08);
	status = MmCopyMemory(&pdpte, PhysPDPT, sizeof(pdpte), MM_COPY_MEMORY_PHYSICAL, &numRec);
	// TODO: The PFN of !vtop output for PML4E does not match with the pfn of PDPTERaw->PageFrameNumber instead it matches to PhysPDPT.PhysicalAddress.QuadPart
	pdpte = pdpte & 0xFFFFFFFFFFFF; // Mask out the upper bits
	PDPTERaw = (PDPTE*)&pdpte;

	if (PDPTERaw->PageSize == 0) {
		// 1 = Maps a 1GB page, 0 = Points to a page directory.
		PhysPD.PhysicalAddress.QuadPart = (pdpte & 0xFFFFF000) + (PDOffset * 0x08);
		status = MmCopyMemory(&pde, PhysPD, sizeof(pde), MM_COPY_MEMORY_PHYSICAL, &numRec);
		pde = pde & 0xFFFFFFFFFFFF; // Mask out the upper bits
		PDERaw = (PDE*)&pde;
		if (PDERaw->PageSize == 0) {
			// 1 = Maps a 2 MB page, 0 = Points to a page table.
			PhysPage.PhysicalAddress.QuadPart = (pde & 0xFFFFF000) + (PTOffset * 0x08);
			Phys.PhysicalAddress.QuadPart = PhysPage.PhysicalAddress.QuadPart + MaskOffset;
			status = MmCopyMemory(&pte, PhysPage, sizeof(pte), MM_COPY_MEMORY_PHYSICAL, &numRec);
			pte = pte & 0xFFFFFFFFFFFF; // Mask out the upper bits
			PTERaw = (PTE*)&pte;
			PHYSRaw4KB = (PHYSICAL_4KB*)&pte;
		}
		else {
			PHYSRaw2MB = (PHYSICAL_2MB*)&pde;
		}
	}
	else {
		PHYSRaw1GB = (PHYSICAL_1GB*)&pdpte;
	}
	//MmUnlockPages(pMdl);
	//IoFreeMdl(pMdl);

	if (log) {
		DbgPrint("[+] cr3: 0x%llx\n", cr3);
		DbgPrint("[+] PML4E Raw - Virtual: 0x%llx\n"
			"\t[*] Accessed: %llx\n"
			"\t[*] ExecuteDisable: %llx\n"
			"\t[*] PageCacheDisable: %llx\n"
			"\t[*] PageFrameNumber: %llx\n"
			"\t[*] PageSize: %llx\n"
			"\t[*] PageWriteThrough: %llx\n"
			"\t[*] Present: %llx\n"
			"\t[*] ProtectionKey: %llx\n"
			"\t[*] ReadWrite: %llx\n"
			"\t[*] UseSupervisor: %llx\n"
			"\t[*] Value: %llx\n",
			PhysPML4.PhysicalAddress.QuadPart,
			PML4ERaw->Accessed, PML4ERaw->ExecuteDisable, PML4ERaw->PageCacheDisable,
			PML4ERaw->PageFrameNumber, PML4ERaw->PageSize, PML4ERaw->PageWriteThrough,
			PML4ERaw->Present, PML4ERaw->ProtectionKey, PML4ERaw->ReadWrite, PML4ERaw->UserSupervisor, PML4ERaw->Value);
		DbgPrint("[+] PDPTE Raw - Virtual: 0x%llx\n"
			"\t[*] Accessed: %llu\n"
			"\t[*] ExecuteDisable: %llu\n"
			"\t[*] PageCacheDisable: %llu\n"
			"\t[*] PageSize: %llu\n"
			"\t[*] PageWriteThrough: %llu\n"
			"\t[*] Present: %llu\n"
			"\t[*] PAT: %llu\n"
			"\t[*] ReadWrite: %llu\n"
			"\t[*] UserSupervisor: %llu\n"
			"\t[*] Value: %llx\n"
			"\t[*] PageFrameNumber: %llx\n",
			PhysPDPT.PhysicalAddress.QuadPart,
			(unsigned long long)PDPTERaw->Accessed,
			(unsigned long long)PDPTERaw->ExecuteDisable,
			(unsigned long long)PDPTERaw->PageCacheDisable,
			(unsigned long long)PDPTERaw->PageSize,
			(unsigned long long)PDPTERaw->PageWriteThrough,
			(unsigned long long)PDPTERaw->Present,
			PDPTERaw->PageSize ? (unsigned long long)PDPTERaw->PAT : 0,
			(unsigned long long)PDPTERaw->ReadWrite,
			(unsigned long long)PDPTERaw->UserSupervisor,
			PDPTERaw->Value,
			(unsigned long long)PDPTERaw->PageFrameNumber);
		DbgPrint("[*] PDPTE PAT-Index -> PAT: %d | PCD: %d | PWT: %d -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
			PDPTERaw->PageSize ? (int)PDPTERaw->PAT : -1,
			(int)PDPTERaw->PageCacheDisable,
			(int)PDPTERaw->PageWriteThrough,
			PDPTERaw->PageSize ?
			((unsigned long long)PDPTERaw->PAT << 2) | ((unsigned long long)PDPTERaw->PageCacheDisable << 1) | (unsigned long long)PDPTERaw->PageWriteThrough :
			(unsigned long long) - 1,
			IA32_PAT_MSR);
		if (PDERaw != 0x0) {
			DbgPrint("[+] PDE Raw - Virtual: 0x%llx\n"
				"\t[*] Accessed: %llx\n"
				"\t[*] Ignored1: %llx\n"
				"\t[*] Ignored2: %llx\n"
				"\t[*] ExecuteDisable: %llx\n"
				"\t[*] PageCacheDisable: %llx\n"
				"\t[*] PageFrameNumber: %llx\n"
				"\t[*] PageSize: %llx\n"
				"\t[*] PageWriteThrough: %llx\n"
				"\t[*] PAT: %llx\n"
				"\t[*] Present: %llx\n"
				"\t[*] ReadWrite: %llx\n"
				"\t[*] Reserved: %llx\n"
				"\t[*] UserSupervisor: %llx\n"
				"\t[*] Ignored3: %llx\n"
				"\t[*] Value: %llx\n",
				PhysPD.PhysicalAddress.QuadPart,
				PDERaw->Accessed, PDERaw->AVL, PDERaw->Ignored2,
				PDERaw->ExecuteDisable, PDERaw->PageCacheDisable, PDERaw->PageFrameNumber,
				PDERaw->PageSize, PDERaw->PageWriteThrough, PDERaw->PAT,
				PDERaw->Present, PDERaw->ReadWrite, PDERaw->Reserved,
				PDERaw->UserSupervisor, PDERaw->Ignored3, PDERaw->Value);
			DbgPrint("[*] PDE PAT-Index -> PAT: %d | PCD: %d | PWT: %d -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
				PDERaw->PAT, PDERaw->PageCacheDisable, PDERaw->PageWriteThrough,
				(PDERaw->PAT << 2) | (PDERaw->PageCacheDisable << 1) | PDERaw->PageWriteThrough,
				IA32_PAT_MSR);
			if (PTERaw != 0x0) {
				// For lines where PTERaw->PageAccessType is referenced:
				DbgPrint("[+] PTE Raw - Virtual: 0x%llx\n"
					"\t[*] Accessed: %llu\n"
					"\t[*] Dirty: %llu\n"
					"\t[*] ExecuteDisable: %llu\n"
					"\t[*] Global: %llu\n"
					"\t[*] PAT: %llu\n"
					"\t[*] PageCacheDisable: %llu\n"
					"\t[*] PageFrameNumber: %llu\n"
					"\t[*] PageWriteThrough: %llu\n"
					"\t[*] Present: %llu\n"
					"\t[*] ProtectionKey: %llu\n"
					"\t[*] ReadWrite: %llu\n"
					"\t[*] UserSupervisor: %llu\n"
					"\t[*] COW: %llx\n",
					"\t[*] Value: %llx\n",
					PhysPage.PhysicalAddress.QuadPart,
					PTERaw->Accessed, PTERaw->Dirty, PTERaw->ExecuteDisable, PTERaw->Global, PTERaw->PAT, PTERaw->PageCacheDisable, PTERaw->PageFrameNumber, PTERaw->PageWriteThrough, PTERaw->Present,
					PTERaw->ProtectionKey, PTERaw->ReadWrite, PTERaw->UserSupervisor, PTERaw->COW, PTERaw->Value);
				DbgPrint("[*] PTE PAT-Index -> PAT: %llu | PCD: %llu | PWT: %llu -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
					PTERaw->PAT, PTERaw->PageCacheDisable, PTERaw->PageWriteThrough,
					(PTERaw->PAT << 2) | (PTERaw->PageCacheDisable << 1) | PTERaw->PageWriteThrough, IA32_PAT_MSR);
				DbgPrint("[+] PHYS 4KB-\n"
					"\t[*] Offset: %llx\n"
					"\t[*] PageNumber: %llx\n"
					"\t[*] Value: %llx\n",
					PHYSRaw4KB->Offset, PHYSRaw4KB->PageNumber, PHYSRaw4KB->Value);
			}
			else {
				DbgPrint("[+] PHYS 2MB-\n"
					"\t[*] Offset: %llx\n"
					"\t[*] PageNumber: %llx\n"
					"\t[*] Value: %llx\n",
					PHYSRaw2MB->Offset, PHYSRaw2MB->PageNumber, PHYSRaw2MB->Value);
			}
		}
		else {
			DbgPrint("[+] PHYS 1GB-\n"
				"\t[*] Offset: %llx\n"
				"\t[*] PageNumber: %llx\n"
				"\t[*] Value: %llx\n",
				PHYSRaw1GB->Offset, PHYSRaw1GB->PageNumber, PHYSRaw1GB->Value);
		}
	}
	PTE* retVal = MmGetVirtualForPhysical(Phys.PhysicalAddress);
	if (MmIsAddressValid(retVal) == FALSE) {
		DbgPrint("[-] VirtToPhys: Invalid address: 0x%llx\n", retVal);
		KeUnstackDetachProcess(&ApcState);
		return 0x0; // Return 0 if the address is invalid
	}
	KeUnstackDetachProcess(&ApcState);
	return retVal->Value; // Return the physical address
}
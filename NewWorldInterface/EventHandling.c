#include <ntifs.h>
// ---
#include "EventHandling.h"


VOID WorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
		if (NT_SUCCESS(status)) {
			DbgPrint("[+] Event signaled\n");
		}
		else {
			DbgPrint("[-] WorkerThread Failed to wait for event: %08X\n", status);
		}
		g_StopRequested = TRUE;
		pEvent->Header.SignalState = 0; // Reset the event
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID LinkWorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		pEvent->Header.SignalState = 0; // Reset the event
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] LinkWorkerThread Failed to wait for event: %08X\n", status);
			break;
		}
		// check if gInit.sourceProcess and gInit.targetProcess contains data or is filled with null-bytes
		if (gInit.sourceProcess[0] == '\0' || gInit.targetProcess[0] == '\0') {
			DbgPrint("[-] LinkWorkerThread: sourceProcess or targetProcess is invalid (empty)\n");
			break;
		}

		gSourceProcess = GetProcessByName(gInit.sourceProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
		PEPROCESS pTargetProcess = GetProcessByName(gInit.targetProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
		unsigned long long targetCR3 = GetDirectoryTableBaseByName(gInit.targetProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks, gSymInfo.KPROCDirectoryTableBase);
		unsigned long long sourceCR3 = GetDirectoryTableBaseByName(gInit.sourceProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks, gSymInfo.KPROCDirectoryTableBase);
		if (gInit.targetVPN != 0x0) {
			PVOID targetVA = gInit.targetVPN * 0x1000;
			DbgPrint("[+] LinkWorkerThread called\n");
			DbgPrint("    sourceVA:  0x%llx\n", gInit.sourceVA);
			DbgPrint("    targetCR3: 0x%llx\n", targetCR3);
			DbgPrint("    sourceCR3: 0x%llx\n", sourceCR3);
			//VirtToPhys(gInit.sourceVA, gSourceProcess, sourceCR3, TRUE);
			ChangeRef(gInit.sourceVA, gSourceProcess, sourceCR3, targetVA, pTargetProcess, targetCR3);
		}
		else {
			DbgPrint("[-] LinkWorkerThread: targetVPN is invalid (0x0)\n");
			break;
		}
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}
VOID UnlinkWorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		pEvent->Header.SignalState = 0; // Reset the event
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] UnlinkWorkerThread, Failed to wait for event: %08X\n", status);
			break;
		}
		if (gOrigVal != 0x0 && gOrigPhys.QuadPart != 0x0 && gSourceProcess != NULL) {
			PKAPC_STATE ApcState;
			KeStackAttachProcess(gSourceProcess, &ApcState);
			PVOID* temp = MmGetVirtualForPhysical(gOrigPhys);
			memcpy(temp, &gOrigVal, sizeof(gOrigVal));
			unsigned long long curVal = *temp;
			if (curVal != 0x0) {
				if (curVal == gOrigVal) {
					DbgPrint("[+] Successfully restored all modified PTEs to their original values\n");
				}
				else {
					DbgPrint("[-] Failed to restore modified PTEs\n");
				}
			}
			else {
				DbgPrint("[-] MmGetVirtualForPhysical has no content\n");
			}
			KeUnstackDetachProcess(&ApcState);
		}
		else {
			DbgPrint("[-] No modified PTEs to restore\n");
		}

		ZwClose(hEventLINK);
		ZwClose(hEventUnlink);
		ZwClose(hEventINIT);
		ZwClose(hEventUSERMODEREADY);
		ZwClose(hEventWRITE_PHYS);
		ZwClose(hEventREAD_PHYS);

		ZwUnmapViewOfSection(ZwCurrentProcess(), hInSection);
		ZwClose(hInSection);

		DbgPrint("[+] Freeing space...\n");
		ZwUnmapViewOfSection(ZwCurrentProcess(), gpDeviceContext->hSection);
		ZwClose(gpDeviceContext->hSection);

		DbgPrint("[+] Freeing space for FileName...\n");
		ZwUnmapViewOfSection(ZwCurrentProcess(), gpDeviceContext->hSectionFileName);
		ZwClose(gpDeviceContext->hSectionFileName);

		DbgPrint("[+] Freeing space for WritePhysical...\n");
		ZwUnmapViewOfSection(ZwCurrentProcess(), &gWritePhysSection);
		ZwClose(hWritePhysSection);

		DbgPrint("[+] Freeing space for ReadPhysical...\n");
		ZwUnmapViewOfSection(ZwCurrentProcess(), gReadPhysSection);
		ZwClose(hReadPhysSection);
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}
VOID UserModeReadWorkerThread(PVOID Context) {
	g_StopRequested = FALSE;
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		pEvent->Header.SignalState = 0; // Reset the event
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL); // TODO: perhaps change to WaitForMultipleObjects
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] UserModeReadWorkerThread Failed to wait for event: %08X\n", status);
			break;
		}

		// check if gInit.sourceProcess and gInit.targetProcess contains data or is filled with null-bytes
		if (gInit.targetProcess[0] == '\0') {
			DbgPrint("[-] UserModeReadWorkerThread: targetProcess is invalid (empty)\n");
			break;
		}

		// Make sure section is not getting paged-out | VAD Node Info - Memory Section
		DbgPrint("[+] Allocating MDL for section\n");
		gpDeviceContext->pMdl = IoAllocateMdl(gSection, gViewSize, FALSE, FALSE, NULL);

		DbgPrint("[+] Source Process: %s\n", gInit.sourceProcess);
		DbgPrint("[+] Target Process: %s\n", gInit.targetProcess);
		gSourceProcess = GetProcessByName(gInit.sourceProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
		PEPROCESS pTargetProcess = GetProcessByName(gInit.targetProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);

		RtlZeroMemory(gFileNameSection, gFileNameViewSize);
		RtlZeroMemory(gSection, gViewSize);
		if (pTargetProcess != NULL) {
			WalkVAD(pTargetProcess, gSymInfo.VADRoot, gSymInfo.StartingVpnOffset, gSymInfo.EndingVpnOffset,
				gSymInfo.Left, gSymInfo.Right, gSymInfo.MMVADSubsection, gSymInfo.MMVADControlArea,
				gSymInfo.MMVADCAFilePointer, gSymInfo.FILEOBJECTFileName, 0x0);
		}
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID INITWorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	int test;
	while (!g_StopRequested) {
		pEvent->Header.SignalState = 0; // Reset the event
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL); // TODO: perhaps change to WaitForMultipleObjects
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] UserModeReadWorkerThread Failed to wait for event: %08X\n", status);
			break;
		}
		if (pInSection == NULL) {
			status = ZwMapViewOfSection(hInSection, ZwCurrentProcess(), &pInSection,
				0, 0, NULL, &gSymsViewSize, ViewShare,
				0, PAGE_READONLY);
			if (!NT_SUCCESS(status)) {
				DbgPrint("[-] Failed to map view of input section: %08X\n", status);
				ZwClose(hInSection);
				IoDeleteSymbolicLink(&usSymbolicLinkName);
				IoDeleteDevice(gpDeviceObject);
				return status;
			}
			DbgPrint("[+] Initializing Sym Info\n");
			if (!InitSymInfo()) {
				DbgPrint("[-] Failed to initialize symbol information\n");
				return STATUS_UNSUCCESSFUL;
			}
		}
		DbgPrint("[+] Initializing INIT Data %llx\n", status);
		if (!InitData()) {
			DbgPrint("[-] Failed to initialize data\n");
			return STATUS_UNSUCCESSFUL;
		}
		else {
			if (gSourceProcess != NULL && gInit.requestedProtection != 0x0) {
				ChangeMemoryProtection(gSourceProcess, gInit.sourceVA, 4096, gInit.requestedProtection);
				gInit.requestedProtection = 0x0;
			}
			else {
				DbgPrint("Skip protect\n");
			}
		}
		DbgPrint("[+] Finished initializing data and symbol information\n");
		DbgPrint("[+] Source Process: %s\n", gInit.sourceProcess);
		DbgPrint("[+] Target Process: %s\n", gInit.targetProcess);
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID WritePhysicalWorkerThread(PVOID Context) {
    PKEVENT pEvent = (PKEVENT)Context;
    while (!g_StopRequested) {
        pEvent->Header.SignalState = 0; // Reset the event
        NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] WritePhysicalWorkerThread Failed to wait for event: %08X\n", status);
            break;
        }

        if (&gWritePhysSection == NULL) {
            DbgPrint("[-] WritePhysicalWorkerThread: gWritePhysSection is NULL\n");
            continue;
        }

        // Cast to our write request structure
        //PWRITE_PHYS_REQUEST writeRequest = (PWRITE_PHYS_REQUEST)&gWritePhysSection;
        
        // Create a local copy of the WRITE_PHYS_REQUEST structure and copy the content from gWritePhysSection
        WRITE_PHYS_REQUEST writeRequestCopy;
        writeRequestCopy = *(PWRITE_PHYS_REQUEST)gWritePhysSection;
        // TEST START
        PEPROCESS pTargetProcess = GetProcessByName(gInit.targetProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
        if (pTargetProcess == NULL) {
			DbgPrint("[-] WritePhysicalWorkerThread: Failed to get target process by name: %s\n", gInit.targetProcess);
            continue;
        }
        unsigned long long targetCR3 = GetDirectoryTableBaseByName(gInit.targetProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks, gSymInfo.KPROCDirectoryTableBase);
        unsigned long long targetVA = writeRequestCopy.targetVA;

		DbgPrint("[+] pTargetProcess: %s\n", gInit.targetProcess);
		DbgPrint("[+] targetCR3: 0x%llx\n", targetCR3);
        
        PHYSICAL_ADDRESS targetPhysicalAddress = { 0 };
        KAPC_STATE ApcState;
        SIZE_T numRec = 0;

        MM_COPY_ADDRESS PhysPML4 = { 0 };
		MM_COPY_ADDRESS PhysPDPT = { 0 };
		MM_COPY_ADDRESS PhysPD = { 0 };
		MM_COPY_ADDRESS PhysPage = { 0 };
		MM_COPY_ADDRESS Phys = { 0 };

		unsigned long long PML4Offset;
		unsigned long long PDPTOffset;
		unsigned long long PDOffset;
		unsigned long long PTOffset;
		unsigned long long MaskOffset;

        unsigned long long temp = 0x0;
        unsigned long long pml4e = 0x0;
		unsigned long long pdpte = 0x0;
		unsigned long long pde = 0x0;
		unsigned long long pte = 0x0;
        unsigned long long physAdr = 0x0;

        PML4E* PML4ERaw = 0x0;
		PDPTE* PDPTERaw = 0x0;
		PDE* PDERaw = 0x0;
		PTE* PTERaw = 0x0;
		PHYSICAL_1GB* PHYSRaw1GB = 0x0;
		PHYSICAL_2MB* PHYSRaw2MB = 0x0;
		PHYSICAL_4KB* PHYSRaw4KB = 0x0;

        KeStackAttachProcess(pTargetProcess, &ApcState);

        PML4Offset = (targetVA & 0xFF8000000000) >> 0x27;
        PDPTOffset = (targetVA & 0x7FC0000000) >> 0x1E;
        PDOffset = (targetVA & 0x3FE00000) >> 0x15;
        PTOffset = (targetVA & 0x1FF000) >> 0x0C;
        MaskOffset = (targetVA & 0xFFF);

        PhysPML4.PhysicalAddress.QuadPart = targetCR3 + (PML4Offset * 0x08);
		status = MmCopyMemory(&pml4e, PhysPML4, sizeof(pml4e), MM_COPY_MEMORY_PHYSICAL, &numRec);
        pml4e = pml4e & 0xFFFFFFFFFFFF;
        PML4ERaw = (PML4E*)&pml4e;
        DbgPrint("[+] PML4E Raw - Virtual: 0x%llx\n", pml4e);

        PhysPDPT.PhysicalAddress.QuadPart = (pml4e & 0xFFFFF000) + (PDPTOffset * 0x08);
        status = MmCopyMemory(&pdpte, PhysPDPT, sizeof(pdpte), MM_COPY_MEMORY_PHYSICAL, &numRec);
        pdpte = pdpte & 0xFFFFFFFFFFFF;
        PDPTERaw = (PDPTE*)&pdpte;
		DbgPrint("[+] PDPTE Raw - Virtual: 0x%llx\n", pdpte);

        if (PDPTERaw->PageSize == 0) {
            PhysPD.PhysicalAddress.QuadPart = (pdpte & 0xFFFFF000) + (PDOffset * 0x08);
            status = MmCopyMemory(&pde, PhysPD, sizeof(pde), MM_COPY_MEMORY_PHYSICAL, &numRec);
            PDERaw = (PDE*)&pde;
            pde = pde & 0xFFFFFFFFFFFF;
            PDERaw = (PDE*)&pde;
			DbgPrint("[+] PDE Raw - Virtual: 0x%llx\n", pde);

            if (PDERaw->PageSize == 0) {
                PhysPage.PhysicalAddress.QuadPart = (pde & 0xFFFFF000) + (PTOffset * 0x08);
                Phys.PhysicalAddress.QuadPart = PhysPage.PhysicalAddress.QuadPart + MaskOffset;
                status = MmCopyMemory(&pte, PhysPage, sizeof(pte), MM_COPY_MEMORY_PHYSICAL, &numRec);
				DbgPrint("[+] PTE Raw - Virtual: 0x%llx\n", pte);
            } else {
				PHYSRaw2MB = (PHYSICAL_2MB*)&pde;
				DbgPrint("[+] PHYSRaw2MB - Virtual: 0x%llx\n", pde);
            }
        } else {
			PHYSRaw1GB = (PHYSICAL_1GB*)&pdpte;
			DbgPrint("[+] PHYSRaw1GB - Virtual: 0x%llx\n", pdpte);
        }

        KeUnstackDetachProcess(&ApcState);

        targetPhysicalAddress.QuadPart = pte + writeRequestCopy.offsetInPage;
		DbgPrint("[+] TargetVA: 0x%llx\n", targetVA);
		DbgPrint("[+] WritePhysicalWorkerThread: Writing %zu bytes to physical address 0x%llx (base: 0x%llx, offset: %llu)\n",
                 writeRequestCopy.dataSize, targetPhysicalAddress.QuadPart,
                 pte, writeRequestCopy.offsetInPage);

        SIZE_T bytesWritten = 0;
		status = WritePhysicalAddress((PVOID)targetPhysicalAddress.QuadPart, writeRequestCopy.data, writeRequestCopy.dataSize, &bytesWritten);
        if (NT_SUCCESS(status)) {
            DbgPrint("[+] WritePhysicalWorkerThread: Successfully wrote %zu bytes to physical memory at 0x%llx\n", bytesWritten, targetPhysicalAddress.QuadPart);
            // Mark request as processed
            writeRequestCopy.isValid = FALSE;
            RtlZeroMemory(gWritePhysSection, sizeof(WRITE_PHYS_REQUEST));
        } else {
            DbgPrint("[-] WritePhysicalWorkerThread: Failed to write to physical memory: %08X\n", status);
            // Clear the section on error
            RtlZeroMemory(gWritePhysSection, sizeof(WRITE_PHYS_REQUEST));
		}
        
        // TEST END
        //DbgPrint("&gWritePhysSection: 0x%llx\n", &gWritePhysSection);
        //DbgPrint("targetPhysicalAddress: 0x%llx\n", writeRequestCopy.targetPhysicalAddress.QuadPart);
        ////RtlCopyMemory(&writeRequestCopy, gWritePhysSection, sizeof(WRITE_PHYS_REQUEST));
        //if (MmIsAddressValid(&gWritePhysSection) == FALSE) {
        //    DbgPrint("[-] writeRequestCopy is not a valid address: 0x%llx\n", &gWritePhysSection);
        //    DbgPrint("[-] WritePhysicalWorkerThread: Invalid write request address\n");
        //    continue;
        //}
        //
        //// Validate the request using the original pointer
        //if (!writeRequestCopy.isValid) {
        //    DbgPrint("[-] WritePhysicalWorkerThread: Invalid write request\n");
        //    continue;
        //}

        //// Check identifier using the copy
        //if (memcmp(writeRequestCopy.identifier, "WPHY", 4) != 0) {
        //    DbgPrint("[-] WritePhysicalWorkerThread: Invalid identifier\n");
        //    continue;
        //}

        //// Validate offset and size to ensure we don't exceed page boundary using the copy
        //if (writeRequestCopy.offsetInPage >= PAGE_SIZE) {
        //    DbgPrint("[-] WritePhysicalWorkerThread: Offset exceeds page size (%lu)\n", writeRequestCopy.offsetInPage);
        //    continue;
        //}

        //if (writeRequestCopy.dataSize == 0 || writeRequestCopy.dataSize > MAX_WRITE_BUFFER_SIZE) {
        //    DbgPrint("[-] WritePhysicalWorkerThread: Invalid data size (%lu)\n", writeRequestCopy.dataSize);
        //    continue;
        //}

        //// Check if write would exceed page boundary
        //if ((writeRequestCopy.offsetInPage + writeRequestCopy.dataSize) > PAGE_SIZE) {
        //    DbgPrint("[-] WritePhysicalWorkerThread: Write would exceed page boundary. Offset: %lu, Size: %lu\n", 
        //             writeRequestCopy.offsetInPage, writeRequestCopy.dataSize);
        //    // Truncate the write to stay within page boundary
        //    writeRequestCopy.dataSize = PAGE_SIZE - writeRequestCopy.offsetInPage;
        //    DbgPrint("[!] WritePhysicalWorkerThread: Truncated write size to %lu bytes\n", writeRequestCopy.dataSize);
        //}

        //// Calculate the actual target physical address with offset
        //PHYSICAL_ADDRESS targetAddress;
        //targetAddress.QuadPart = writeRequestCopy.targetPhysicalAddress.QuadPart + writeRequestCopy.offsetInPage;

        //DbgPrint("[+] WritePhysicalWorkerThread: Writing %lu bytes to physical address 0x%llx (base: 0x%llx, offset: %lu)\n",
        //         writeRequestCopy.dataSize, targetAddress.QuadPart, 
        //         writeRequestCopy.targetPhysicalAddress.QuadPart, writeRequestCopy.offsetInPage);

        //// Perform the write operation using the copied data
        //SIZE_T bytesWritten = 0;
        //status = WritePhysicalAddress((PVOID)targetAddress.QuadPart, writeRequestCopy.data, writeRequestCopy.dataSize, &bytesWritten);
        //
        //if (NT_SUCCESS(status)) {
        //    DbgPrint("[+] WritePhysicalWorkerThread: Successfully wrote %zu bytes to physical memory\n", bytesWritten);
        //    // Mark request as processed using the original pointer
        //    writeRequestCopy.isValid = FALSE;
        //    //RtlZeroMemory(gWritePhysSection.identifier, 4);
        //    // Clear the local copy
        //    RtlZeroMemory(gWritePhysSection, sizeof(WRITE_PHYS_REQUEST));
        //    RtlZeroMemory(&writeRequestCopy, sizeof(WRITE_PHYS_REQUEST));
        //} else {
        //    DbgPrint("[-] WritePhysicalWorkerThread: Failed to write to physical memory: %08X\n", status);
        //    // Clear both the original structure and the copy on error
        //    RtlZeroMemory(gWritePhysSection, sizeof(WRITE_PHYS_REQUEST));
        //    RtlZeroMemory(&writeRequestCopy, sizeof(WRITE_PHYS_REQUEST));
        //    //RtlZeroMemory(&writeRequestCopy, sizeof(WRITE_PHYS_REQUEST));
        //}
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID ReadPhysicalWorkerThread(PVOID Context) {
    PKEVENT pEvent = (PKEVENT)Context;
    while (!g_StopRequested) {
        pEvent->Header.SignalState = 0; // Reset the event
        NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] ReadPhysicalWorkerThread Failed to wait for event: %08X\n", status);
            break;
        }

        if (gReadPhysSection == NULL) {
            DbgPrint("[-] ReadPhysicalWorkerThread: gReadPhysSection is NULL\n");
            continue;
        }

        // Cast to our read request structure
        PREAD_PHYS_REQUEST readRequest = (PREAD_PHYS_REQUEST)gReadPhysSection;

		// Create a new READ_PHYS_REQUEST structure and copy the content from gReadPhysSection
		READ_PHYS_REQUEST readRequestCopy;

		RtlCopyMemory(&readRequestCopy, gReadPhysSection, sizeof(READ_PHYS_REQUEST));

        if (MmIsAddressValid(&readRequestCopy) == FALSE) {
            DbgPrint("[-] readRequest is not a valid address: 0x%llx\n", &readRequestCopy);
            DbgPrint("[-] ReadPhysicalWorkerThread: Invalid read request address\n");
            continue;
        }
        
        // Validate the request
        if (!readRequest->isValid) {
            DbgPrint("[-] ReadPhysicalWorkerThread: Invalid read request\n");
            continue;
        }

        // Check identifier
        if (memcmp(readRequestCopy.identifier, "RPHY", 4) != 0) {
            DbgPrint("[-] ReadPhysicalWorkerThread: Invalid identifier\n");
            continue;
        }

        // Validate target virtual address
        if (readRequestCopy.targetVirtualAddress == NULL) {
            DbgPrint("[-] ReadPhysicalWorkerThread: Invalid target virtual address\n");
            continue;
        }

        // Get target process from gInit
        if (gInit.targetProcess[0] == '\0') {
            DbgPrint("[-] ReadPhysicalWorkerThread: targetProcess is invalid (empty)\n");
            continue;
        }

        // Get the target process and its CR3
        PEPROCESS pTargetProcess = GetProcessByName(gInit.targetProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
        if (pTargetProcess == NULL) {
            DbgPrint("[-] ReadPhysicalWorkerThread: Failed to get target process '%s'\n", gInit.targetProcess);
            continue;
        }

        unsigned long long targetCR3 = GetDirectoryTableBaseByName(gInit.targetProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks, gSymInfo.KPROCDirectoryTableBase);
        if (targetCR3 == 0) {
            DbgPrint("[-] ReadPhysicalWorkerThread: Failed to get CR3 for target process '%s'\n", gInit.targetProcess);
            continue;
        }

        DbgPrint("[+] ReadPhysicalWorkerThread: Processing virtual address 0x%llx for process '%s'\n", 
            readRequestCopy.targetVirtualAddress, gInit.targetProcess);

        // Resolve virtual address to physical address using existing VirtToPhys function
        // Note: VirtToPhys returns PTE value, we need to extract the physical address from it
        KAPC_STATE ApcState;
        KeStackAttachProcess(pTargetProcess, &ApcState);

        // Use the virtual address translation logic from ChangeRef
        unsigned long long VA = readRequestCopy.targetVirtualAddress;
        unsigned long long PML4Offset = (VA & 0xFF8000000000) >> 0x27;
        unsigned long long PDPTOffset = (VA & 0x7FC0000000) >> 0x1E;
        unsigned long long PDOffset = (VA & 0x3FE00000) >> 0x15;
        unsigned long long PTOffset = (VA & 0x1FF000) >> 0x0C;
        unsigned long long PageOffset = (VA & 0xFFF);

        MM_COPY_ADDRESS PhysPML4 = { 0 };
        MM_COPY_ADDRESS PhysPDPT = { 0 };
        MM_COPY_ADDRESS PhysPD = { 0 };
        MM_COPY_ADDRESS PhysPage = { 0 };

        unsigned long long pml4e = 0x0;
        unsigned long long pdpte = 0x0;
        unsigned long long pde = 0x0;
        unsigned long long pte = 0x0;
        SIZE_T numRec = 0;
        PHYSICAL_ADDRESS physicalPageBase = { 0 };

        // Walk page tables to get physical address
        PhysPML4.PhysicalAddress.QuadPart = targetCR3 + (PML4Offset * 0x08);
        status = MmCopyMemory(&pml4e, PhysPML4, sizeof(pml4e), MM_COPY_MEMORY_PHYSICAL, &numRec);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] ReadPhysicalWorkerThread: Failed to read PML4E: %08X\n", status);
            KeUnstackDetachProcess(&ApcState);
            continue;
        }
        pml4e = pml4e & 0xFFFFFFFFFFFF;
        PML4E* PML4ERaw = (PML4E*)&pml4e;
        if (!PML4ERaw->Present) {
            DbgPrint("[-] ReadPhysicalWorkerThread: PML4E not present\n");
            KeUnstackDetachProcess(&ApcState);
            continue;
        }

        PhysPDPT.PhysicalAddress.QuadPart = (pml4e & 0xFFFFF000) + (PDPTOffset * 0x08);
        status = MmCopyMemory(&pdpte, PhysPDPT, sizeof(pdpte), MM_COPY_MEMORY_PHYSICAL, &numRec);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] ReadPhysicalWorkerThread: Failed to read PDPTE: %08X\n", status);
            KeUnstackDetachProcess(&ApcState);
            continue;
        }
        pdpte = pdpte & 0xFFFFFFFFFFFF;
        PDPTE* PDPTERaw = (PDPTE*)&pdpte;
        if (!PDPTERaw->Present) {
            DbgPrint("[-] ReadPhysicalWorkerThread: PDPTE not present\n");
            KeUnstackDetachProcess(&ApcState);
            continue;
        }

        if (PDPTERaw->PageSize == 0) {
            // 4KB or 2MB page
            PhysPD.PhysicalAddress.QuadPart = (pdpte & 0xFFFFF000) + (PDOffset * 0x08);
            status = MmCopyMemory(&pde, PhysPD, sizeof(pde), MM_COPY_MEMORY_PHYSICAL, &numRec);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[-] ReadPhysicalWorkerThread: Failed to read PDE: %08X\n", status);
                KeUnstackDetachProcess(&ApcState);
                continue;
            }
            pde = pde & 0xFFFFFFFFFFFF;
            PDE* PDERaw = (PDE*)&pde;
            if (!PDERaw->Present) {
                DbgPrint("[-] ReadPhysicalWorkerThread: PDE not present\n");
                KeUnstackDetachProcess(&ApcState);
                continue;
            }

            if (PDERaw->PageSize == 0) {
                // 4KB page
                PhysPage.PhysicalAddress.QuadPart = (pde & 0xFFFFF000) + (PTOffset * 0x08);
                status = MmCopyMemory(&pte, PhysPage, sizeof(pte), MM_COPY_MEMORY_PHYSICAL, &numRec);
                if (!NT_SUCCESS(status)) {
                    DbgPrint("[-] ReadPhysicalWorkerThread: Failed to read PTE: %08X\n", status);
                    KeUnstackDetachProcess(&ApcState);
                    continue;
                }
                pte = pte & 0xFFFFFFFFFFFF;
                PTE* PTERaw = (PTE*)&pte;
                if (!PTERaw->Present) {
                    DbgPrint("[-] ReadPhysicalWorkerThread: PTE not present\n");
                    KeUnstackDetachProcess(&ApcState);
                    continue;
                }

                // Calculate physical address of the page
                physicalPageBase.QuadPart = (PTERaw->PageFrameNumber << 12);
            } else {
                // 2MB page
                physicalPageBase.QuadPart = (PDERaw->PageFrameNumber << 12);
            }
        } else {
            // 1GB page
            physicalPageBase.QuadPart = (PDPTERaw->PageFrameNumber << 12);
        }

        KeUnstackDetachProcess(&ApcState);

        DbgPrint("[+] ReadPhysicalWorkerThread: Virtual address 0x%llx resolves to physical page 0x%llx\n",
                 VA, physicalPageBase.QuadPart);

        // Read the entire 4KB page from physical memory
        SIZE_T bytesRead = 0;
        status = ReadPhysicalAddress((PVOID)physicalPageBase.QuadPart, readRequest->pageData, PAGE_SIZE, &bytesRead);
        
        if (NT_SUCCESS(status)) {
            DbgPrint("[+] ReadPhysicalWorkerThread: Successfully read %zu bytes from physical memory\n", bytesRead);
            // Clear the request identifier but keep the data
            RtlZeroMemory(readRequest->identifier, 4);
			RtlZeroMemory(&readRequestCopy, sizeof(READ_PHYS_REQUEST));
        } else {
            DbgPrint("[-] ReadPhysicalWorkerThread: Failed to read from physical memory: %08X\n", status);
            // Clear the entire structure on error
            RtlZeroMemory(readRequest, sizeof(READ_PHYS_REQUEST));
            RtlZeroMemory(&readRequestCopy, sizeof(READ_PHYS_REQUEST));
        }

        // Mark request as processed
        readRequest->isValid = FALSE;
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}
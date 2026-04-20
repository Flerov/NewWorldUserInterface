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
			continue; // keep thread alive
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
			continue; // keep thread alive
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
			KAPC_STATE ApcState; // must be KAPC_STATE (the struct), NOT PKAPC_STATE (a pointer)
			KeStackAttachProcess(gSourceProcess, &ApcState);
			PVOID temp = MmGetVirtualForPhysical(gOrigPhys);
			if (temp != NULL) {
				memcpy(temp, &gOrigVal, sizeof(gOrigVal));
				unsigned long long curVal = *(unsigned long long*)temp;
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
			} else {
				DbgPrint("[-] MmGetVirtualForPhysical returned NULL for phys=0x%llx\n",
					gOrigPhys.QuadPart);
			}
			KeUnstackDetachProcess(&ApcState);
		}
		else {
			DbgPrint("[-] No modified PTEs to restore\n");
		}

		// -------------------------------------------------------
		// Session reset — DO NOT close any kernel handles.
		// All named sections and events must remain open so a
		// restarted usermode can call OpenFileMappingW /
		// OpenEventW and reconnect without reloading the driver.
		// -------------------------------------------------------

		// Unmap the symbol-input view so INITWorkerThread remaps
		// it (and re-reads offsets) when the next INIT fires.
		if (pInSection != NULL) {
			ZwUnmapViewOfSection(ZwCurrentProcess(), pInSection);
			pInSection = NULL;
		}

		// Reset per-session state
		gSourceProcess      = NULL;
		gOrigVal            = 0x0;
		gOrigPhys.QuadPart  = 0;
		gSecVADIndex        = 0;
		gCurrFileNameOffset = 1;

		// Zero output buffers so stale data isn't shown on reconnect
		if (gSection)          RtlZeroMemory(gSection,          gViewSize);
		if (gFileNameSection)  RtlZeroMemory(gFileNameSection,  gFileNameViewSize);
		if (gVadModifySection) RtlZeroMemory(gVadModifySection, sizeof(VAD_MODIFY_REQUEST));

		// Zero INIT / symbol structs — will be repopulated on next INIT signal
		RtlZeroMemory(&gInit,    sizeof(gInit));
		RtlZeroMemory(&gSymInfo, sizeof(gSymInfo));

		DbgPrint("[+] UnlinkWorkerThread: session reset complete — driver ready for reconnect\n");
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}
VOID UserModeReadWorkerThread(PVOID Context) {
	// g_StopRequested is initialised to FALSE in DriverCore.c; do NOT reset it here —
	// DriverUnload may have already set it TRUE before this thread is scheduled.
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		// SynchronizationEvent: KeWaitForSingleObject atomically resets the event on wake.
		// Do NOT manually clear SignalState — that would discard any signal that arrived
		// while WalkVAD was running, causing subsequent '1' presses to appear to do nothing.
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] UserModeReadWorkerThread Failed to wait for event: %08X\n", status);
			break;
		}

		// Read walkMode directly from the live input section so a new mode written by '1'
		// is immediately honoured without requiring a new INIT event.
		UCHAR liveWalkMode = (pInSection != NULL) ? ((PINIT)pInSection)->walkMode : 0;

		// Verify the process required by the requested walk mode is configured
		if (liveWalkMode == 1) {
			if (gInit.sourceProcess[0] == '\0') {
				DbgPrint("[-] UserModeReadWorkerThread: sourceProcess not set (mode=source) — waiting\n");
				continue;
			}
		} else {
			if (gInit.targetProcess[0] == '\0') {
				DbgPrint("[-] UserModeReadWorkerThread: targetProcess not set — waiting\n");
				continue;
			}
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
		gSecVADIndex        = 0;
		gCurrFileNameOffset = 1;

		if (liveWalkMode == 1) {
				// Source process only
				if (gSourceProcess) {
					WalkVAD(gSourceProcess, gSymInfo.VADRoot, gSymInfo.StartingVpnOffset, gSymInfo.EndingVpnOffset,
						gSymInfo.Left, gSymInfo.Right, gSymInfo.MMVADSubsection, gSymInfo.MMVADControlArea,
						gSymInfo.MMVADCAFilePointer, gSymInfo.MMCAFlags, gSymInfo.FILEOBJECTFileName, 0x0);
					DbgPrint("[+] UserModeReadWorkerThread: source walk done, %zu entries\n", gSecVADIndex);
				}
			} else if (liveWalkMode == 2) {
				// Target first
				if (pTargetProcess) {
					WalkVAD(pTargetProcess, gSymInfo.VADRoot, gSymInfo.StartingVpnOffset, gSymInfo.EndingVpnOffset,
						gSymInfo.Left, gSymInfo.Right, gSymInfo.MMVADSubsection, gSymInfo.MMVADControlArea,
						gSymInfo.MMVADCAFilePointer, gSymInfo.MMCAFlags, gSymInfo.FILEOBJECTFileName, 0x0);
					DbgPrint("[+] UserModeReadWorkerThread: target walk done, %zu entries\n", gSecVADIndex);
				}
				// Sentinel: Level=-1, magic StartingVpn marks the boundary
				size_t maxSlots = gViewSize / sizeof(VAD_NODE);
				if (gSecVADIndex < maxSlots - 1) {
					PVAD_NODE sent = (PVAD_NODE)gSection + gSecVADIndex;
					RtlZeroMemory(sent, sizeof(VAD_NODE));
					sent->Level       = -1;
					sent->StartingVpn = 0xFFFFFFFFFFFFFFFEULL;
					gSecVADIndex++;
				}
				// Source second
				if (gSourceProcess) {
					WalkVAD(gSourceProcess, gSymInfo.VADRoot, gSymInfo.StartingVpnOffset, gSymInfo.EndingVpnOffset,
						gSymInfo.Left, gSymInfo.Right, gSymInfo.MMVADSubsection, gSymInfo.MMVADControlArea,
						gSymInfo.MMVADCAFilePointer, gSymInfo.MMCAFlags, gSymInfo.FILEOBJECTFileName, 0x0);
					DbgPrint("[+] UserModeReadWorkerThread: source walk done, %zu total entries\n", gSecVADIndex);
				}
			} else {
				// Target only (mode 0, default)
				if (pTargetProcess) {
					WalkVAD(pTargetProcess, gSymInfo.VADRoot, gSymInfo.StartingVpnOffset, gSymInfo.EndingVpnOffset,
						gSymInfo.Left, gSymInfo.Right, gSymInfo.MMVADSubsection, gSymInfo.MMVADControlArea,
						gSymInfo.MMVADCAFilePointer, gSymInfo.MMCAFlags, gSymInfo.FILEOBJECTFileName, 0x0);
					DbgPrint("[+] UserModeReadWorkerThread: target walk done, %zu entries\n", gSecVADIndex);
				}
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

// =================================================================
// VadInsertWorkerThread
// Waits for hEventVAD_INSERT. Reads a VAD_MODIFY_REQUEST with
// identifier "VINS", allocates a minimal MMVAD-compatible node,
// fills the VPN range and flags, then calls VadTreeInsert.
// Result NTSTATUS is written back to the request before isValid=FALSE.
// =================================================================
VOID VadInsertWorkerThread(PVOID Context) {
    PKEVENT          pEvent = (PKEVENT)Context;
    PVAD_MODIFY_REQUEST req;
    PEPROCESS        pTarget;
    PVOID            newNode;
    NTSTATUS         status;
    SIZE_T           nodeSize;
    unsigned long long qw;
    unsigned long long high;
    UCHAR            liveWalkMode;
    const char*      procName;

    while (!g_StopRequested) {
        pEvent->Header.SignalState = 0;
        status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] VadInsertWorkerThread: wait failed %08X\n", status);
            break;
        }

        if (!gVadModifySection) {
            DbgPrint("[-] VadInsertWorkerThread: gVadModifySection is NULL\n");
            continue;
        }

        req = (PVAD_MODIFY_REQUEST)gVadModifySection;

        if (!req->isValid) {
            DbgPrint("[-] VadInsertWorkerThread: isValid=FALSE, skipping\n");
            continue;
        }

        // ── QHNT: query VadFreeHint → return the suggested next-free StartingVpn ──
        if (memcmp(req->identifier, "QHNT", 4) == 0) {
            // Walk the same tree that was last populated: source for mode=1, target for mode=0/2
            liveWalkMode = (pInSection != NULL) ? ((PINIT)pInSection)->walkMode : 0;
            procName     = (liveWalkMode == 1) ? gInit.sourceProcess : gInit.targetProcess;
            PEPROCESS pQ = GetProcessByName(procName,
                gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
            if (!pQ) {
                DbgPrint("[-] QHNT: process '%s' not found\n", procName);
                req->Result  = STATUS_NOT_FOUND;
                req->isValid = FALSE;
                continue;
            }

            // The MMVAD stores only 40 bits of VPN (32-bit low + 8-bit high).
            // A user-mode process VAD tree has NO kernel-space nodes, so we can't
            // use the canonical hole as a split point.  Instead divide the 40-bit
            // VPN space in half:
            //   low  (≤ 0x3FFFFFFFF): private heap/stack/data allocations
            //   high (> 0x3FFFFFFFF): system DLL / high-VA area (0x7FF... range)
            // This naturally separates the two allocation zones in any user process.
            // For a kernel process walk, actual kernel VPNs (0xFFxx_xxxxxxxx after
            // 40-bit truncation) are >> 0x3FFFFFFFF and land in the high bucket too.
            #define USER_MAX_VPN   0x7FFFFFFFFull
            #define KERNEL_MIN_VPN 0x400000000ull  // upper half of 40-bit VPN space

            // Full in-order BST walk: track the maximum EndingVpn seen in each
            // address space independently.  Single pass, explicit stack.
            {
                PVOID* pVadRoot = (PVOID*)((ULONG_PTR)pQ + gSymInfo.VADRoot);
                PVOID  vadRoot  = (pVadRoot && MmIsAddressValid(pVadRoot)) ? *pVadRoot : NULL;

                unsigned long long maxUserEndVpn   = 0;
                unsigned long long maxKernelEndVpn = 0;

                #define QHNT_STACK_DEPTH 64
                PVOID qstack[QHNT_STACK_DEPTH];
                int   qtop = 0;
                PVOID cur  = vadRoot;

                while ((cur && MmIsAddressValid(cur)) || qtop > 0) {
                    while (cur && MmIsAddressValid(cur)) {
                        if (qtop < QHNT_STACK_DEPTH) qstack[qtop++] = cur;
                        cur = *(PVOID*)((ULONG_PTR)cur + gSymInfo.Left);
                    }
                    if (qtop == 0) break;
                    cur = qstack[--qtop];

                    ULONG endLow  = *(ULONG*)((ULONG_PTR)cur + gSymInfo.EndingVpnOffset);
                    UCHAR endHigh = *(UCHAR*)((ULONG_PTR)cur + gSymInfo.EndingVpnOffset + 5);
                    unsigned long long endVpn = (unsigned long long)endLow | ((unsigned long long)endHigh << 32);

                    if (endVpn >= KERNEL_MIN_VPN) {
                        if (endVpn > maxKernelEndVpn) maxKernelEndVpn = endVpn;
                    } else {
                        if (endVpn > maxUserEndVpn) maxUserEndVpn = endVpn;
                    }

                    cur = *(PVOID*)((ULONG_PTR)cur + gSymInfo.Right);
                }
                #undef QHNT_STACK_DEPTH

                // User suggestion
                if (maxUserEndVpn > 0 && (maxUserEndVpn + 1) <= USER_MAX_VPN)
                    req->SuggestedUserVpn = maxUserEndVpn + 1;
                else
                    req->SuggestedUserVpn = 0;

                // Kernel suggestion
                if (maxKernelEndVpn > 0) {
                    unsigned long long ksugg = maxKernelEndVpn + 1;
                    req->SuggestedKernelVpn = (ksugg >= KERNEL_MIN_VPN) ? ksugg : 0;
                } else {
                    req->SuggestedKernelVpn = 0;
                }

                DbgPrint("[+] QHNT: process='%s' userSugg=0x%llx kernelSugg=0x%llx\n",
                    procName, req->SuggestedUserVpn, req->SuggestedKernelVpn);
            }

            req->Result  = STATUS_SUCCESS;
            req->isValid = FALSE;
            continue;
        }

        if (memcmp(req->identifier, "VINS", 4) != 0) {
            DbgPrint("[-] VadInsertWorkerThread: unknown identifier, discarding\n");
            req->Result  = STATUS_INVALID_PARAMETER;
            req->isValid = FALSE;
            continue;
        }

        // Insert into the same process whose tree was last walked
        liveWalkMode = (pInSection != NULL) ? ((PINIT)pInSection)->walkMode : 0;
        procName     = (liveWalkMode == 1) ? gInit.sourceProcess : gInit.targetProcess;
        pTarget = GetProcessByName(procName,
            gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
        if (!pTarget) {
            DbgPrint("[-] VadInsertWorkerThread: process '%s' not found\n", procName);
            req->Result  = STATUS_NOT_FOUND;
            req->isValid = FALSE;
            continue;
        }

        // ── Step 1: allocate and initialise node ─────────────────────────
        // Done before acquiring the lock because ExAllocatePool2 can block.
        nodeSize = req->NodeSize ? req->NodeSize : 0x80;
        newNode  = NULL;
        status   = VadAllocateNode(nodeSize, &newNode);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] VadInsertWorkerThread: VadAllocateNode failed %08X\n", status);
            req->Result  = status;
            req->isValid = FALSE;
            continue;
        }

        // Encode StartingVpn / EndingVpn at StartingVpnOffset
        qw   = (req->StartingVpn & 0xFFFFFFFF) | ((req->EndingVpn & 0xFFFFFFFF) << 32);
        *(unsigned long long*)((ULONG_PTR)newNode + gSymInfo.StartingVpnOffset) = qw;
        // High bytes at +0x20 (StartingVpnHigh[7:0] | EndingVpnHigh[7:0]<<8)
        high = (req->StartingVpn >> 32) & 0xFF;
        high |= ((req->EndingVpn >> 32) & 0xFF) << 8;
        *(unsigned long long*)((ULONG_PTR)newNode + 0x20) = high;
        // MMVAD_FLAGS at +0x30
        *(ULONG*)((ULONG_PTR)newNode + 0x30) = req->VadTypeRaw;

        // ── Step 2: commit charges ────────────────────────────────────────
        // Mi* offsets are PDB RVAs — add NtBaseOffset to get the real VA.
        // MiInsertVadCharges can block; must run outside the lock.
        if (gSymInfo.MiInsertVadCharges) {
            PFN_MiInsertVadCharges fnCharges =
                (PFN_MiInsertVadCharges)(gInit.NtBaseOffset + gSymInfo.MiInsertVadCharges);
            __try {
                status = fnCharges(newNode, pTarget);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
                DbgPrint("[-] VadInsertWorkerThread: MiInsertVadCharges raised exception %08X — rolling back\n", status);
                VadFreeNode(newNode);
                req->Result  = status;
                req->isValid = FALSE;
                continue;
            }
            if (!NT_SUCCESS(status)) {
                DbgPrint("[-] VadInsertWorkerThread: MiInsertVadCharges failed %08X — rolling back\n", status);
                VadFreeNode(newNode);
                req->Result  = status;
                req->isValid = FALSE;
                continue;
            }
        }

        // ── Step 3+4: conflict check + insert under exclusive lock ────────
        {
            PEX_PUSH_LOCK pLock =
                (PEX_PUSH_LOCK)((ULONG_PTR)pTarget + gSymInfo.AddressCreationLock);

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(pLock);

            BOOLEAN hasConflict = FALSE;
            if (gSymInfo.MiCheckForConflictingVad) {
                PFN_MiCheckForConflictingVad fnCheck =
                    (PFN_MiCheckForConflictingVad)(gInit.NtBaseOffset + gSymInfo.MiCheckForConflictingVad);
                PVOID conflict = NULL;
                __try {
                    conflict = fnCheck(pTarget,
                        (ULONG_PTR)(req->StartingVpn << 12),
                        (ULONG_PTR)(req->EndingVpn   << 12));
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    DbgPrint("[!] VadInsertWorkerThread: MiCheckForConflictingVad exception %08X\n",
                        GetExceptionCode());
                }
                hasConflict = (conflict != NULL);
            } else {
                PVOID* pFbRoot = (PVOID*)((ULONG_PTR)pTarget + gSymInfo.VADRoot);
                hasConflict = VadConflictWalkUnlocked(
                    (pFbRoot && MmIsAddressValid(pFbRoot)) ? *pFbRoot : NULL,
                    &gSymInfo, req->StartingVpn, req->EndingVpn);
            }

            if (hasConflict) {
                ExReleasePushLockExclusive(pLock);
                KeLeaveCriticalRegion();
                DbgPrint("[-] VadInsertWorkerThread: conflicting VAD for VPN 0x%llx-0x%llx\n",
                    req->StartingVpn, req->EndingVpn);
                if (gSymInfo.MiRemoveVadCharges) {
                    PFN_MiRemoveVadCharges fnRollback =
                        (PFN_MiRemoveVadCharges)(gInit.NtBaseOffset + gSymInfo.MiRemoveVadCharges);
                    fnRollback(newNode, pTarget);
                }
                VadFreeNode(newNode);
                req->Result  = STATUS_CONFLICTING_ADDRESSES;
                req->isValid = FALSE;
                continue;
            }

            if (gSymInfo.MiInsertVad) {
                PFN_MiInsertVad fnInsert =
                    (PFN_MiInsertVad)(gInit.NtBaseOffset + gSymInfo.MiInsertVad);
                __try {
                    fnInsert(newNode, pTarget, 0);
                    status = STATUS_SUCCESS;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = GetExceptionCode();
                    DbgPrint("[-] VadInsertWorkerThread: MiInsertVad raised exception %08X\n", status);
                }
            } else {
                ExReleasePushLockExclusive(pLock);
                KeLeaveCriticalRegion();
                status = VadTreeInsert(pTarget, &gSymInfo, newNode);
                if (!NT_SUCCESS(status)) {
                    if (gSymInfo.MiRemoveVadCharges) {
                        PFN_MiRemoveVadCharges fnRollback =
                            (PFN_MiRemoveVadCharges)(gInit.NtBaseOffset + gSymInfo.MiRemoveVadCharges);
                        fnRollback(newNode, pTarget);
                    }
                    VadFreeNode(newNode);
                }
                req->Result  = status;
                req->isValid = FALSE;
                continue;
            }

            ExReleasePushLockExclusive(pLock);
            KeLeaveCriticalRegion();

            if (!NT_SUCCESS(status)) {
                if (gSymInfo.MiRemoveVadCharges) {
                    PFN_MiRemoveVadCharges fnRollback =
                        (PFN_MiRemoveVadCharges)(gInit.NtBaseOffset + gSymInfo.MiRemoveVadCharges);
                    fnRollback(newNode, pTarget);
                }
                VadFreeNode(newNode);
                req->Result  = status;
                req->isValid = FALSE;
                continue;
            }
        }

        if (NT_SUCCESS(status)) {
            DbgPrint("[+] VadInsertWorkerThread: inserted node 0x%p into '%s' (VPN 0x%llx-0x%llx)\n",
                newNode, procName, req->StartingVpn, req->EndingVpn);
        } else {
            DbgPrint("[-] VadInsertWorkerThread: insert into '%s' failed %08X\n", procName, status);
        }

        req->Result  = status;
        req->isValid = FALSE;
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// =================================================================
// VadRemoveWorkerThread
// Waits for hEventVAD_REMOVE. Reads a VAD_MODIFY_REQUEST with
// identifier "VREM" and calls VadTreeRemove for the given StartingVpn.
// If FreeOnRemove is set the unlinked node is also freed via VadFreeNode.
// =================================================================
VOID VadRemoveWorkerThread(PVOID Context) {
    PKEVENT          pEvent = (PKEVENT)Context;
    PVAD_MODIFY_REQUEST req;
    PEPROCESS        pTarget;
    PVOID            removed;
    NTSTATUS         status;
    UCHAR            liveWalkMode;
    const char*      procName;

    while (!g_StopRequested) {
        pEvent->Header.SignalState = 0;
        status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] VadRemoveWorkerThread: wait failed %08X\n", status);
            break;
        }

        if (!gVadModifySection) {
            DbgPrint("[-] VadRemoveWorkerThread: gVadModifySection is NULL\n");
            continue;
        }

        req = (PVAD_MODIFY_REQUEST)gVadModifySection;

        if (!req->isValid || memcmp(req->identifier, "VREM", 4) != 0) {
            DbgPrint("[-] VadRemoveWorkerThread: invalid request\n");
            continue;
        }

        // Remove from the same process whose tree was last walked
        liveWalkMode = (pInSection != NULL) ? ((PINIT)pInSection)->walkMode : 0;
        procName     = (liveWalkMode == 1) ? gInit.sourceProcess : gInit.targetProcess;
        pTarget = GetProcessByName(procName,
            gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
        if (!pTarget) {
            DbgPrint("[-] VadRemoveWorkerThread: process '%s' not found\n", procName);
            req->Result  = STATUS_NOT_FOUND;
            req->isValid = FALSE;
            continue;
        }

        removed = NULL;

        if (gSymInfo.MiRemoveVad) {
            removed = VadFindNodeByVpn(pTarget, &gSymInfo, req->StartingVpn);
            if (!removed) {
                DbgPrint("[-] VadRemoveWorkerThread: node VPN 0x%llx not found\n", req->StartingVpn);
                status = STATUS_NOT_FOUND;
            } else {
                PFN_MiRemoveVad fnRemove =
                    (PFN_MiRemoveVad)(gInit.NtBaseOffset + gSymInfo.MiRemoveVad);
                __try {
                    fnRemove(removed, pTarget);
                    status = STATUS_SUCCESS;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = GetExceptionCode();
                    DbgPrint("[-] VadRemoveWorkerThread: MiRemoveVad raised exception %08X\n", status);
                    removed = NULL;
                }

                if (NT_SUCCESS(status) && gSymInfo.MiRemoveVadCharges) {
                    PFN_MiRemoveVadCharges fnCharges =
                        (PFN_MiRemoveVadCharges)(gInit.NtBaseOffset + gSymInfo.MiRemoveVadCharges);
                    __try {
                        fnCharges(removed, pTarget);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        DbgPrint("[!] VadRemoveWorkerThread: MiRemoveVadCharges raised exception %08X (ignored)\n",
                            GetExceptionCode());
                    }
                }
            }
        } else {
            status = VadTreeRemove(pTarget, &gSymInfo, req->StartingVpn, &removed);
        }

        if (NT_SUCCESS(status)) {
            DbgPrint("[+] VadRemoveWorkerThread: removed node 0x%p from '%s' (VPN 0x%llx)\n",
                removed, procName, req->StartingVpn);
            if (req->FreeOnRemove && removed)
                VadFreeNode(removed);
        } else {
            DbgPrint("[-] VadRemoveWorkerThread: remove from '%s' failed %08X\n", procName, status);
        }

        req->Result  = status;
        req->isValid = FALSE;
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

#include <ntifs.h>
#include "MemoryProtection.h"

//
// Change memory protection for a target process
//
NTSTATUS ChangeMemoryProtection(
    _In_ PEPROCESS Process,
    _In_ PVOID Address,
    _In_ SIZE_T SizeOfMem,
    _In_ ULONG NewProtection
)
{
    NTSTATUS status;
    ZwProtectVirtualMemory_t ZwProtectVirtualMemory;
    PVOID tmpAddress;
    SIZE_T tmpSize;
    ULONG tmpProtect;
    ULONG oldProtection = 0;
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    SIZE_T returnLength = 0;
    KAPC_STATE apcState = { 0 };

    // Parameter validation
    if (Process == NULL || Address == NULL) {
        DbgPrint("[-] Invalid parameters passed to ChangeMemoryProtection\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (SizeOfMem == 0) {
        DbgPrint("[-] Invalid memory size passed to ChangeMemoryProtection\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (!IsValidProtectionFlags(NewProtection)) {
        DbgPrint("[-] Invalid protection flags: 0x%x\n", NewProtection);
        return STATUS_INVALID_PARAMETER;
    }

    // Get ZwProtectVirtualMemory function address
    status = GetZwProtectVirtualMemoryAddress(&ZwProtectVirtualMemory);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to get ZwProtectVirtualMemory address: %08X\n", status);
        return status;
    }

    // Copy parameters to preserve values after context switch
    tmpAddress = Address;
    tmpSize = SizeOfMem;
    tmpProtect = NewProtection;

    // Attach to target process context
    status = AttachToProcessSafely(Process, &apcState);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to attach to process context: %08X\n", status);
        return status;
    }

    // Query current memory information
    status = ZwQueryVirtualMemory(ZwCurrentProcess(), tmpAddress, MemoryBasicInformation,
        &mbi, sizeof(mbi), &returnLength);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to query virtual memory: %08X\n", status);
        DetachFromProcessSafely(&apcState);
        return status;
    }

    DbgPrint("[+] Current memory information:\n");
    DbgPrint("    BaseAddress: %p\n", mbi.BaseAddress);
    DbgPrint("    RegionSize:  0x%llx\n", mbi.RegionSize);
    DbgPrint("    Protect:     0x%x\n", mbi.Protect);

    // Only change protection if different from current
    if (tmpProtect != mbi.Protect) {
        if (KeGetCurrentIrql() <= PASSIVE_LEVEL) {
            status = ZwProtectVirtualMemory(ZwCurrentProcess(), &tmpAddress, &tmpSize,
                tmpProtect, &oldProtection);

            if (NT_SUCCESS(status)) {
                DbgPrint("[+] Memory protection changed successfully\n");
                DbgPrint("    Address: %p\n", tmpAddress);
                DbgPrint("    Size: 0x%llx\n", tmpSize);
                DbgPrint("    Old Protection: 0x%x\n", oldProtection);
                DbgPrint("    New Protection: 0x%x\n", tmpProtect);
            }
            else {
                DbgPrint("[-] Failed to change memory protection: %08X\n", status);
            }
        }
        else {
            DbgPrint("[-] IRQL too high for memory protection change\n");
            status = STATUS_UNSUCCESSFUL;
        }
    }
    else {
        DbgPrint("[+] Memory protection already set to desired value\n");
        status = STATUS_SUCCESS;
    }

    // Detach from process context
    DetachFromProcessSafely(&apcState);

    // Dereference process object
    ObDereferenceObject(Process);

    return status;
}

//
// Query memory protection information
//
NTSTATUS QueryMemoryProtection(
    _In_ PEPROCESS Process,
    _In_ PVOID Address,
    _Out_ PMEMORY_BASIC_INFORMATION MemoryInfo
)
{
    NTSTATUS status;
    KAPC_STATE apcState = { 0 };
    SIZE_T returnLength = 0;

    if (Process == NULL || Address == NULL || MemoryInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Attach to target process context
    status = AttachToProcessSafely(Process, &apcState);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to attach to process context for query: %08X\n", status);
        return status;
    }

    // Query memory information
    status = ZwQueryVirtualMemory(ZwCurrentProcess(), Address, MemoryBasicInformation,
        MemoryInfo, sizeof(MEMORY_BASIC_INFORMATION), &returnLength);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to query memory information: %08X\n", status);
    }

    // Detach from process context
    DetachFromProcessSafely(&apcState);

    return status;
}

//
// Restore memory protection to original value
//
NTSTATUS RestoreMemoryProtection(
    _In_ PEPROCESS Process,
    _In_ PVOID Address,
    _In_ SIZE_T SizeOfMem,
    _In_ ULONG OriginalProtection
)
{
    DbgPrint("[+] Restoring memory protection to: 0x%x\n", OriginalProtection);
    return ChangeMemoryProtection(Process, Address, SizeOfMem, OriginalProtection);
}

//
// Validate protection flags
//
BOOLEAN IsValidProtectionFlags(_In_ ULONG Protection)
{
    // Check for valid Windows memory protection constants
    switch (Protection & 0xFF) {
    case PAGE_NOACCESS:
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return TRUE;
    default:
        return FALSE;
    }
}

//
// Validate memory address in target process
//
BOOLEAN IsValidMemoryAddress(_In_ PEPROCESS Process, _In_ PVOID Address)
{
    MEMORY_BASIC_INFORMATION mbi;
    NTSTATUS status;

    if (Process == NULL || Address == NULL) {
        return FALSE;
    }

    status = QueryMemoryProtection(Process, Address, &mbi);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    // Check if memory is committed
    return (mbi.State == MEM_COMMIT);
}

//
// Get ZwProtectVirtualMemory function address
//
NTSTATUS GetZwProtectVirtualMemoryAddress(_Out_ ZwProtectVirtualMemory_t* FunctionAddress)
{
    if (FunctionAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Calculate function address using symbol information
    if (gInit.NtBaseOffset == 0 || gSymInfo.ZwProtectVirtualMemory == 0) {
        DbgPrint("[-] Symbol information not available\n");
        return STATUS_UNSUCCESSFUL;
    }

    *FunctionAddress = (ZwProtectVirtualMemory_t)(gInit.NtBaseOffset + gSymInfo.ZwProtectVirtualMemory);

    DbgPrint("[+] ZwProtectVirtualMemory address: 0x%p\n", *FunctionAddress);
    DbgPrint("    NT Base Offset: 0x%llx\n", gInit.NtBaseOffset);
    DbgPrint("    Function Offset: 0x%llx\n", gSymInfo.ZwProtectVirtualMemory);

    return STATUS_SUCCESS;
}

//
// Validate memory region
//
NTSTATUS ValidateMemoryRegion(_In_ PEPROCESS Process, _In_ PVOID Address, _In_ SIZE_T Size)
{
    MEMORY_BASIC_INFORMATION mbi;
    NTSTATUS status;
    PVOID endAddress;

    if (Process == NULL || Address == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Check for overflow
    endAddress = (PVOID)((ULONG_PTR)Address + Size);
    if (endAddress <= Address) {
        DbgPrint("[-] Memory region causes overflow\n");
        return STATUS_INVALID_PARAMETER;
    }

    status = QueryMemoryProtection(Process, Address, &mbi);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to validate memory region: %08X\n", status);
        return status;
    }

    // Check if the entire region is within the queried region
    if ((ULONG_PTR)endAddress > ((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize)) {
        DbgPrint("[-] Memory region spans multiple regions\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Check if memory is committed
    if (mbi.State != MEM_COMMIT) {
        DbgPrint("[-] Memory region is not committed\n");
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

//
// Safely attach to process context
//
NTSTATUS AttachToProcessSafely(_In_ PEPROCESS Process, _Out_ PKAPC_STATE ApcState)
{
    if (Process == NULL || ApcState == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        KeStackAttachProcess(Process, ApcState);
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] Exception occurred while attaching to process\n");
        return STATUS_UNSUCCESSFUL;
    }
}

//
// Safely detach from process context
//
VOID DetachFromProcessSafely(_In_ PKAPC_STATE ApcState)
{
    if (ApcState == NULL) {
        return;
    }

    __try {
        KeUnstackDetachProcess(ApcState);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] Exception occurred while detaching from process\n");
    }
}
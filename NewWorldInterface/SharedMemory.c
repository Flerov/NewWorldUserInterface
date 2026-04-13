#include <ntifs.h>
#include "SharedMemory.h"

//
// Create input section for symbol information from user mode
//
NTSTATUS CreateInputSection(VOID)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING sectionName;
    LARGE_INTEGER sectionSize;
    SECURITY_DESCRIPTOR securityDescriptor;

    // Set section size
    sectionSize.QuadPart = 0x2000; // 8KB

    // Create security descriptor
    status = RtlCreateSecurityDescriptor(&securityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create security descriptor for input section: %08X\n", status);
        return status;
    }

    // Set DACL
    status = RtlSetDaclSecurityDescriptor(&securityDescriptor, TRUE, NULL, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to set DACL for input section: %08X\n", status);
        return status;
    }

    // Initialize section name and attributes
    RtlInitUnicodeString(&sectionName, MAPPING_NAME_INPUT);
    InitializeObjectAttributes(&objectAttributes, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &securityDescriptor);

    // Create the section
    status = ZwCreateSection(&hInSection, SECTION_ALL_ACCESS | SECTION_MAP_WRITE,
        &objectAttributes, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    if (!NT_SUCCESS(status) || hInSection == NULL) {
        DbgPrint("[-] Failed to create input section: %08X\n", status);
        return status;
    }

    DbgPrint("[+] Input section created successfully\n");
    return STATUS_SUCCESS;
}

//
// Create output section for VAD information to user mode
//
NTSTATUS CreateOutputSection(VOID)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING sectionName;
    LARGE_INTEGER sectionSize;
    SECURITY_DESCRIPTOR securityDescriptor;

    // Set section size
    sectionSize.QuadPart = 0x4000; // 16KB

    // Create security descriptor
    status = RtlCreateSecurityDescriptor(&securityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create security descriptor for output section: %08X\n", status);
        return status;
    }

    // Set DACL
    status = RtlSetDaclSecurityDescriptor(&securityDescriptor, TRUE, NULL, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to set DACL for output section: %08X\n", status);
        return status;
    }

    // Initialize section name and attributes
    RtlInitUnicodeString(&sectionName, MAPPING_NAME_OUTPUT);
    InitializeObjectAttributes(&objectAttributes, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &securityDescriptor);

    // Create the section
    status = ZwCreateSection(&gpDeviceContext->hSection, SECTION_ALL_ACCESS | SECTION_MAP_WRITE,
        &objectAttributes, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    if (!NT_SUCCESS(status) || gpDeviceContext->hSection == NULL) {
        DbgPrint("[-] Failed to create output section: %08X\n", status);
        return status;
    }

    DbgPrint("[+] Output section created successfully\n");
    return STATUS_SUCCESS;
}

//
// Create filename section for file path information to user mode
//
NTSTATUS CreateFileNameSection(VOID)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING sectionName;
    LARGE_INTEGER sectionSize;
    SECURITY_DESCRIPTOR securityDescriptor;

    // Set section size
    sectionSize.QuadPart = 0x4000; // 16KB

    // Create security descriptor
    status = RtlCreateSecurityDescriptor(&securityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create security descriptor for filename section: %08X\n", status);
        return status;
    }

    // Set DACL
    status = RtlSetDaclSecurityDescriptor(&securityDescriptor, TRUE, NULL, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to set DACL for filename section: %08X\n", status);
        return status;
    }

    // Initialize section name and attributes
    RtlInitUnicodeString(&sectionName, MAPPING_NAME_FROM_FILENAMES);
    InitializeObjectAttributes(&objectAttributes, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &securityDescriptor);

    // Create the section
    status = ZwCreateSection(&gpDeviceContext->hSectionFileName, SECTION_ALL_ACCESS | SECTION_MAP_WRITE,
        &objectAttributes, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    if (!NT_SUCCESS(status) || gpDeviceContext->hSectionFileName == NULL) {
        DbgPrint("[-] Failed to create filename section: %08X\n", status);
        return status;
    }

    DbgPrint("[+] Filename section created successfully\n");
    return STATUS_SUCCESS;
}

//
// Map input section into kernel address space
//
NTSTATUS MapInputSection(VOID)
{
    NTSTATUS status;
    LARGE_INTEGER sectionOffset = { 0 };

    if (hInSection == NULL) {
        DbgPrint("[-] Input section handle is NULL\n");
        return STATUS_INVALID_HANDLE;
    }

    gSymsViewSize = 0;

    status = ZwMapViewOfSection(hInSection, ZwCurrentProcess(), &pInSection,
        0, 0, &sectionOffset, &gSymsViewSize, ViewShare,
        0, PAGE_READONLY);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to map input section: %08X\n", status);
        return status;
    }

    DbgPrint("[+] Input section mapped successfully - Size: %zu Bytes, Base: 0x%p\n",
        gSymsViewSize, pInSection);

    return STATUS_SUCCESS;
}

//
// Map output section into kernel address space
//
NTSTATUS MapOutputSection(VOID)
{
    NTSTATUS status;
    LARGE_INTEGER sectionOffset = { 0 };

    if (gpDeviceContext->hSection == NULL) {
        DbgPrint("[-] Output section handle is NULL\n");
        return STATUS_INVALID_HANDLE;
    }

    gViewSize = 0;

    status = ZwMapViewOfSection(gpDeviceContext->hSection, ZwCurrentProcess(), &gSection,
        0, 0, &sectionOffset, &gViewSize, ViewShare,
        0, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to map output section: %08X\n", status);
        return status;
    }

    DbgPrint("[+] Output section mapped successfully - Size: %zu Bytes, Base: 0x%p\n",
        gViewSize, gSection);

    gpDeviceContext->gSectionMapped = TRUE;
    return STATUS_SUCCESS;
}

//
// Map filename section into kernel address space
//
NTSTATUS MapFileNameSection(VOID)
{
    NTSTATUS status;
    LARGE_INTEGER sectionOffset = { 0 };

    if (gpDeviceContext->hSectionFileName == NULL) {
        DbgPrint("[-] Filename section handle is NULL\n");
        return STATUS_INVALID_HANDLE;
    }

    gFileNameViewSize = 0;

    status = ZwMapViewOfSection(gpDeviceContext->hSectionFileName, ZwCurrentProcess(), &gFileNameSection,
        0, 0, &sectionOffset, &gFileNameViewSize, ViewUnmap,
        0, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to map filename section: %08X\n", status);
        return status;
    }

    DbgPrint("[+] Filename section mapped successfully - Size: %zu Bytes, Base: 0x%p\n",
        gFileNameViewSize, gFileNameSection);

    gpDeviceContext->gFileNameSectionMapped = TRUE;
    return STATUS_SUCCESS;
}

//
// Unmap input section from kernel address space
//
NTSTATUS UnmapInputSection(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pInSection != NULL) {
        status = ZwUnmapViewOfSection(ZwCurrentProcess(), pInSection);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] Failed to unmap input section: %08X\n", status);
        }
        else {
            DbgPrint("[+] Input section unmapped successfully\n");
            pInSection = NULL;
            gSymsViewSize = 0;
        }
    }

    return status;
}

//
// Unmap output section from kernel address space
//
NTSTATUS UnmapOutputSection(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (gSection != NULL) {
        status = ZwUnmapViewOfSection(ZwCurrentProcess(), gSection);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] Failed to unmap output section: %08X\n", status);
        }
        else {
            DbgPrint("[+] Output section unmapped successfully\n");
            gSection = NULL;
            gViewSize = 0;
            gpDeviceContext->gSectionMapped = FALSE;
        }
    }

    return status;
}

//
// Unmap filename section from kernel address space
//
NTSTATUS UnmapFileNameSection(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (gFileNameSection != NULL) {
        status = ZwUnmapViewOfSection(ZwCurrentProcess(), gFileNameSection);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] Failed to unmap filename section: %08X\n", status);
        }
        else {
            DbgPrint("[+] Filename section unmapped successfully\n");
            gFileNameSection = NULL;
            gFileNameViewSize = 0;
            gpDeviceContext->gFileNameSectionMapped = FALSE;
        }
    }

    return status;
}

//
// Cleanup input section resources
//
NTSTATUS CleanupInputSection(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    // Unmap section first
    if (pInSection != NULL) {
        UnmapInputSection();
    }

    // Close section handle
    if (hInSection != NULL) {
        status = ZwClose(hInSection);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] Failed to close input section handle: %08X\n", status);
        }
        else {
            DbgPrint("[+] Input section handle closed successfully\n");
            hInSection = NULL;
        }
    }

    return status;
}

//
// Cleanup output section resources
//
NTSTATUS CleanupOutputSection(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    // Unmap section first
    if (gSection != NULL) {
        UnmapOutputSection();
    }

    // Close section handle
    if (gpDeviceContext != NULL && gpDeviceContext->hSection != NULL) {
        status = ZwClose(gpDeviceContext->hSection);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] Failed to close output section handle: %08X\n", status);
        }
        else {
            DbgPrint("[+] Output section handle closed successfully\n");
            gpDeviceContext->hSection = NULL;
        }
    }

    return status;
}

//
// Cleanup filename section resources
//
NTSTATUS CleanupFileNameSection(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    // Unmap section first
    if (gFileNameSection != NULL) {
        UnmapFileNameSection();
    }

    // Close section handle
    if (gpDeviceContext != NULL && gpDeviceContext->hSectionFileName != NULL) {
        status = ZwClose(gpDeviceContext->hSectionFileName);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] Failed to close filename section handle: %08X\n", status);
        }
        else {
            DbgPrint("[+] Filename section handle closed successfully\n");
            gpDeviceContext->hSectionFileName = NULL;
        }
    }

    return status;
}

//
// Cleanup all section resources
//
NTSTATUS CleanupAllSections(VOID)
{
    NTSTATUS status1, status2, status3;

    DbgPrint("[+] Cleaning up all shared memory sections\n");

    status1 = CleanupInputSection();
    status2 = CleanupOutputSection();
    status3 = CleanupFileNameSection();

    // Return the first error encountered
    if (!NT_SUCCESS(status1)) return status1;
    if (!NT_SUCCESS(status2)) return status2;
    if (!NT_SUCCESS(status3)) return status3;

    DbgPrint("[+] All shared memory sections cleaned up successfully\n");
    return STATUS_SUCCESS;
}

//
// Initialize all shared memory sections
//
NTSTATUS InitializeSharedMemory(VOID)
{
    NTSTATUS status;

    DbgPrint("[+] Initializing shared memory subsystem\n");

    // Create sections
    status = CreateInputSection();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create input section during initialization\n");
        return status;
    }

    status = CreateOutputSection();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create output section during initialization\n");
        CleanupInputSection();
        return status;
    }

    status = CreateFileNameSection();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create filename section during initialization\n");
        CleanupInputSection();
        CleanupOutputSection();
        return status;
    }

    // Map sections
    status = MapOutputSection();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to map output section during initialization\n");
        CleanupAllSections();
        return status;
    }

    status = MapFileNameSection();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to map filename section during initialization\n");
        CleanupAllSections();
        return status;
    }

    // Input section is mapped later when needed

    DbgPrint("[+] Shared memory subsystem initialized successfully\n");
    return STATUS_SUCCESS;
}

//
// Cleanup shared memory subsystem
//
NTSTATUS CleanupSharedMemory(VOID)
{
    DbgPrint("[+] Cleaning up shared memory subsystem\n");
    return CleanupAllSections();
}

//
// Zero out all mapped shared memory sections
//
VOID ZeroSharedMemorySections(VOID)
{
    if (gSection != NULL && gViewSize > 0) {
        RtlZeroMemory(gSection, gViewSize);
        DbgPrint("[+] Output section zeroed\n");
    }

    if (gFileNameSection != NULL && gFileNameViewSize > 0) {
        RtlZeroMemory(gFileNameSection, gFileNameViewSize);
        DbgPrint("[+] Filename section zeroed\n");
    }

    if (pInSection != NULL && gSymsViewSize > 0) {
        RtlZeroMemory(pInSection, gSymsViewSize);
        DbgPrint("[+] Input section zeroed\n");
    }
}

//
// Helper function to create a named section
//
NTSTATUS CreateNamedSection(
    _In_ PCWSTR SectionName,
    _In_ SIZE_T SectionSize,
    _In_ ULONG Protection,
    _Out_ PHANDLE SectionHandle
)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING sectionName;
    LARGE_INTEGER sectionSizeLI;
    SECURITY_DESCRIPTOR securityDescriptor;

    if (SectionHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *SectionHandle = NULL;

    // Set section size
    sectionSizeLI.QuadPart = SectionSize;

    // Create security descriptor
    status = RtlCreateSecurityDescriptor(&securityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Set DACL
    status = RtlSetDaclSecurityDescriptor(&securityDescriptor, TRUE, NULL, FALSE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Initialize section name and attributes
    RtlInitUnicodeString(&sectionName, SectionName);
    InitializeObjectAttributes(&objectAttributes, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &securityDescriptor);

    // Create the section
    status = ZwCreateSection(SectionHandle, SECTION_ALL_ACCESS | SECTION_MAP_WRITE,
        &objectAttributes, &sectionSizeLI, Protection, SEC_COMMIT, NULL);

    return status;
}

//
// Helper function to map a named section
//
NTSTATUS MapNamedSection(
    _In_ HANDLE SectionHandle,
    _Out_ PVOID* MappedBase,
    _Inout_ PSIZE_T ViewSize
)
{
    LARGE_INTEGER sectionOffset = { 0 };

    if (SectionHandle == NULL || MappedBase == NULL || ViewSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *MappedBase = NULL;

    return ZwMapViewOfSection(SectionHandle, ZwCurrentProcess(), MappedBase,
        0, 0, &sectionOffset, ViewSize, ViewShare,
        0, PAGE_READWRITE);
}

//
// Helper function to unmap a named section
//
NTSTATUS UnmapNamedSection(
    _In_ PVOID MappedBase
)
{
    if (MappedBase == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    return ZwUnmapViewOfSection(ZwCurrentProcess(), MappedBase);
}
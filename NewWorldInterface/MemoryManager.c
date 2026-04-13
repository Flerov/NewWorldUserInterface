#pragma once
#include <ntifs.h>
#include "MemoryManager.h"


NTSTATUS WritePhysicalAddress(PVOID PhysTargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
{
	if (!PhysTargetAddress)
		return STATUS_UNSUCCESSFUL;

	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = (LONGLONG)(ULONG_PTR)PhysTargetAddress;

	PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

	if (!pmapped_mem)
		return STATUS_UNSUCCESSFUL;

	memcpy(pmapped_mem, lpBuffer, Size);

	*BytesWritten = Size;
	MmUnmapIoSpace(pmapped_mem, Size);
	return STATUS_SUCCESS;
}

NTSTATUS ReadPhysicalAddress(PVOID PhysSourceAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
	if (!PhysSourceAddress || !lpBuffer)
		return STATUS_INVALID_PARAMETER;

	PHYSICAL_ADDRESS AddrToRead = { 0 };
	AddrToRead.QuadPart = (LONGLONG)(ULONG_PTR)PhysSourceAddress;

	PVOID pmapped_mem = MmMapIoSpaceEx(AddrToRead, Size, PAGE_READONLY);

	if (!pmapped_mem)
		return STATUS_UNSUCCESSFUL;

	memcpy(lpBuffer, pmapped_mem, Size);

	*BytesRead = Size;
	MmUnmapIoSpace(pmapped_mem, Size);
	return STATUS_SUCCESS;
}
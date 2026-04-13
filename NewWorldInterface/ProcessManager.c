#include "ProcessManager.h"


PEPROCESS GetProcessByName(
	const char* FileName,
	unsigned long long eprocImageFileNameOffset,
	unsigned long long eprocActiveProcessLinks) {
	PVOID CurrEProc = PsGetCurrentProcess();
	PVOID StartProc = CurrEProc;
	PLIST_ENTRY CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	PCHAR CurrentImageName = (PCHAR)((ULONG_PTR)CurrEProc + eprocImageFileNameOffset);
	size_t FileNameSize = (strlen(FileName) > 15) ? 14 : strlen(FileName); // 14 cause of null terminator
	do {
		if (!MmIsAddressValid(CurrEProc)) {
			DbgPrint("[-] Invalid EPROCESS address: 0x%llx\n", CurrEProc);
			return 0x0;
		}
		if (memcmp(FileName, CurrentImageName, FileNameSize) == 0)
			return CurrEProc;
		CurrEProc = (ULONG_PTR)CurList->Flink - eprocActiveProcessLinks;
		CurrentImageName = (PCHAR)((ULONG_PTR)CurrEProc + eprocImageFileNameOffset);
		CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	} while ((ULONG_PTR)StartProc != (ULONG_PTR)CurrEProc);
	return 0x0;
}
unsigned long long GetDirectoryTableBaseByName(
	const char* FileName,
	unsigned long long eprocImageFileNameOffset,
	unsigned long long eprocActiveProcessLinks,
	unsigned long long kprocDirectoryTableBase) {
	PVOID CurrEProc = PsGetCurrentProcess();
	PVOID StartProc = CurrEProc;
	PLIST_ENTRY CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	PCHAR CurrentImageName = (PCHAR)((ULONG_PTR)CurrEProc + eprocImageFileNameOffset);
	size_t FileNameSize = (strlen(FileName) > 14) ? 14 : strlen(FileName);
	do {
		if (!MmIsAddressValid(CurrEProc)) {
			DbgPrint("[-] Invalid EPROCESS address: 0x%llx\n", CurrEProc);
			return 0x0;
		}
		if (memcmp(FileName, CurrentImageName, FileNameSize) == 0) {
			PVOID* test = (unsigned long long)CurrEProc + kprocDirectoryTableBase;
			return *test;
		}
		CurrEProc = (ULONG_PTR)CurList->Flink - eprocActiveProcessLinks;
		CurrentImageName = (PCHAR)((ULONG_PTR)CurrEProc + eprocImageFileNameOffset);
		CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	} while ((ULONG_PTR)StartProc != (ULONG_PTR)CurrEProc);
	return 0x0;
}

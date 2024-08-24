#include "thread.h"
#include "../memory/memory.h"


void thread::set_start_addr(PETHREAD ethread, PVOID start, bool isWin32)
{
	if (!MmIsAddressValid(ethread))
	{
		return;
	}

	PVOID StartAddress = nullptr;
	if(isWin32)
	{
		get_Win32StartAddress(ethread, &StartAddress);
	}
	else
	{
		get_Win32StartAddress(ethread, &StartAddress);
	}

	if (StartAddress)
	{
		memory::write_safe<PVOID>(StartAddress, start);
	}
}

NTSTATUS thread::get_tid_by_handle(HANDLE hThread, PHANDLE tid)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PETHREAD pEthread = nullptr;
	status = ObReferenceObjectByHandle(
		hThread,
		THREAD_ALL_ACCESS,
		*PsThreadType,
		KernelMode,
		reinterpret_cast<PVOID*>(&pEthread),
		nullptr
	);
	if (NT_SUCCESS(status))
	{
		CLIENT_ID cid{};
		status = thread::get_Cid(pEthread, &cid);
		if (NT_SUCCESS(status))
		{
			memory::write_safe<HANDLE>(tid,cid.UniqueThread);
		}
		ObDereferenceObject(pEthread);
	}
	return status;
}
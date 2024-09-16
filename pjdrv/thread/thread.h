#pragma once
#include <ntifs.h>
#include "../symbols/symbols.h"
#include "../memory/memory.h"
#include "../macro_defs.h"

class thread
{
public:

	static MACRO_GET_MEMBER(CLIENT_ID, symbols::data_.ethread,Cid)

	static MACRO_GET_PTR(PVOID, symbols::data_.ethread,Win32StartAddress)

	static MACRO_GET_PTR(PVOID,symbols::data_.ethread,StartAddress)

	static MACRO_GET_PTR(PVOID, symbols::data_.kthread, Process)

	static MACRO_GET_PTR(PUCHAR, symbols::data_.kthread, PreviousMode)

	static void set_start_addr(const PETHREAD ethread, PVOID start, bool isWin32);

	static NTSTATUS get_tid_by_handle(const HANDLE hThread, const PHANDLE tid);

	static NTSTATUS get_ethread(const HANDLE tid, PETHREAD* pEThread);

	static bool is_alive(const HANDLE tid);
};

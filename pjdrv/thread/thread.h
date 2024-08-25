#pragma once
#include <ntifs.h>
#include "../symbols/symbols.hpp"
#include "../memory/memory.h"
#include "../macro_defs.h"

class thread
{
public:

	static MACRO_GET_MEMBER(CLIENT_ID, symbols::data_.ethread,Cid)

	static MACRO_GET_PTR(PVOID, symbols::data_.ethread,Win32StartAddress)

	static MACRO_GET_PTR(PVOID,symbols::data_.ethread,StartAddress)

	static MACRO_GET_PTR(PVOID, symbols::data_.ethread, Process)

	static void set_start_addr(PETHREAD ethread, PVOID start, bool isWin32);

	static NTSTATUS get_tid_by_handle(HANDLE hThread,PHANDLE tid);
};

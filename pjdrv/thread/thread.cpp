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
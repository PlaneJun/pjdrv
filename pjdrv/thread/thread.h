#pragma once
#include <ntifs.h>
#include "../symbols/symbols.hpp"
#include "../memory/memory.h"

class thread
{
private:

#define MACRO_GET_MEMBER(type,member) NTSTATUS get_##member##(const PETHREAD ethread,  ##type##* out) \
	{ \
		NTSTATUS status = STATUS_UNSUCCESSFUL; \
		if (!MmIsAddressValid(ethread)) { return status;} \
		if (symbols::data_.ethread.##member## == NULL)  { return status;} \
		*out = memory::read_safe<##type>(reinterpret_cast<PUCHAR>(ethread) + symbols::data_.ethread.##member##); \
		status = STATUS_SUCCESS; \
		return status; \
	}

#define MACRO_GET_PTR(type,member) NTSTATUS get_##member##(const PETHREAD ethread,  ##type##* out) \
	{ \
		NTSTATUS status = STATUS_UNSUCCESSFUL; \
		if (!MmIsAddressValid(ethread)) { return status;} \
		if (symbols::data_.ethread.##member## == NULL)  { return status;} \
		*out = reinterpret_cast<##type>(reinterpret_cast<PUCHAR>(ethread) + symbols::data_.ethread.##member##); \
		status = STATUS_SUCCESS; \
		return status; \
	}

public:

	static MACRO_GET_MEMBER(CLIENT_ID, Cid)

	static MACRO_GET_PTR(PVOID, Win32StartAddress)

	static MACRO_GET_PTR(PVOID, StartAddress)

	static void set_start_addr(PETHREAD ethread, PVOID start, bool isWin32);

};

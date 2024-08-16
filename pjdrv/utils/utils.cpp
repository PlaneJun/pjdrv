#include "utils.h"


PVOID utils::get_system_function(const wchar_t* funcname)
{
	PVOID retAddr = NULL;
	if (funcname)
	{
		UNICODE_STRING fun_name = { 0 };
		RtlInitUnicodeString(&fun_name, funcname);
		retAddr = MmGetSystemRoutineAddress(&fun_name);
	}
	return retAddr;
}


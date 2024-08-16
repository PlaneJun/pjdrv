#pragma once
#include <ntifs.h>

namespace utils
{
	PVOID get_system_function(const wchar_t* funcname);
}

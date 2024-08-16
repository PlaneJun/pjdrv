#pragma once
#include <ntifs.h>
#include <stdint.h>

namespace module
{
	NTSTATUS get_kernel_module(const char* szModuleName, uintptr_t* BaseAddress, _Out_ size_t* ModuleSize);

	PVOID kernel_load_library(const wchar_t* full_dll_path);

	PVOID get_module_export(PVOID pBase, const char* name_ord);

	PVOID get_ntoskrnl_base(OUT PULONG pSize);
}

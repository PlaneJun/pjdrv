#pragma once
#include <ntifs.h>

namespace memory
{
	PVOID find_pattern_in_module(uintptr_t base, const char* sec_name, const unsigned char* pattern, size_t size, size_t offset);

	NTSTATUS translate_addrsss(IN UINT64 DirBase, _Inout_ PUINT64 addr);

	NTSTATUS read_physical_addr(IN PVOID64 address, OUT PVOID64 buffer, IN SIZE_T size, OUT SIZE_T* BytesTransferred);

	NTSTATUS write_physical_addr(IN PVOID64 address, IN PVOID64 buffer,IN SIZE_T size, OUT SIZE_T* BytesTransferred);

}

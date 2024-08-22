#pragma once
#include <ntifs.h>
#include <stdint.h>

namespace memory
{
	PVOID find_pattern_in_module(uintptr_t base, const char* sec_name, const unsigned char* pattern, size_t size, size_t offset);

	uint64_t translate_addrsss(uint64_t DirBase, uint64_t addr);

	NTSTATUS read_physical_addr(IN PVOID64 address, OUT PVOID64 buffer, IN SIZE_T size, OUT SIZE_T* BytesTransferred);

	NTSTATUS write_physical_addr(IN PVOID64 address, IN PVOID64 buffer,IN SIZE_T size, OUT SIZE_T* BytesTransferred);

	SIZE_T copy_mem_safe(PVOID dest, PVOID src, SIZE_T len);

	template<typename T>
	T read_safe(PVOID addr)
	{
		T val{};
		copy_mem_safe(&val,addr,sizeof(T));
		return val;
	}

	template<typename T>
	void write_safe(PVOID addr,T val)
	{
		copy_mem_safe(addr, &val, sizeof(T));
	}
}

#pragma once
#include <ntifs.h>

namespace process
{
	bool get_eprocess(const HANDLE ProcessId,PEPROCESS* pEProcess);

	NTSTATUS get_dir_base(const HANDLE ProcessId, _Out_ PUINT64 pDataBase);

	PVOID get_module_base(const HANDLE ProcessId, const wchar_t* module_name, bool isWow64, PDWORD32 out_size);

	NTSTATUS rw_virtual_memory(const HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes, PSIZE_T ReturnBytes, bool Read);

	NTSTATUS alloc_virtual_memory(const HANDLE ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protect, _Out_ PVOID out_buffer);

	NTSTATUS free_virtual_memory(const HANDLE ProcessId, PVOID BaseAddress, SIZE_T RegionSize);

	NTSTATUS query_virtual_memory(const HANDLE ProcessId, PVOID addr, _Out_ PVOID out_buffer);

	void write_vmem_mdl(const HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes, PSIZE_T retBytes);

	void read_vmem_cpy(const HANDLE ProcessId, PVOID BaseAddress, _Out_ PVOID Buffer, SIZE_T BufferBytes, PSIZE_T retBytes);

	NTSTATUS read_vmem_physic(const HANDLE ProcessId, PVOID BaseAddress, _Out_ PVOID Buffer, SIZE_T BufferBytes, PSIZE_T retBytes);

	NTSTATUS write_vmem_physic(const HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes, PSIZE_T retBytes);

	NTSTATUS protect_vmem(const HANDLE ProcessId, PVOID BaseAddress, SIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

	NTSTATUS create_thread(const HANDLE ProcessId, PVOID entry,PVOID params, _Out_ PHANDLE handler);

	NTSTATUS close_handle(const HANDLE ProcessId, HANDLE handler);
}

#pragma once
#include <ntifs.h>

namespace process
{
	bool get_eprocess(HANDLE ProcessId,PEPROCESS* pEProcess);

	NTSTATUS get_dir_base(HANDLE ProcessId, _Out_ PUINT64 pDataBase);

	PVOID get_module_base(HANDLE ProcessId, const wchar_t* module_name, bool isWow64, PDWORD32 out_size);

	NTSTATUS rw_virtual_memory(HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes, PSIZE_T ReturnBytes, bool Read);

	NTSTATUS alloc_virtual_memory(HANDLE ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protect, _Out_ PVOID out_buffer);

	NTSTATUS free_virtual_memory(HANDLE ProcessId, PVOID BaseAddress, SIZE_T RegionSize);

	NTSTATUS query_virtual_memory(HANDLE ProcessId, PVOID addr, _Out_ PVOID out_buffer);

	void write_vmem_mdl(HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes);

	void read_vmem_cpy(HANDLE ProcessId, PVOID BaseAddress, _Out_ PVOID Buffer, SIZE_T BufferBytes);

	void read_vmem_physic(HANDLE ProcessId, PVOID BaseAddress, _Out_ PVOID Buffer, SIZE_T BufferBytes);

	void write_vmem_physic(HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes);

	NTSTATUS protect_vmem(HANDLE ProcessId, PVOID BaseAddress, SIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection);

	NTSTATUS create_thread(HANDLE ProcessId, PVOID entry,PVOID params, _Out_ PHANDLE handler);

	NTSTATUS close_handle(HANDLE ProcessId, HANDLE handler);
}

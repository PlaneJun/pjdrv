#pragma once
#include <ntifs.h>
#include "../symbols/symbols.hpp"
#include "../memory/memory.h"

class process
{
	#define MACRO_GET_MEMBER(type,member) NTSTATUS get_##member##(const PEPROCESS eprocess,  ##type##* out) \
	{ \
		NTSTATUS status = STATUS_UNSUCCESSFUL; \
		if (!MmIsAddressValid(eprocess)) { return status;} \
		if (symbols::data_.eprocess.##member## == NULL)  { return status;} \
		*out = memory::read_safe<##type>(reinterpret_cast<PUCHAR>(eprocess) + symbols::data_.eprocess.##member##); \
		status = STATUS_SUCCESS; \
		return status; \
	}

#define MACRO_GET_PTR(type,member) NTSTATUS get_##member##(const PEPROCESS eprocess,  ##type##* out) \
	{ \
		NTSTATUS status = STATUS_UNSUCCESSFUL; \
		if (!MmIsAddressValid(eprocess)) { return status;} \
		if (symbols::data_.eprocess.##member## == NULL)  { return status;} \
		*out = reinterpret_cast<##type>(reinterpret_cast<PUCHAR>(eprocess) + symbols::data_.eprocess.##member##); \
		status = STATUS_SUCCESS; \
		return status; \
	}

public:

	static MACRO_GET_MEMBER(UINT64, DirectoryTableBase)

	static MACRO_GET_PTR(PLIST_ENTRY, ThreadListHead)

	static MACRO_GET_PTR(PLIST_ENTRY, ActiveProcessLinks)

	static MACRO_GET_MEMBER(HANDLE, UniqueProcessId)

	static bool get_eprocess(const HANDLE ProcessId, PEPROCESS* pEProcess);

	static PLIST_ENTRY find_thread_link_by_tid(PLIST_ENTRY header,const HANDLE tid);

	static PLIST_ENTRY find_process_link_by_pid(const HANDLE pid);

	static PVOID get_module_base(const HANDLE ProcessId, const wchar_t* module_name, PDWORD32 out_size);

	static PVOID get_module_base_by_eprocess(const PEPROCESS eprocess, PUNICODE_STRING module_name, PDWORD32 out_size);

	static NTSTATUS rw_virtual_memory(const HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes, PSIZE_T ReturnBytes, bool Read);

	static NTSTATUS alloc_virtual_memory(const HANDLE ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protect, _Out_ PVOID out_buffer);

	static NTSTATUS free_virtual_memory(const HANDLE ProcessId, PVOID BaseAddress, SIZE_T RegionSize);

	static NTSTATUS query_virtual_memory(const HANDLE ProcessId, PVOID addr, _Out_ PVOID out_buffer);

	static void write_vmem_mdl(const HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes, PSIZE_T retBytes);

	static void read_vmem_cpy(const HANDLE ProcessId, PVOID BaseAddress, _Out_ PVOID Buffer, SIZE_T BufferBytes, PSIZE_T retBytes);

	static NTSTATUS read_vmem_physic(const HANDLE ProcessId, PVOID BaseAddress, _Out_ PVOID Buffer, SIZE_T BufferBytes, PSIZE_T retBytes);

	static NTSTATUS write_vmem_physic(const HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes, PSIZE_T retBytes);

	static NTSTATUS protect_vmem(const HANDLE ProcessId, PVOID BaseAddress, SIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

	static NTSTATUS create_thread(const HANDLE ProcessId, PVOID entry, PVOID params, bool disable_notify, bool hide, _Out_ PHANDLE handler, _Out_ PULONG tid);

	static NTSTATUS close_handle(const HANDLE ProcessId, HANDLE handler);

	static NTSTATUS wait_single_object(const HANDLE ProcessId, HANDLE handler,bool alert,unsigned int wait_time);
};

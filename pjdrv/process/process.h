#pragma once
#include <ntifs.h>
#include "../symbols/symbols.hpp"
#include "../memory/memory.h"
#include "../macro_defs.h"

class process
{
public:

	static MACRO_GET_MEMBER(UINT64, symbols::data_.eprocess,DirectoryTableBase)

	static MACRO_GET_PTR(PLIST_ENTRY, symbols::data_.eprocess, ThreadListHead)

	static MACRO_GET_PTR(PLIST_ENTRY, symbols::data_.eprocess, ActiveProcessLinks)

	static MACRO_GET_MEMBER(HANDLE, symbols::data_.eprocess, UniqueProcessId)

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

	static NTSTATUS create_thread(const HANDLE ProcessId, PVOID entry, PVOID params,bool hide, _Out_ PHANDLE handler, _Out_ PHANDLE tid);

	static NTSTATUS close_handle(const HANDLE ProcessId, HANDLE handler);

	static NTSTATUS wait_single_object(const HANDLE ProcessId, HANDLE handle,bool alert,unsigned int wait_time);

	static NTSTATUS hide_thread_by_id(const HANDLE ProcessId, HANDLE tid,bool hide);
};

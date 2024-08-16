#include "process.h"
#include <Veil.h>
#include "../memory/memory.h"
#include "../symbols/symbols.hpp"


bool process::get_eprocess(HANDLE ProcessId, PEPROCESS* pEProcess)
{
	NTSTATUS status = STATUS_SUCCESS;
	status = PsLookupProcessByProcessId(ProcessId, pEProcess);
	if (!NT_SUCCESS(status) && !MmIsAddressValid(*pEProcess))
	{
		return false;
	}
	return true;
}

NTSTATUS process::get_dir_base(HANDLE ProcessId, OUT PUINT64 pDataBase)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = NULL;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}

	*pDataBase = *(PUINT64)((PUCHAR)pEProcess + symbols::offsets::data_base_);

	return STATUS_SUCCESS;
}

PVOID process::get_module_base(HANDLE ProcessId, const wchar_t* module_name, bool isWow64, PDWORD32 out_size)
{
	PEPROCESS pEProcess = NULL;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return NULL;
	}

	PVOID retBase = NULL;
	ULONG retSize = NULL;
	UNICODE_STRING usModuleName ={0};
	RtlInitUnicodeString(&usModuleName, module_name);
	KAPC_STATE apc_state = { 0 };
	KeStackAttachProcess(pEProcess, &apc_state);

	if (isWow64)
	{
		PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(pEProcess);
		if (pPeb32 == NULL || !pPeb32->Ldr)
		{
			goto exit;
		}

		// SearchInLoadOrderModuleList
		PLIST_ENTRY32 pListEntry = reinterpret_cast<PLIST_ENTRY32>(reinterpret_cast<PPEB_LDR_DATA32>(pPeb32->Ldr)->InLoadOrderModuleList.Flink);
		for (; pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList; pListEntry = reinterpret_cast<PLIST_ENTRY32>(pListEntry->Flink))
		{
			UNICODE_STRING ustr;
			PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
			if (!MmIsAddressValid((PVOID)pEntry->BaseDllName.Buffer))
			{
				continue;
			}

			RtlInitUnicodeString(&ustr, (PWCHAR)pEntry->BaseDllName.Buffer);
			if (RtlCompareUnicodeString(&ustr, &usModuleName, TRUE) == 0)
			{
				retSize = pEntry->SizeOfImage;
				retBase = (PVOID)pEntry->DllBase;
				break;
			}
		}
	}
	else
	{
		PPEB pPeb = PsGetProcessPeb(pEProcess);
		if (!pPeb || !pPeb->Ldr)
		{
			goto exit;
		}

		for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink; pListEntry != &pPeb->Ldr->InLoadOrderModuleList; pListEntry = pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (RtlCompareUnicodeString(&pEntry->BaseDllName, &usModuleName, TRUE) == 0)
			{
				retSize = pEntry->SizeOfImage;
				retBase = pEntry->DllBase;
				break;
			}
		}
	}

exit:
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	*out_size = retSize;
	return retBase;
}

NTSTATUS process::rw_virtual_memory(HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes, PSIZE_T ReturnBytes, bool Read)
{
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();;

	PAGED_CODE();
	if (PreviousMode != KernelMode)
	{

		if (((PCHAR)BaseAddress + BufferBytes < (PCHAR)BaseAddress) ||
			((PCHAR)Buffer + BufferBytes < (PCHAR)Buffer) ||
			((PVOID)((PCHAR)BaseAddress + BufferBytes) > MM_HIGHEST_USER_ADDRESS) ||
			((PVOID)((PCHAR)Buffer + BufferBytes) > MM_HIGHEST_USER_ADDRESS))
		{
			return STATUS_ACCESS_VIOLATION;
		}

		if (ARGUMENT_PRESENT(ReturnBytes))
		{
			__try
			{
				ProbeForWrite(ReturnBytes, sizeof(PSIZE_T), sizeof(ULONG));
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}
	}

	SIZE_T BytesCopied = 0;
	NTSTATUS Status = STATUS_SUCCESS;
	if (BufferBytes != 0)
	{
		do
		{
			PEPROCESS temp_process;
			Status = PsLookupProcessByProcessId(ProcessId, &temp_process);
			if (!NT_SUCCESS(Status))
			{
				break;
			}
			if (Read)
			{
				Status = MmCopyVirtualMemory(temp_process, BaseAddress, PsGetCurrentProcess(),Buffer, BufferBytes, PreviousMode, &BytesCopied);
			}
			else
			{
				Status = MmCopyVirtualMemory(PsGetCurrentProcess(), Buffer, temp_process,BaseAddress, BufferBytes, PreviousMode, &BytesCopied);
			}
			ObDereferenceObject(temp_process);
		} while (false);
	}

	if (ARGUMENT_PRESENT(ReturnBytes))
	{
		__try
		{
			*ReturnBytes = BytesCopied;

		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			NOTHING;
		}
	}

	return Status;
}

NTSTATUS process::alloc_virtual_memory(HANDLE ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protect, _Out_ PVOID out_buffer)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = NULL;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}
	KAPC_STATE apc_state = { 0 };
	KeStackAttachProcess(pEProcess, &apc_state);
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &RegionSize, AllocationType, Protect);
	if (NT_SUCCESS(status))
	{
		RtlZeroMemory(BaseAddress, RegionSize);
	}
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	*(PULONG_PTR)out_buffer = (ULONG_PTR)BaseAddress;
	return status;
}

NTSTATUS process::query_virtual_memory(HANDLE ProcessId,PVOID addr,PVOID out_buffer)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = NULL;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}

	PVOID64 buffer = ExAllocatePool(NonPagedPool, sizeof(MEMORY_BASIC_INFORMATION) + 0x100);
	if (MmIsAddressValid(buffer))
	{
		KAPC_STATE apc_state = { 0 };
		KeStackAttachProcess(pEProcess, &apc_state);
		status = ZwQueryVirtualMemory(NtCurrentProcess(), addr, MemoryBasicInformation, buffer, sizeof(MEMORY_BASIC_INFORMATION), NULL);
		KeUnstackDetachProcess(&apc_state);
		RtlCopyMemory(out_buffer, buffer, sizeof(MEMORY_BASIC_INFORMATION));
		ExFreePool(buffer);
	}
	ObDereferenceObject(pEProcess);
	return status;
}

NTSTATUS process::free_virtual_memory(HANDLE ProcessId, PVOID BaseAddress, SIZE_T RegionSize)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = NULL;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}

	KAPC_STATE apc_state = { 0 };
	KeStackAttachProcess(pEProcess, &apc_state);
	status = ZwFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, MEM_RELEASE);
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	return status;
}

void process::write_vmem_mdl(HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes)
{
	PEPROCESS pEProcess = NULL;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return;
	}

	if (MmHighestUserAddress > BaseAddress && MmHighestUserAddress > ((PCHAR)BaseAddress + BufferBytes))
	{
		if (PsGetProcessExitStatus(pEProcess) == STATUS_PENDING)
		{
			PVOID lpMem = ExAllocatePool(NonPagedPool, BufferBytes);
			if (lpMem)
			{
				RtlZeroMemory(lpMem, BufferBytes);
			}

			RtlCopyMemory(lpMem, Buffer, BufferBytes);
			KAPC_STATE apc_state = { 0 };
			KeStackAttachProcess(pEProcess, &apc_state);
			if (MmIsAddressValid(BaseAddress) && MmIsAddressValid((PCHAR)BaseAddress + BufferBytes) && lpMem)
			{
				PMDL mdl = MmCreateMdl(NULL, BaseAddress, BufferBytes);
				if (mdl)
				{
					MmBuildMdlForNonPagedPool(mdl);
					PVOID page = MmMapLockedPages(mdl, KernelMode);
					if (page)
					{
						RtlCopyMemory(page, lpMem, BufferBytes);
					}
					MmUnmapLockedPages(page, mdl);
					IoFreeMdl(mdl);
				}
			}
			KeUnstackDetachProcess(&apc_state);
			if (lpMem)
			{
				ExFreePool(lpMem);
			}
		}
	}
	ObDereferenceObject(pEProcess);
}

void process::read_vmem_cpy(HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes)
{
	PEPROCESS pEProcess = NULL;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return;
	}

	if (MmHighestUserAddress > BaseAddress && MmHighestUserAddress > ((PCHAR)BaseAddress + BufferBytes))
	{
		if (PsGetProcessExitStatus(pEProcess) == STATUS_PENDING)
		{
			PVOID lpMem = ExAllocatePool(NonPagedPool, BufferBytes);
			if (lpMem)
			{
				RtlZeroMemory(lpMem, BufferBytes);
			}

			KAPC_STATE apc_state = { 0 };
			KeStackAttachProcess(pEProcess, &apc_state);
			if (MmIsAddressValid(BaseAddress) && MmIsAddressValid((PCHAR)BaseAddress + BufferBytes) && lpMem)
			{
				RtlCopyMemory(lpMem, BaseAddress, BufferBytes);
			}
			KeUnstackDetachProcess(&apc_state);
			if (lpMem)
			{
				RtlCopyMemory(Buffer, lpMem, BufferBytes);
				ExFreePool(lpMem);
			}
		}
	}
	ObDereferenceObject(pEProcess);
}

void process::read_vmem_physic(HANDLE ProcessId, PVOID BaseAddress, _Out_ PVOID Buffer, SIZE_T BufferBytes)
{
	ULONG64 uDirBase = NULL;
	NTSTATUS status = get_dir_base(ProcessId, &uDirBase);
	if (!NT_SUCCESS(status)) {
		return;
	}

	// 将虚拟地址转化成物理地址
	status = memory::translate_addrsss(uDirBase, reinterpret_cast<PUINT64>(&BaseAddress));
	if (!NT_SUCCESS(status)) {
		return;
	}

	// 读取物理地址内容, 然后修改内容
	SIZE_T BytesTransferred = NULL;
	memory::read_physical_addr(BaseAddress, Buffer, BufferBytes, &BytesTransferred);
}

void process::write_vmem_physic(HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes)
{
	ULONG64 uDirBase = NULL;
	NTSTATUS status = get_dir_base(ProcessId, &uDirBase);
	if (!NT_SUCCESS(status)) {
		return;
	}

	// 将虚拟地址转化成物理地址
	status = memory::translate_addrsss(uDirBase, reinterpret_cast<PUINT64>(&BaseAddress));
	if (!NT_SUCCESS(status)) {
		return;
	}

	// 读取物理地址内容, 然后修改内容
	SIZE_T BytesTransferred = NULL;
	memory::write_physical_addr(BaseAddress, Buffer, BufferBytes, &BytesTransferred);
}

NTSTATUS process::protect_vmem(HANDLE ProcessId, PVOID BaseAddress, SIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = NULL;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}
	KAPC_STATE apc_state = { 0 };
	KeStackAttachProcess(pEProcess, &apc_state);
	ULONG old = NULL;
	status = ZwProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &NumberOfBytesToProtect, NewAccessProtection, &old);
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	return status;
}

NTSTATUS process::create_thread(HANDLE ProcessId, PVOID entry, PVOID params, PHANDLE handler)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = NULL;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}
	PUSER_THREAD_START_ROUTINE pEntry = reinterpret_cast<PUSER_THREAD_START_ROUTINE>(entry);
	KAPC_STATE apc_state = { 0 };
	KeStackAttachProcess(pEProcess, &apc_state);
	OBJECT_ATTRIBUTES obj_attr = { 0 };
	InitializeObjectAttributes(&obj_attr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwCreateThreadEx(handler, THREAD_ALL_ACCESS, &obj_attr, ZwCurrentProcess(), pEntry, params, 0, 0, 0x1000, 0x100000, NULL);
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	return status;
}

NTSTATUS process::close_handle(HANDLE ProcessId, HANDLE handler)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = NULL;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}
	KAPC_STATE apc_state = { 0 };
	KeStackAttachProcess(pEProcess, &apc_state);
	status = ZwClose(handler);
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	return status;
}
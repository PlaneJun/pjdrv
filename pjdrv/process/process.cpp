#include "process.h"
#include <Veil.h>
#include "../memory/memory.h"
#include "../symbols/symbols.hpp"


bool process::get_eprocess(const HANDLE ProcessId, PEPROCESS* pEProcess)
{
	NTSTATUS status = STATUS_SUCCESS;
	status = PsLookupProcessByProcessId(ProcessId, pEProcess);
	if (!NT_SUCCESS(status) && !MmIsAddressValid(*pEProcess))
	{
		return false;
	}
	return true;
}

NTSTATUS process::get_dir_base(const HANDLE ProcessId, PUINT64 pDataBase)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}

	*pDataBase = *reinterpret_cast<PUINT64>(reinterpret_cast<PCHAR>(pEProcess) + symbols::offsets::data_base_);
	ObDereferenceObject(pEProcess);
	return STATUS_SUCCESS;
}

PVOID process::get_module_base(const HANDLE ProcessId, const wchar_t* module_name, bool isWow64, PDWORD32 out_size)
{
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return nullptr;
	}

	PVOID retBase = nullptr;
	ULONG retSize = NULL;
	UNICODE_STRING usModuleName ={0};
	RtlInitUnicodeString(&usModuleName, module_name);
	KAPC_STATE apc_state = { 0 };
	KeStackAttachProcess(pEProcess, &apc_state);

	if (isWow64)
	{
		const PPEB32 pPeb32 = PsGetProcessWow64Process(pEProcess);
		if (!pPeb32 || !pPeb32->Ldr)
		{
			goto exit;
		}

		// SearchInLoadOrderModuleList
		PLIST_ENTRY32 pListEntry = reinterpret_cast<PLIST_ENTRY32>(pPeb32->Ldr->InLoadOrderModuleList.Flink);
		for (; pListEntry != &(pPeb32->Ldr)->InLoadOrderModuleList; pListEntry = reinterpret_cast<PLIST_ENTRY32>(pListEntry->Flink))
		{
			UNICODE_STRING ustr;
			const auto pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
			if (!MmIsAddressValid(reinterpret_cast<PVOID>(pEntry->BaseDllName.Buffer)))
			{
				continue;
			}

			RtlInitUnicodeString(&ustr, reinterpret_cast<PCWSTR>(pEntry->BaseDllName.Buffer));
			if (RtlCompareUnicodeString(&ustr, &usModuleName, TRUE) == 0)
			{
				retSize = pEntry->SizeOfImage;
				retBase = pEntry->DllBase;
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

		for (auto pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink; pListEntry != &pPeb->Ldr->InLoadOrderModuleList; pListEntry = pListEntry->Flink)
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

NTSTATUS process::rw_virtual_memory(const HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes, PSIZE_T ReturnBytes, bool Read)
{
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();

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
				Status = MmCopyVirtualMemory(temp_process,
					BaseAddress, PsGetCurrentProcess(),Buffer, BufferBytes, PreviousMode, &BytesCopied);
			}
			else
			{
				Status = MmCopyVirtualMemory(PsGetCurrentProcess(), 
					Buffer, temp_process,BaseAddress, BufferBytes, PreviousMode, &BytesCopied);
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

NTSTATUS process::alloc_virtual_memory(const HANDLE ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protect, _Out_ PVOID out_buffer)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}
	KAPC_STATE apc_state{};
	KeStackAttachProcess(pEProcess, &apc_state);
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &RegionSize, AllocationType, Protect);
	if (NT_SUCCESS(status))
	{
		RtlZeroMemory(BaseAddress, RegionSize);
	}
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	*(PULONG_PTR)out_buffer = reinterpret_cast<ULONG64>(BaseAddress);
	return status;
}

NTSTATUS process::query_virtual_memory(const HANDLE ProcessId,PVOID addr,PVOID out_buffer)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}

	PVOID64 buffer = ExAllocatePool(NonPagedPool, sizeof(MEMORY_BASIC_INFORMATION) + 0x100);
	if (MmIsAddressValid(buffer))
	{
		KAPC_STATE apc_state{};
		KeStackAttachProcess(pEProcess, &apc_state);
		status = ZwQueryVirtualMemory(NtCurrentProcess(),
			addr, MemoryBasicInformation, buffer, sizeof(MEMORY_BASIC_INFORMATION), nullptr);
		KeUnstackDetachProcess(&apc_state);
		RtlCopyMemory(out_buffer, buffer, sizeof(MEMORY_BASIC_INFORMATION));
		ExFreePool(buffer);
	}
	ObDereferenceObject(pEProcess);
	return status;
}

NTSTATUS process::free_virtual_memory(const HANDLE ProcessId, PVOID BaseAddress, SIZE_T RegionSize)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}

	KAPC_STATE apc_state{};
	KeStackAttachProcess(pEProcess, &apc_state);
	status = ZwFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, MEM_RELEASE);
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	return status;
}

void process::write_vmem_mdl(const HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes, PSIZE_T retBytes)
{
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return;
	}

	if (MmHighestUserAddress > BaseAddress && MmHighestUserAddress > (static_cast<PCHAR>(BaseAddress) + BufferBytes))
	{
		if (PsGetProcessExitStatus(pEProcess) == STATUS_PENDING)
		{
			KAPC_STATE apc_state = { nullptr };
			KeStackAttachProcess(pEProcess, &apc_state);
			if (MmIsAddressValid(BaseAddress) && MmIsAddressValid(static_cast<PCHAR>(BaseAddress) + BufferBytes))
			{
				if (const PMDL mdl = MmCreateMdl(NULL, BaseAddress, BufferBytes))
				{
					__try {
						MmBuildMdlForNonPagedPool(mdl);
						const PVOID page = MmMapLockedPages(mdl, KernelMode);
						if (page)
						{
							RtlCopyMemory(page, Buffer, BufferBytes);
						}
						MmUnmapLockedPages(page, mdl);
						IoFreeMdl(mdl);
					}
					__except(1){}
				}
			}
			KeUnstackDetachProcess(&apc_state);
		}
	}
	ObDereferenceObject(pEProcess);
}

void process::read_vmem_cpy(const HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes, PSIZE_T retBytes)
{
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return;
	}

	if (MmHighestUserAddress > BaseAddress && MmHighestUserAddress > (static_cast<PCHAR>(BaseAddress) + BufferBytes))
	{
		if (PsGetProcessExitStatus(pEProcess) == STATUS_PENDING)
		{
			KAPC_STATE apc_state{};
			KeStackAttachProcess(pEProcess, &apc_state);
			if (MmIsAddressValid(BaseAddress) && MmIsAddressValid(static_cast<PCHAR>(BaseAddress) + BufferBytes))
			{
				__try{
					ProbeForRead(BaseAddress, BufferBytes, 1);
					RtlCopyMemory(Buffer, BaseAddress, BufferBytes);
				}
				__except(1){}
			}
			KeUnstackDetachProcess(&apc_state);
		}
	}
	ObDereferenceObject(pEProcess);
}

NTSTATUS process::read_vmem_physic(const HANDLE ProcessId, PVOID BaseAddress, _Out_ PVOID Buffer, SIZE_T BufferBytes, PSIZE_T retBytes)
{
	ULONG64 uDirBase = NULL;
	NTSTATUS status = get_dir_base(ProcessId, &uDirBase);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = BufferBytes;
	while (TotalSize)
	{
		uint64_t CurPhysAddr = memory::translate_addrsss(uDirBase, reinterpret_cast<uint64_t>(BaseAddress) + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesRead = 0;
		status = memory::read_physical_addr(reinterpret_cast<PVOID64>(CurPhysAddr), static_cast<uint8_t*>(Buffer) + CurOffset, ReadSize, &BytesRead);
		TotalSize -= BytesRead;
		CurOffset += BytesRead;
		if (status != STATUS_SUCCESS)
		{
			break;
		}
		if (BytesRead == 0)
		{
			break;
		}
	}
	*retBytes = CurOffset;
	return status;
}

NTSTATUS process::write_vmem_physic(const HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes, PSIZE_T retBytes)
{
	ULONG64 uDirBase = NULL;
	NTSTATUS status = get_dir_base(ProcessId, &uDirBase);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = BufferBytes;
	while (TotalSize)
	{
		uint64_t CurPhysAddr = memory::translate_addrsss(uDirBase, reinterpret_cast<uint64_t>(BaseAddress) + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesWritten = 0;
		status = memory::write_physical_addr(reinterpret_cast<PVOID64>(CurPhysAddr), static_cast<uint8_t*>(Buffer) + CurOffset, WriteSize, &BytesWritten);
		TotalSize -= BytesWritten;
		CurOffset += BytesWritten;
		if (status != STATUS_SUCCESS)
		{
			break;
		}
		if (BytesWritten == 0)
		{
			break;
		}
	}
	*retBytes = CurOffset;
	return status;
}

NTSTATUS process::protect_vmem(const HANDLE ProcessId, PVOID BaseAddress, SIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection,PULONG OldAccessProtection)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}
	KAPC_STATE apc_state{};
	KeStackAttachProcess(pEProcess, &apc_state);
	status = ZwProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	return status;
}

NTSTATUS process::create_thread(const HANDLE ProcessId, PVOID entry, PVOID params, PHANDLE handler)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}
	auto pEntry = reinterpret_cast<PUSER_THREAD_START_ROUTINE>(entry);
	KAPC_STATE apc_state{};
	KeStackAttachProcess(pEProcess, &apc_state);
	OBJECT_ATTRIBUTES obj_attr{};
	InitializeObjectAttributes(&obj_attr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwCreateThreadEx(handler, THREAD_ALL_ACCESS, 
		&obj_attr, ZwCurrentProcess(), pEntry, params, 0, 0, 0x1000, 0x100000, nullptr);
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	return status;
}

NTSTATUS process::close_handle(const HANDLE ProcessId, HANDLE handler)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}
	KAPC_STATE apc_state{};
	KeStackAttachProcess(pEProcess, &apc_state);
	status = ZwClose(handler);
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	return status;
}
#include "process.h"
#include "../memory/memory.h"
#include "../utils/utils.h"
#include "../thread/thread.h"
#include "../module/module.h"
#include "../log/log.hpp"
#include <Veil.h>
#include "../ssdt/ssdt.h"


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

PLIST_ENTRY process::find_thread_link_by_tid(PLIST_ENTRY header,const HANDLE tid)
{
	PLIST_ENTRY unlink_entry = nullptr;

	if(!MmIsAddressValid(header))
	{
		return unlink_entry;
	}

	PLIST_ENTRY pNextLinks = header->Flink;
	while (pNextLinks->Flink != header->Flink)
	{
		PETHREAD et = reinterpret_cast<PETHREAD>(reinterpret_cast<PUCHAR>(pNextLinks) - symbols::data_.ethread.ThreadListEntry);
		CLIENT_ID ci{};
		if (!NT_SUCCESS(thread::get_Cid(et, &ci)))
		{
			// 获取失败直接返回
			break;
		}

		if (ci.UniqueThread == tid)
		{
			unlink_entry = pNextLinks;
			break;
		}

		pNextLinks = pNextLinks->Flink;
	}

	return unlink_entry;
}

PLIST_ENTRY process::find_process_link_by_pid(PLIST_ENTRY header, const HANDLE pid)
{
	PLIST_ENTRY unlink_entry = nullptr;

	PLIST_ENTRY nextNode = header->Flink;
	do
	{
		PEPROCESS ep = reinterpret_cast<PEPROCESS>(reinterpret_cast<PUCHAR>(nextNode) - symbols::data_.eprocess.ActiveProcessLinks);
		HANDLE pid_{};
		if (!NT_SUCCESS(get_UniqueProcessId(ep, &pid_)))
		{
			// 获取失败直接返回
			break;
		}

		if (pid_ == pid)
		{
			unlink_entry = nextNode;
			break;
		}
		nextNode = nextNode->Flink;
	} while (header->Flink != nextNode);

	return unlink_entry;
}

PVOID process::get_module_base(const HANDLE ProcessId, const wchar_t* module_name, PDWORD32 out_size)
{
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return nullptr;
	}

	PVOID retBase = nullptr;
	ULONG retSize = NULL;
	UNICODE_STRING usModuleName = { 0 };

	SIZE_T msize = wcslen(module_name) * 2 +1;
	PVOID lpMem = ExAllocatePool(NonPagedPool, msize*2);
	if(!lpMem)
	{
		return NULL;
	}

	memory::copy_mem_safe(lpMem, (PVOID)(module_name), msize*2);
	RtlInitUnicodeString(&usModuleName, static_cast<PCWSTR>(lpMem));

	KAPC_STATE apc_state = { 0 };
	KeStackAttachProcess(pEProcess, &apc_state);
	retBase = get_module_base_by_eprocess(pEProcess,&usModuleName,reinterpret_cast<PDWORD32>(&retSize));
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	if(retBase)
	{
		memory::write_safe<ULONG>(out_size, retSize);
	}
	ExFreePool(lpMem);
	return retBase;
}

PVOID process::get_module_base_by_eprocess(const PEPROCESS eprocess, PUNICODE_STRING module_name, PDWORD32 out_size)
{
	PVOID module_base = NULL;
	{
		const PPEB32 pPeb32 = PsGetProcessWow64Process(eprocess);
		if (!pPeb32 || !pPeb32->Ldr)
		{
			goto maby64;
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
			if (RtlCompareUnicodeString(&ustr, module_name, TRUE) == 0)
			{
				*out_size = pEntry->SizeOfImage;
				module_base = pEntry->DllBase;
				break;
			}
		}
	}

maby64:
	{
		
		PPEB pPeb = PsGetProcessPeb(eprocess);
		if (!pPeb || !pPeb->Ldr)
		{
			return NULL;
		}

		for (auto pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink; pListEntry != &pPeb->Ldr->InLoadOrderModuleList; pListEntry = pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (RtlCompareUnicodeString(&pEntry->BaseDllName, module_name, TRUE) == 0)
			{
				*out_size = pEntry->SizeOfImage;
				module_base = pEntry->DllBase;
				break;
			}
		}
	}

	return module_base;
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
	PVOID addr = BaseAddress;
	SIZE_T rsize = RegionSize;

	KAPC_STATE apc_state{};
	KeStackAttachProcess(pEProcess, &apc_state);
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &rsize, AllocationType, Protect);
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	if (NT_SUCCESS(status))
	{
		memory::write_safe<ULONG64>(out_buffer, reinterpret_cast<ULONG64>(addr));
	}
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
	if (buffer)
	{
		PVOID addr_ = addr;
		KAPC_STATE apc_state{};
		KeStackAttachProcess(pEProcess, &apc_state);
		status = ZwQueryVirtualMemory(NtCurrentProcess(),
			addr_, MemoryBasicInformation, buffer, sizeof(MEMORY_BASIC_INFORMATION), nullptr);
		KeUnstackDetachProcess(&apc_state);
		if(NT_SUCCESS(status))
		{
			memory::copy_mem_safe(out_buffer, buffer, sizeof(MEMORY_BASIC_INFORMATION));
		}
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

	PVOID addr = BaseAddress;
	SIZE_T rsize = RegionSize;
	KAPC_STATE apc_state{};
	KeStackAttachProcess(pEProcess, &apc_state);
	status = ZwFreeVirtualMemory(NtCurrentProcess(), &addr, &rsize, MEM_RELEASE);
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
			if (PVOID lpMem = ExAllocatePool(NonPagedPool, BufferBytes))
			{
				RtlZeroMemory(lpMem, BufferBytes);
				SIZE_T len = BufferBytes;
				PVOID addr = BaseAddress;
				KAPC_STATE apc_state = { nullptr };
				KeStackAttachProcess(pEProcess, &apc_state);
				if(MmIsAddressValid(BaseAddress))
				{
					if (const PMDL mdl = MmCreateMdl(nullptr, addr, len))
					{
						__try {
							MmBuildMdlForNonPagedPool(mdl); // 执行前确保addr有效，不然会炸
							const PVOID page = MmMapLockedPages(mdl, KernelMode);
							if (page)
							{
								RtlCopyMemory(page, Buffer, BufferBytes);
							}
							MmUnmapLockedPages(page, mdl);
							IoFreeMdl(mdl);
						}
						__except (1) {
						}
					}
				}
				KeUnstackDetachProcess(&apc_state);
				ExFreePool(lpMem);
			}
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

	if (MmHighestUserAddress > BaseAddress && MmHighestUserAddress > (static_cast<PUCHAR>(BaseAddress) + BufferBytes))
	{
		if (PsGetProcessExitStatus(pEProcess) == STATUS_PENDING)
		{
			if (PVOID lpMem = ExAllocatePool(NonPagedPool, BufferBytes))
			{
				RtlZeroMemory(lpMem, BufferBytes);
				SIZE_T len = BufferBytes;
				PVOID addr = BaseAddress;
				KAPC_STATE apc_state{};
				KeStackAttachProcess(pEProcess, &apc_state);
				memory::copy_mem_safe(lpMem, addr, len);
				KeUnstackDetachProcess(&apc_state);
				len = memory::copy_mem_safe(Buffer, lpMem, len);
				memory::write_safe<SIZE_T>(retBytes, len);
				ExFreePool(lpMem);
			}
		}
	}
	ObDereferenceObject(pEProcess);
}

NTSTATUS process::read_vmem_physic(const HANDLE ProcessId, PVOID BaseAddress, _Out_ PVOID Buffer, SIZE_T BufferBytes, PSIZE_T retBytes)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}

	ULONG64 uDirBase = NULL;
	if (NT_SUCCESS(get_DirectoryTableBase(pEProcess, &uDirBase)))
	{
		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = BufferBytes;
		while (TotalSize)
		{
			uint64_t CurPhysAddr = memory::translate_addrsss(uDirBase, reinterpret_cast<uint64_t>(BaseAddress) + CurOffset);
			if (!CurPhysAddr) return status;

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
		status = STATUS_SUCCESS;
	}
	ObDereferenceObject(pEProcess);
	return status;
}

NTSTATUS process::write_vmem_physic(const HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferBytes, PSIZE_T retBytes)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}

	ULONG64 uDirBase = NULL;
	if(NT_SUCCESS(get_DirectoryTableBase(pEProcess, &uDirBase)))
	{
		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = BufferBytes;
		while (TotalSize)
		{
			uint64_t CurPhysAddr = memory::translate_addrsss(uDirBase, reinterpret_cast<uint64_t>(BaseAddress) + CurOffset);
			if (!CurPhysAddr) return status;

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
		memory::write_safe<SIZE_T>(retBytes, CurOffset);
		status = STATUS_SUCCESS;
	}
	ObDereferenceObject(pEProcess);
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

	// 拷贝参数
	PVOID addr = BaseAddress;
	SIZE_T protect = NumberOfBytesToProtect;
	ULONG oldProtect = NULL;

	KAPC_STATE apc_state{};
	KeStackAttachProcess(pEProcess, &apc_state);
	status = ZwProtectVirtualMemory(NtCurrentProcess(),&addr, &protect, NewAccessProtection, &oldProtect);
	KeUnstackDetachProcess(&apc_state);
	if(NT_SUCCESS(status))
	{
		memory::write_safe<ULONG>(OldAccessProtection, oldProtect);
	}
	ObDereferenceObject(pEProcess);
	return status;
}

NTSTATUS process::create_thread(const HANDLE ProcessId, PVOID entry, PVOID params,bool no_notify,PHANDLE handler, PHANDLE tid)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}

	// 关闭通知回调；只处理了创建的，结束的时候还是可以捕获到
	if(no_notify)
	{
		utils::disable_notify_routine();
	}

	// 拷贝参数
	HANDLE hThread = nullptr;
	auto pEntry = reinterpret_cast<PUSER_THREAD_START_ROUTINE>(entry);
	HANDLE ulTid = NULL;

	KAPC_STATE apc_state{};
	KeStackAttachProcess(pEProcess, &apc_state);
	OBJECT_ATTRIBUTES obj_attr{};
	InitializeObjectAttributes(&obj_attr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	KdBreakPoint();
	const auto lpfnZwCreateThreadEx = reinterpret_cast<decltype(ZwCreateThreadEx)*>(ssdt::get_instance()->get_func_by_name("ZwCreateThreadEx"));
	if(lpfnZwCreateThreadEx)
	{
		PUCHAR PreviousMode_ptr = NULL;
		if(NT_SUCCESS(thread::get_PreviousMode(PsGetCurrentThread(), &PreviousMode_ptr)))
		{
			UCHAR prevMode = memory::read_safe<UCHAR>(PreviousMode_ptr);
			memory::write_safe<UCHAR>(PreviousMode_ptr,KernelMode);
			status = lpfnZwCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &obj_attr, ZwCurrentProcess(), pEntry, params, 0, 0, 0x1000, 0x100000, nullptr);
			memory::write_safe<UCHAR>(PreviousMode_ptr, prevMode);

			if (NT_SUCCESS(status))
			{
				// 获取创建线程的ethread
				PETHREAD pEthread = nullptr;
				if (NT_SUCCESS(ObReferenceObjectByHandle(
					hThread,
					THREAD_ALL_ACCESS,
					*PsThreadType,
					KernelMode,
					reinterpret_cast<PVOID*>(&pEthread),
					nullptr
				)))
				{
					CLIENT_ID cid{};
					status = thread::get_Cid(pEthread, &cid);
					if (NT_SUCCESS(status))
					{
						ulTid = cid.UniqueThread;
						DBG_LOG("create thread tid:%x", ulTid);
						
					}
					ObDereferenceObject(pEthread);
				}
			}
		}
	}
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);

	memory::write_safe<HANDLE>(handler, hThread);
	memory::write_safe<HANDLE>(tid, ulTid);
	if (no_notify)
	{
		utils::enable_notify_routine();
	}

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

NTSTATUS process::wait_single_object(const HANDLE ProcessId, HANDLE handle, bool alert, unsigned int wait_time)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}

	LARGE_INTEGER interval{};
	if(wait_time > 0)
	{
		// 3s = -10 * 1000 * 3000
		interval.QuadPart = -10 * 1000 * wait_time;
	}
	BOOLEAN alert_ = alert;
	KAPC_STATE apc_state{};
	KeStackAttachProcess(pEProcess, &apc_state);
	status = ZwWaitForSingleObject(handle, alert_, interval.QuadPart > 0? &interval : nullptr);
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	return status;
}

NTSTATUS process::hide_thread_by_id(const HANDLE ProcessId, HANDLE tid, bool hide)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = nullptr;
	if (!get_eprocess(ProcessId, &pEProcess))
	{
		return status;
	}

	HANDLE tid_ = tid;
	KAPC_STATE apc_state{};
	KeStackAttachProcess(pEProcess, &apc_state);

	// hide = true -> 从ThreadListEntry里断链
	// hide = false -> 因为已经断链了得去记录里查找
	PLIST_ENTRY threadListHeader = nullptr;
	if (NT_SUCCESS(get_ThreadListHead(pEProcess, &threadListHeader)))
	{
		if (hide)
		{
			// 1）断链
			if (const auto l = find_thread_link_by_tid(threadListHeader, tid))
			{
				status = utils::unlink_sync(threadListHeader, l, utils::ELIST_TYPE::Thread);
				DBG_LOG("unlink entry = %p", l);
			}

			//  2）摘句柄
			if (NT_SUCCESS(status))
			{
				status = utils::remove_handle_from_table_sync(tid);
				DBG_LOG("remove handle ok");
			}

		}
		else
		{
			// 这里需要关注恢复的顺序，如果先恢复断链,会因为抹句柄的原因，内部is_alive函数判断不成功
			// 所以这里需要先恢复句柄
			if (NT_SUCCESS(utils::resume_handle_sync(tid)))
			{
				status = utils::link_sync(threadListHeader, tid, utils::ELIST_TYPE::Process);
			}
			if (NT_SUCCESS(status))
			{
				DBG_LOG("resume ok");
			}
		}
	}

	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEProcess);
	return status;
}

NTSTATUS process::hide_process_by_id(const HANDLE ProcessId, bool hide)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	do
	{
		PLIST_ENTRY activity_process = nullptr;
		if (!NT_SUCCESS(get_ActiveProcessLinks(PsGetCurrentProcess(), &activity_process)))
		{
			break;
		}

		if (hide)
		{
			// 先断链
			if (const auto l = find_process_link_by_pid(activity_process,ProcessId))
			{
				status = utils::unlink_sync(activity_process, l, utils::ELIST_TYPE::Process);
			}

			// 抹句柄
			if (NT_SUCCESS(status))
			{
				status = utils::remove_handle_from_table_sync(ProcessId);
			}
		}
		else
		{
			// 这里需要关注恢复的顺序，如果先恢复断链,会因为抹句柄的原因，内部is_alive函数判断不成功
			// 所以这里需要先恢复句柄
			if(NT_SUCCESS(utils::resume_handle_sync(ProcessId)))
			{
				status = utils::link_sync(activity_process, ProcessId, utils::ELIST_TYPE::Process);
			}
			if (NT_SUCCESS(status))
			{
				DBG_LOG("resume ok");
			}
		}
	}while(false);

	return status;

}

bool process::is_alive(const HANDLE ProcessId)
{
	PEPROCESS tmp = nullptr;
	if(get_eprocess(ProcessId, &tmp))
	{
		ObDereferenceObject(tmp);
		return true;
	}
	return false;
}

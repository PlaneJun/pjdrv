#include "control.h"
#include <stdint.h>

#include "../memory/memory.h"
#include "../module/module.h"
#include "../utils/utils.h"
#include "../symbols/symbols.hpp"
#include "../device/mouse.h"
#include "../device/keybd.h"
#include "../process/process.h"

#include "../../share/communicate.h"
#include "../log/log.hpp"

void IoDispatch(communicate::PParams pdata);

#ifdef IO_ahcache

unsigned char hkAslLogCallPrintf[] =
{
	0x15, //XOR_KEY
	0x59, 0x9c, 0x59, 0x31, 0x35, 0x59, 0x9c, 0x51,
	0x31, 0xd, 0x5d, 0x9c, 0x41, 0x31, 0x5, 0x9c,
	0x59, 0x31, 0x1d, 0x5d, 0x96, 0xf9, 0x5d, 0x5d,
	0xad, 0x7, 0x84, 0x6d, 0x43, 0x21, 0x7, 0x15,
	0x15, 0x5d, 0x9c, 0x51, 0x31, 0x3d, 0x5d, 0x9e,
	0x51, 0x31, 0x3d, 0xea, 0x5, 0x5d, 0x9c, 0x51,
	0x31, 0x25, 0x5d, 0x9e, 0x59, 0x31, 0x25, 0x5d,
	0x9e, 0x51, 0x31, 0x3d, 0xea, 0x45, 0x1d, 0x1a,
	0xa3, 0xd5, 0x90, 0xd5, 0x61, 0x79, 0x5d, 0x9e,
	0x51, 0x31, 0x25, 0x5d, 0x9e, 0x55, 0x2d, 0x5d,
	0x9c, 0x51, 0x31, 0x35, 0x5d, 0x9e, 0x51, 0x31,
	0x25, 0x5d, 0xd2, 0x55, 0x2d, 0x15, 0x15, 0x15,
	0x15, 0x5d, 0x96, 0x69, 0x31, 0x35, 0x15, 0x61,
	0x5c, 0x5d, 0x9e, 0x59, 0x31, 0x35, 0x5d, 0x9e,
	0x51, 0x31, 0x3d, 0xea, 0x45, 0x1d, 0x1a, 0xa3,
	0xd5, 0x90, 0xd5, 0x61, 0x20, 0xaf, 0x3d, 0x15,
	0x15, 0x15, 0x5d, 0x9e, 0x59, 0x31, 0x35, 0x5d,
	0x9e, 0x51, 0x31, 0x3d, 0xea, 0x45, 0x5, 0x5d,
	0x8d, 0x5d, 0x9e, 0x59, 0x31, 0x35, 0x5d, 0x9c,
	0x54, 0xd, 0x5d, 0x9e, 0x51, 0x31, 0x35, 0x96,
	0x6d, 0xd, 0x15, 0x69, 0x18, 0x5d, 0x9e, 0x51,
	0x31, 0x35, 0x5d, 0xd2, 0x55, 0xd, 0x32, 0x15,
	0x15, 0xd5, 0xa5, 0x14, 0x5d, 0x96, 0xd1, 0x5d,
	0xd6
};

PVOID g_AslLogPfnVPrintf = nullptr;
PVOID find_control_ptr()
{
	uintptr_t ahcache_base = NULL;
	size_t ahcache_size = NULL;
	NTSTATUS status = module::get_kernel_module("ahcache.sys", &ahcache_base, &ahcache_size);
	if (!NT_SUCCESS(status))
	{
		return nullptr;
	}

	static uint8_t Pattern[] = {
		0x4C, 0x89, 0x4C, 0x24, 0xCC, 0x48, 0x83, 0xEC, 0xCC, 0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x85,
		0xC0, 0xCC
	};
	g_AslLogPfnVPrintf = memory::find_pattern_in_module(ahcache_base, "PAGE", Pattern, sizeof(Pattern), 9);
	if (!MmIsAddressValid(g_AslLogPfnVPrintf))
		return nullptr;
	return g_AslLogPfnVPrintf;
}
#else

PDEVICE_OBJECT g_device = nullptr;
UNICODE_STRING g_undevice_name = RTL_CONSTANT_STRING(L"\\Device\\rongshen_device");
UNICODE_STRING g_unsymlink_name = RTL_CONSTANT_STRING(L"\\??\\rongshen_link");

NTSTATUS common_dispatch(PDRIVER_OBJECT device, PIRP pIrp)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG control_code = stack->Parameters.DeviceIoControl.IoControlCode;
	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS io_dispatch(IN PDEVICE_OBJECT lpDeviceObject, IN PIRP lpIrp)
{

	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION lpIoStackLocation = nullptr;
	ULONG IoCtrlCode = 0;
	ULONG ReturnLength = 0;

	lpIoStackLocation = IoGetCurrentIrpStackLocation(lpIrp);		//获取当前IRP的调用栈空间
	IoCtrlCode = lpIoStackLocation->Parameters.DeviceIoControl.IoControlCode;	//得到在Ring3程序中传入的IO控制码
	switch (IoCtrlCode)
	{
		case IOCTL_NEITHER:
		{
			// 通信
			IoDispatch(static_cast<communicate::PParams>(lpIoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer));
			break;
		}
		default:
		{
			Status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
	}

	lpIrp->IoStatus.Status = Status;
	lpIrp->IoStatus.Information = ReturnLength;
	IoCompleteRequest(lpIrp, IO_NO_INCREMENT);
	return Status;
}

#endif


void IoDispatch(communicate::PParams pdata)
{
	NTSTATUS status = STATUS_SUCCESS;
	do
	{
		if (!MmIsAddressValid(pdata->buffer))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		DBG_LOG("pdata->buffer = %p", pdata->buffer);
		switch (pdata->cmd)
		{
			case communicate::ECMD::CMD_CONTROL:
			{
				memory::write_safe<int>(pdata->buffer, 1);
				DBG_LOG("inti buffer = %p", pdata->buffer);
				break;
			}
			case communicate::ECMD::CMD_R3_GetProcessModules:
			{
				communicate::PModule p_module = static_cast<decltype(p_module)>(pdata->buffer);
				p_module->output = process::get_module_base(reinterpret_cast<HANDLE>(pdata->pid), static_cast<const wchar_t*>(p_module->module_name), &p_module->module_size);
				if (!p_module->output)
				{
					status = STATUS_UNSUCCESSFUL;
				}
				break;
			}
			case communicate::ECMD::CMD_R3_GetExportFunction:
			{
				communicate::PModule p_module = static_cast<decltype(p_module)>(pdata->buffer);
				PEPROCESS pEProcess = nullptr;
				if (process::get_eprocess(reinterpret_cast<HANDLE>(pdata->pid), &pEProcess))
				{
					auto funName = static_cast<PCHAR>(ExAllocatePool(NonPagedPool, strlen(static_cast<char const*>(p_module->module_name)) + 1));
					memcpy(funName, p_module->module_name, strlen(static_cast<PCCHAR>(p_module->module_name)) + 1);

					KAPC_STATE apc_state = { nullptr };
					KeStackAttachProcess(pEProcess, &apc_state);
					p_module->output = module::get_module_export(p_module->module_base, funName);
					KeUnstackDetachProcess(&apc_state);
					ObDereferenceObject(pEProcess);
				}
				break;
			}
			case communicate::ECMD::CMD_R3_QueryVirtualMemory:
			{
				communicate::PMemory p_mem = static_cast<decltype(p_mem)>(pdata->buffer);
				status = process::query_virtual_memory(reinterpret_cast<HANDLE>(pdata->pid), p_mem->addr,
														p_mem->output);
				break;
			}
			case communicate::ECMD::CMD_R3_ProtectVirtualMemory:
			{
				communicate::PMemory p_mem = static_cast<decltype(p_mem)>(pdata->buffer);
				status = process::protect_vmem(reinterpret_cast<HANDLE>(pdata->pid), p_mem->addr,
											 p_mem->length, p_mem->proctect, &p_mem->oldprotect);
				break;
			}
			case communicate::ECMD::CMD_R3_AllocMemory:
			{
				communicate::PMemory p_mem = static_cast<decltype(p_mem)>(pdata->buffer);
				status = process::alloc_virtual_memory(reinterpret_cast<HANDLE>(pdata->pid), p_mem->addr,
														p_mem->length, p_mem->alloctype,
														p_mem->proctect, p_mem->output);
				break;
			}
			case communicate::ECMD::CMD_R3_ReadMemory:
			{
				communicate::PMemory p_mem = static_cast<decltype(p_mem)>(pdata->buffer);
				switch (p_mem->rw_type)
				{
					case communicate::ERWTYPE::MmCopy:
					{
						status = process::rw_virtual_memory(reinterpret_cast<HANDLE>(pdata->pid), p_mem->addr,
															p_mem->output, p_mem->length, &p_mem->ret_bytes, true);
						break;
					}
					case communicate::ERWTYPE::Mdl:
					{
						process::read_vmem_cpy(reinterpret_cast<HANDLE>(pdata->pid), p_mem->addr,
													  p_mem->output, p_mem->length, &p_mem->ret_bytes);
						break;
					}
					case communicate::ERWTYPE::Phycical:
					{
						status = process::read_vmem_physic(reinterpret_cast<HANDLE>(pdata->pid), p_mem->addr,
														  p_mem->output, p_mem->length, &p_mem->ret_bytes);
						break;
					}
				}
				break;
			}
			case communicate::ECMD::CMD_R3_WriteMemory:
			{
				communicate::PMemory p_mem = static_cast<decltype(p_mem)>(pdata->buffer);
				switch (p_mem->rw_type)
				{
					case communicate::ERWTYPE::MmCopy:
					{
						status = process::rw_virtual_memory(reinterpret_cast<HANDLE>(pdata->pid),
															p_mem->addr, p_mem->buffer,
															p_mem->length, &p_mem->ret_bytes, false);
						break;
					}
					case communicate::ERWTYPE::Mdl:
					{
						process::write_vmem_mdl(reinterpret_cast<HANDLE>(pdata->pid), p_mem->addr,
														p_mem->buffer, p_mem->length, &p_mem->ret_bytes);
						break;
					}
					case communicate::ERWTYPE::Phycical:
					{
						status = process::write_vmem_physic(reinterpret_cast<HANDLE>(pdata->pid),
															p_mem->addr, p_mem->buffer,
															p_mem->length, &p_mem->ret_bytes);
						break;
					}
				}
				break;
			}
			case communicate::ECMD::CMD_R3_FreeMemory:
			{
				communicate::PMemory p_mem = static_cast<decltype(p_mem)>(pdata->buffer);
				status = process::free_virtual_memory(reinterpret_cast<HANDLE>(pdata->pid), p_mem->addr,
													  p_mem->length);
				break;
			}
			case communicate::ECMD::CMD_R3_CreateThread:
			{
				communicate::PThread p_thread = static_cast<decltype(p_thread)>(pdata->buffer);
				status = process::create_thread(reinterpret_cast<HANDLE>(pdata->pid),
											  p_thread->entry,
											  p_thread->params,
											  p_thread->hide,
											  &p_thread->handler,
											  &p_thread->threadid);
				break;
			}
			case communicate::ECMD::CMD_R3_WaitSingleObject:
			{
				communicate::PThread p_thread = static_cast<decltype(p_thread)>(pdata->buffer);
				status = process::wait_single_object(reinterpret_cast<HANDLE>(pdata->pid), p_thread->handler, p_thread->alert, p_thread->wait_time);

			}
			case communicate::ECMD::CMD_R3_CloseHandle:
			{
				communicate::PThread p_thread = static_cast<decltype(p_thread)>(pdata->buffer);
				status = process::close_handle(reinterpret_cast<HANDLE>(pdata->pid), p_thread->handler);
				break;
			}
			case communicate::ECMD::cmd_R3_HideThread:
			{
				communicate::PThread p_thread = static_cast<decltype(p_thread)>(pdata->buffer);
				status = process::hide_thread_by_id(reinterpret_cast<HANDLE>(pdata->pid),p_thread->threadid,p_thread->hide);
				break;
			}
			case communicate::ECMD::CMD_R3_KbdEvent:
			{
				if (NT_SUCCESS(Keybd::init()))
				{
					communicate::PDevice p_device = static_cast<decltype(p_device)>(pdata->buffer);
					Keybd::keybd_event_(p_device->keycode, p_device->flags);
				}
				break;
			}
			case communicate::ECMD::CMD_R3_MouseEvent:
			{
				if (NT_SUCCESS(Mouse::init()))
				{
					communicate::PDevice p_device = static_cast<decltype(p_device)>(pdata->buffer);
					Mouse::mouse_event_(p_device->mx, p_device->my, p_device->flags);
				}
				break;
			}
			case communicate::ECMD::CMD_Symbol:
			{
				communicate::PSymbols p_symbols = static_cast<decltype(p_symbols)>(pdata->buffer);
				ULONG size = NULL;
				ULONG64 ntBase = reinterpret_cast<ULONG64>(module::get_ntoskrnl_base(&size));
				symbols::data_ = *p_symbols;
				symbols::data_.global.PspNotifyEnableMask += ntBase;
				symbols::data_.global.KeServiceDescriptorTable += ntBase;
				symbols::data_.global.ExMapHandleToPointer += ntBase;
				symbols::data_.global.ExDestroyHandle += ntBase;
				symbols::data_.global.PspCidTable += ntBase;
				break;
			}
		}
	} while (false);

	pdata->status = status;
}

void Control::install(PDRIVER_OBJECT pDrv)
{
#ifdef IO_ahcache

	g_AslLogPfnVPrintf = find_control_ptr();
	if (g_AslLogPfnVPrintf == nullptr)
	{
		return;
	}

	//alloc memmory
	PHYSICAL_ADDRESS lowRange = { 0 };
	PHYSICAL_ADDRESS hightRange = { -1 };
	PULONG_PTR lpMem = nullptr;
	for (int i = 0; i < 10; i++)
	{
		lpMem = static_cast<PULONG_PTR>(MmAllocateContiguousMemorySpecifyCache(
			PAGE_SIZE, lowRange, hightRange, lowRange, MmCached));
		if (lpMem)
			break;
	}

	if (!lpMem)
	{
		return;
	}

	//fill
	lpMem[0] = reinterpret_cast<uintptr_t>(utils::get_system_function(L"PsGetCurrentThreadTeb"));
	lpMem[1] = reinterpret_cast<uintptr_t>(utils::get_system_function(L"MmIsAddressValid"));
	lpMem[2] = reinterpret_cast<uintptr_t>(IoDispatch);

	//decrypt && copy
	auto entry = reinterpret_cast<uint8_t*>(&lpMem[3]);
	for (int i = 1; i < sizeof(hkAslLogCallPrintf); i++)
		entry[i - 1] = hkAslLogCallPrintf[i] ^ hkAslLogCallPrintf[0];

	//fix [mov rax, 123456789112]
	for (int i = 0; i < 50; i++)
	{
		ULONG64* tagPtr = reinterpret_cast<ULONG64*>(&entry[i]);
		if (*tagPtr == 0x123456789112)
		{
			*tagPtr = reinterpret_cast<ULONG64>(lpMem);
		}

	}
	//set point
	PHYSICAL_ADDRESS tmp = MmGetPhysicalAddress(g_AslLogPfnVPrintf);
	auto map = static_cast<PULONG_PTR>(MmMapIoSpace(tmp, 8, MmNonCached));
	if (map)
	{
		*map = reinterpret_cast<ULONG64>(entry);
		MmUnmapIoSpace(map, 8);
	}

#else

	NTSTATUS status = IoCreateDevice(pDrv, 0, &g_undevice_name, FILE_DEVICE_UNKNOWN, 0, 0, &g_device);
	if (!NT_SUCCESS(status))
	{
		DBG_LOG("create virtual device failed,err:%x", status);
		return;
	}
	status = IoCreateSymbolicLink(&g_unsymlink_name, &g_undevice_name);
	if (!NT_SUCCESS(status))
	{
		DBG_LOG("create symbol link failed,err:%x", status);
		return;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		if (i == IRP_MJ_DEVICE_CONTROL)
		{
			pDrv->MajorFunction[i] = (PDRIVER_DISPATCH)io_dispatch;
		}
		else
		{
			pDrv->MajorFunction[i] = (PDRIVER_DISPATCH)(common_dispatch);
		}
	}
#endif

}

void Control::uninstall()
{
#ifdef IO_ahcache

	if (g_AslLogPfnVPrintf)
	{
		PHYSICAL_ADDRESS tmp = MmGetPhysicalAddress(g_AslLogPfnVPrintf);
		auto map = static_cast<PULONG_PTR>(MmMapIoSpace(tmp, 8, MmNonCached));
		if (map)
		{
			*map = NULL;
			MmUnmapIoSpace(map, 8);
		}
	}

#else
	IoDeleteSymbolicLink(&g_unsymlink_name);
	IoDeleteDevice(g_device);
#endif
}

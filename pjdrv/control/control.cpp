#include "control.h"
#include <stdint.h>

#include "../memory/memory.h"
#include "../module/module.h"
#include "../utils/utils.h"
#include "../symbols/symbols.hpp"
#include "../device/mouse.h"
#include "../device/keybd.h"
#include "../process/process.h"

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

void IoDispatch(Control::PDataParams pdata)
{
	switch (pdata->cmd)
	{
	case Control::ECMD::CMD_CONTROL:
		{
			pdata->cmd = 1;
			break;
		}
	case Control::ECMD::CMD_GetProcessModules:
		{
			pdata->params.m.output = process::get_module_base(reinterpret_cast<HANDLE>(pdata->pid),
			                                                  static_cast<const wchar_t*>(pdata->params.m.module_name),
			                                                  pdata->params.m.wow64, &pdata->params.m.module_size);
			break;
		}
	case Control::ECMD::CMD_GetExportFunction:
		{
			PEPROCESS pEProcess = nullptr;
			if (process::get_eprocess(reinterpret_cast<HANDLE>(pdata->pid), &pEProcess))
			{
				auto funName = static_cast<PCHAR>(ExAllocatePool(NonPagedPool,strlen(static_cast<char const*>(pdata->params.m.module_name)) + 1));
				memcpy(funName, pdata->params.m.module_name,
				       strlen(static_cast<PCCHAR>(pdata->params.m.module_name)) + 1);

				KAPC_STATE apc_state = {nullptr};
				KeStackAttachProcess(pEProcess, &apc_state);
				pdata->params.m.output = module::get_module_export(pdata->params.m.module_base, funName);
				KeUnstackDetachProcess(&apc_state);
				ObDereferenceObject(pEProcess);
			}
			break;
		}
	case Control::ECMD::CMD_QueryVirtualMemory:
		{
			process::query_virtual_memory(reinterpret_cast<HANDLE>(pdata->pid), pdata->params.mem.addr,
			                              pdata->params.mem.output);
			break;
		}
	case Control::ECMD::CMD_ProtectVirtualMemory:
		{
			process::protect_vmem(reinterpret_cast<HANDLE>(pdata->pid), pdata->params.mem.addr,
			                      pdata->params.mem.length, pdata->params.mem.proctect, &pdata->params.mem.oldprotect);
			break;
		}
	case Control::ECMD::CMD_AllocMemory:
		{
			process::alloc_virtual_memory(reinterpret_cast<HANDLE>(pdata->pid), pdata->params.mem.addr,
			                              pdata->params.mem.length, pdata->params.mem.alloctype,
			                              pdata->params.mem.proctect, pdata->params.mem.output);
			break;
		}
	case Control::ECMD::CMD_ReadMemory:
		{
			switch (pdata->params.mem.rw_type)
			{
			case Control::ERWTYPE::MmCopy:
				{
					process::rw_virtual_memory(reinterpret_cast<HANDLE>(pdata->pid), pdata->params.mem.addr,
					                           pdata->params.mem.output, pdata->params.mem.length, nullptr, true);
					break;
				}
			case Control::ERWTYPE::MDL:
				{
					process::read_vmem_cpy(reinterpret_cast<HANDLE>(pdata->pid), pdata->params.mem.addr,
					                       pdata->params.mem.output, pdata->params.mem.length, &pdata->params.mem.retByte);
					break;
				}
			case Control::ERWTYPE::PHYSICAL:
				{
					process::read_vmem_physic(reinterpret_cast<HANDLE>(pdata->pid), pdata->params.mem.addr,
					                          pdata->params.mem.output, pdata->params.mem.length, &pdata->params.mem.retByte);
					break;
				}
			}
			break;
		}
	case Control::ECMD::CMD_WriteMemory:
		{
			switch (pdata->params.mem.rw_type)
			{
			case Control::ERWTYPE::MmCopy:
				{
					process::rw_virtual_memory(reinterpret_cast<HANDLE>(pdata->pid),
					                           pdata->params.mem.addr, pdata->params.mem.buffer,
					                           pdata->params.mem.length, nullptr, false);
					break;
				}
			case Control::ERWTYPE::MDL:
				{
					process::write_vmem_mdl(reinterpret_cast<HANDLE>(pdata->pid), pdata->params.mem.addr,
					                        pdata->params.mem.buffer, pdata->params.mem.length, &pdata->params.mem.retByte);
					break;
				}
			case Control::ERWTYPE::PHYSICAL:
				{
					process::write_vmem_physic(reinterpret_cast<HANDLE>(pdata->pid),
					                           pdata->params.mem.addr, pdata->params.mem.buffer,
					                           pdata->params.mem.length,&pdata->params.mem.retByte);
					break;
				}
			}
			break;
		}
	case Control::ECMD::CMD_FreeMemory:
		{
			process::free_virtual_memory(reinterpret_cast<HANDLE>(pdata->pid), pdata->params.mem.addr,
			                             pdata->params.mem.length);
			break;
		}
	case Control::ECMD::CMD_CreateThread:
		{
			process::create_thread(reinterpret_cast<HANDLE>(pdata->pid), pdata->params.thread.entry,
			                       pdata->params.thread.params, &pdata->params.thread.handler);
			break;
		}
	case Control::ECMD::CMD_Close:
		{
			process::close_handle(reinterpret_cast<HANDLE>(pdata->pid), pdata->params.thread.handler);
			break;
		}
	case Control::ECMD::CMD_KbdEvent:
		{
			if (NT_SUCCESS(Keybd::init()))
			{
				Keybd::keybd_event_(pdata->params.device.keycode, pdata->params.device.flags);
			}
			break;
		}
	case Control::ECMD::CMD_MouseEvent:
		{
			if (NT_SUCCESS(Mouse::init()))
			{
				Mouse::mouse_event_(pdata->params.device.mx, pdata->params.device.my, pdata->params.device.flags);
			}
			break;
		}
	case Control::ECMD::CMD_Symbol:
		{
			ULONG size = NULL;
			ULONG64 ntBase = reinterpret_cast<ULONG64>(module::get_ntoskrnl_base(&size));
			symbols::offsets::vad_root_ = pdata->params.symbs.vad_root;
			symbols::global::KeServiceDescriptorTable_ = ntBase + pdata->params.symbs.KeServiceDescriptorTable;
			symbols::offsets::data_base_ = pdata->params.symbs.data_base;
			break;
		}
	}
}

PVOID Control::find_control_ptr()
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
	AslLogPfnVPrintf_ = memory::find_pattern_in_module(ahcache_base, "PAGE", Pattern, sizeof(Pattern), 9);
	if (!MmIsAddressValid(AslLogPfnVPrintf_))
		return nullptr;
	return AslLogPfnVPrintf_;
}

void Control::install()
{
	AslLogPfnVPrintf_ = find_control_ptr();
	if (AslLogPfnVPrintf_ == nullptr)
	{
		return;
	}

	//alloc memmory
	PHYSICAL_ADDRESS lowRange = {0};
	PHYSICAL_ADDRESS hightRange = {-1};
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
	PHYSICAL_ADDRESS tmp = MmGetPhysicalAddress(AslLogPfnVPrintf_);
	auto map = static_cast<PULONG_PTR>(MmMapIoSpace(tmp, 8, MmNonCached));
	if (map)
	{
		*map = reinterpret_cast<ULONG64>(entry);
		MmUnmapIoSpace(map, 8);
	}
}

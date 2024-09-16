#include "ssdt.h"

#include <intrin.h>

#include "../module/module.h"

ssdt* ssdt::instance_ = nullptr;

ssdt* ssdt::get_instance()
{
	if(instance_ == nullptr)
	{
		instance_ = new ssdt();
		instance_->GetKeServiceDescriptorTableAddrX64();
	}
	return instance_;
}

uintptr_t ssdt::get_func_by_index(uint32_t index)
{
	if (KeServiceDescriptorTable_ == NULL)
		return 0;

	LONG dwtmp = 0;
	ULONGLONG addr = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)KeServiceDescriptorTable_->ServiceTableBase;
	dwtmp = ServiceTableBase[index];
	dwtmp = dwtmp >> 4;
	addr = ((LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase);
	return addr;
}

uintptr_t ssdt::get_func_by_name(const char* funname)
{
	if (KeServiceDescriptorTable_ == NULL)
		return 0;

	HANDLE hNtdll = module::kernel_load_library(L"\\SystemRoot\\System32\\ntdll.dll");
	if (!hNtdll)
	{
		return FALSE;
	}
	PUCHAR lpFunc = (PUCHAR)module::get_module_export(hNtdll, funname);
	if (!lpFunc)
		return NULL;
	//get service_id
	ULONG id = *(PULONG)((PUCHAR)lpFunc + 4);
	return (ULONG64)get_func_by_index(id);
}

VOID ssdt::GetKeServiceDescriptorTableAddrX64()
{
	PUCHAR StartSearchAddress = NULL;
	PUCHAR EndSearchAddress = NULL;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	LONG templong = 0;
	ULONGLONG addr = 0;
	RTL_OSVERSIONINFOW Version = { 0 };
	Version.dwOSVersionInfoSize = sizeof(Version);
	RtlGetVersion(&Version);
	if (Version.dwBuildNumber >= 17763)
	{
		StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
		for (i = StartSearchAddress; i < StartSearchAddress + 0x500; i++)
		{
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 5))
			{
				b1 = *i;
				b2 = *(i + 5);
				if (b1 == 0xe9 && b2 == 0xc3)
				{
					memcpy(&templong, i + 1, 4);
					StartSearchAddress = i + 5 + templong;
					break;
				}
			}
		}
	}
	else {
		StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	}
	EndSearchAddress = StartSearchAddress + 0x500;
	for (i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *(i);
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)
			{
				memcpy(&templong, i + 3, 4);
				//核心部分
				//kd> db fffff800`03e8b772
				//fffff800`03e8b772  4c 8d 15 c7 20 23 00 4c-8d 1d 00 21 23 00 f7 83  L... #.L...!#...
				//templong = 002320c7 ,i = 03e8b772, 7为指令长度
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				break;
			}
		}
	}
	KeServiceDescriptorTable_ = (PSYSTEM_SERVICE_TABLE)addr;
	//KeServiceDescriptorTable_ = (PSYSTEM_SERVICE_TABLE)symbols::global::KeServiceDescriptorTable_;
}

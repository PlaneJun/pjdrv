#include "utils.h"

#include <map>
#include <vector>

#include "../module/module.h"
#include "../symbols/symbols.hpp"
#include "../memory/memory.h"
#include "../log/log.hpp"

// 记录所有断链的节点
std::map<PLIST_ENTRY, std::vector<PLIST_ENTRY>> g_unlinks{};

typedef struct _HANDLE_TABLE* PHANDLE_TABLE;
typedef struct HANDLE_TABLE_ENTRY* PHANDLE_TABLE_ENTRY;

PVOID utils::get_system_function(const wchar_t* funcname)
{
	PVOID retAddr = nullptr;
	if (funcname)
	{
		UNICODE_STRING fun_name = { 0 };
		RtlInitUnicodeString(&fun_name, funcname);
		retAddr = MmGetSystemRoutineAddress(&fun_name);
	}
	return retAddr;
}

VOID utils::disable_notify_routine()
{
	PVOID PspNotifyEnableMask = reinterpret_cast<PVOID>(symbols::data_.global.PspNotifyEnableMask);
	if (!MmIsAddressValid(PspNotifyEnableMask))
	{
		return;
	}

	UCHAR mask = memory::read_safe<UCHAR>(PspNotifyEnableMask);
	if ((mask & 8) != 0)
	{
		memory::write_safe<UCHAR>(PspNotifyEnableMask, mask & ~8);
	}
}

VOID utils::enable_notify_routine()
{
	PVOID PspNotifyEnableMask = reinterpret_cast<PVOID>(symbols::data_.global.PspNotifyEnableMask);
	if(!MmIsAddressValid(PspNotifyEnableMask))
	{
		return;
	}

	UCHAR mask = memory::read_safe<UCHAR>(PspNotifyEnableMask);
	if ((mask & 8) == 0)
	{
		memory::write_safe<UCHAR>(PspNotifyEnableMask, mask | 8);
	}
}

NTSTATUS utils::remove_handle_from_table(HANDLE handle)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	do
	{
		if (symbols::data_.global.ExMapHandleToPointer == NULL || symbols::data_.global.ExDestroyHandle == NULL || symbols::data_.global.PspCidTable == NULL)
		{
			break;
		}

		PHANDLE_TABLE_ENTRY(NTAPI * ExMapHandleToPointer)(
			__in  PHANDLE_TABLE HandleTable,
			__in  HANDLE Handle
		) = reinterpret_cast<PHANDLE_TABLE_ENTRY(*)(PHANDLE_TABLE HandleTable, HANDLE Handle)>(symbols::data_.global.ExMapHandleToPointer);

		if (!MmIsAddressValid(ExMapHandleToPointer))
		{
			break;
		}

		BOOLEAN(NTAPI * ExDestroyHandle)(
			__in  PHANDLE_TABLE HandleTable,
			__in  HANDLE Handle,
			__inout_opt PHANDLE_TABLE_ENTRY HandleTableEntry
		) = reinterpret_cast<BOOLEAN(*)(PHANDLE_TABLE HandleTable, HANDLE Handle, PHANDLE_TABLE_ENTRY HandleTableEntry)>(symbols::data_.global.ExDestroyHandle);

		if (!MmIsAddressValid(ExDestroyHandle))
		{
			break;
		}

		PHANDLE_TABLE PspCidTable = memory::read_safe<PHANDLE_TABLE>(reinterpret_cast<PVOID>(symbols::data_.global.PspCidTable));
		if(!MmIsAddressValid(PspCidTable))
		{
			break;
		}

		PHANDLE_TABLE_ENTRY ptr = ExMapHandleToPointer(PspCidTable, handle);
		if (ptr == nullptr)
		{
			break;
		}
		DBG_LOG("ptr = 0x%p", ptr);

		status = ExDestroyHandle(PspCidTable, handle, ptr) ? STATUS_SUCCESS : status;
		DBG_LOG("destroy handle: %x,done!", handle);

	} while (false);

	return status;
}

void utils::unlink(PLIST_ENTRY entryList, PLIST_ENTRY node)
{
	if (!MmIsAddressValid(node) || !MmIsAddressValid(node))
	{
		return;
	}

	RemoveEntryList(node);
	if (g_unlinks.count(entryList) == 0)
	{
		g_unlinks[entryList] = {};
	}
	g_unlinks[entryList].push_back(node);
}

void utils::link(PLIST_ENTRY entryList, PLIST_ENTRY node)
{
	if (!MmIsAddressValid(node))
	{
		return;
	}

	InsertTailList(entryList, node);

	// 删除记录中的节点
	if (g_unlinks.count(entryList) > 0)
	{
		// 找对应节点
		int i = 0;
		for (i = 0; i < g_unlinks[entryList].size(); i++)
		{
			if (g_unlinks[entryList][i] == node)
			{
				g_unlinks[entryList].erase(g_unlinks[entryList].begin() + i);
				break;
			}
		}
	}
}


void utils::resume_all_unlink()
{
	auto bak = g_unlinks;
	for (const auto& t : bak)
	{
		for (const auto& n : t.second)
		{
			link(t.first, n);
		}
	}
	g_unlinks.clear();
}
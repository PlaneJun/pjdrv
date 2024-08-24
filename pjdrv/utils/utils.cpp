#include "utils.h"

#include <map>
#include <vector>

#include "../module/module.h"
#include "../symbols/symbols.hpp"
#include "../memory/memory.h"
#include "../thread/thread.h"
#include "../process/process.h"
#include "../log/log.hpp"

// 记录所有断链的节点
struct Custom_LinkValue
{
	HANDLE id;

	// 1、当node被作为key时，等于对应id的链表头
	// 2、当node被作为value时，等于对应id被断链的节点
	PLIST_ENTRY node;	
};

struct Custom_LinkKey
{
	utils::ELIST_TYPE type;
	Custom_LinkValue info;

	bool operator<(const Custom_LinkKey& other) const {
		return info.id < other.info.id;
	}
};

std::map<Custom_LinkKey, std::vector<Custom_LinkValue>> g_unlinks{};

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

NTSTATUS utils::unlink(PLIST_ENTRY entryList, PLIST_ENTRY node, ELIST_TYPE type)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	do
	{
		if (!MmIsAddressValid(entryList) || !MmIsAddressValid(node))
		{
			break;
		}

		Custom_LinkKey key{};
		key.type = type;
		key.info.node = entryList;
		if (type == Process)
		{
			HANDLE pid{};
			if (NT_SUCCESS(process::get_UniqueProcessId(reinterpret_cast<PEPROCESS>(
				reinterpret_cast<PUCHAR>(entryList) - symbols::data_.eprocess.UniqueProcessId), &pid)))
			{
				key.info.id = pid;
			}
			else
			{
				break;
			}
		}
		else if (type == Thread)
		{
			CLIENT_ID cid{};
			if (NT_SUCCESS(thread::get_Cid(reinterpret_cast<PETHREAD>(
				reinterpret_cast<PUCHAR>(entryList) - symbols::data_.ethread.ThreadListEntry), &cid)))
			{
				key.info.id = cid.UniqueThread;
			}
			else
			{
				break;
			}
		}

		// insert
		if (g_unlinks.count(key) == 0)
		{
			g_unlinks[key] = {};
		}

		Custom_LinkValue info{};
		info.node = node;
		g_unlinks[key].push_back(info);
		RemoveEntryList(node);
		status = STATUS_SUCCESS;
	}
	while (false);
	return status;
}

NTSTATUS utils::link(PLIST_ENTRY entryList, HANDLE id, ELIST_TYPE type)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!MmIsAddressValid(entryList))
	{
		return status;
	}

	// 要恢复的节点
	PLIST_ENTRY node = nullptr;
	for(auto& k : g_unlinks)
	{
		// 确保链表头来源与参数一致
		if(k.first.info.node == entryList && k.first.type == type)
		{
			// 查找对应handle的节点
			int i=0;
			for(i = 0; i < k.second.size(); i++)
			{
				if(k.second[i].id == id)
				{
					node = k.second[i].node;
					break;
				}
			}

			if(node)
			{
				// 如果找到,则删除该节点
				k.second.erase(k.second.begin() + i);

				// 当前节点为空则释放父节点
				if(k.second.empty())
					g_unlinks.erase(k.first);

				// 恢复
				InsertTailList(entryList, node);
				status = STATUS_SUCCESS;
				return status;
			}
		}
	}

	return status;
}


void utils::resume_all_unlink()
{
	auto bak = g_unlinks;
	for (const auto& t : bak)
	{
		for (const auto& n : t.second)
		{
			link(t.first.info.node, n.id,t.first.type);
		}
	}
	g_unlinks.clear();
}
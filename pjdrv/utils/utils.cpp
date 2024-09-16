#include "utils.h"

#include <map>
#include <vector>

#include "../module/module.h"
#include "../symbols/symbols.h"
#include "../memory/memory.h"
#include "../thread/thread.h"
#include "../process/process.h"
#include "../sync/lock.h"
#include "../log/log.hpp"

#include "../struct.h"

// 记录所有断链的节点
struct Custom_LinkValue
{
	// 记录的线程id 或 进程id
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

struct Handle_Info
{
	PHANDLE_TABLE_ENTRY p_entry;
	HANDLE_TABLE_ENTRY entry;
};

// 以进程id为Key，保存对应被断链的 进程链表 或 线程链表
std::map<Custom_LinkKey, std::vector<Custom_LinkValue>> g_unlink_mrg{};

// 以handle为key，保存对应被移除的handle数据
std::map<HANDLE, Handle_Info> g_handle_mrg{};

SpinLock g_link_lock{};
SpinLock g_handle_lock{};

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

NTSTATUS utils::resume_handle_sync(HANDLE handle)
{
	g_handle_lock.enter();
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	do
	{
		if(g_handle_mrg.count(handle) == 0)
		{
			break;
		}
		memory::copy_mem_safe(g_handle_mrg[handle].p_entry, &g_handle_mrg[handle].entry, sizeof(HANDLE_TABLE_ENTRY));

		g_handle_mrg.erase(handle);
		status = STATUS_SUCCESS;
	}while(false);

	g_handle_lock.leave();
	return status;
}

NTSTATUS utils::resume_all_handle_sync()
{
	NTSTATUS status = STATUS_SUCCESS;
	do
	{
		for(const auto& i:g_handle_mrg)
		{
			resume_handle_sync(i.first);
		}

		g_handle_mrg.clear();
		status = STATUS_SUCCESS;
	} while (false);
	return status;
}


NTSTATUS utils::remove_handle_from_table_sync(HANDLE handle)
{
	g_handle_lock.enter();
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	do
	{
		if (symbols::data_.global.ExpLookupHandleTableEntry == NULL || symbols::data_.global.ExDestroyHandle == NULL || symbols::data_.global.PspCidTable == NULL)
		{
			break;
		}

		PHANDLE_TABLE_ENTRY(NTAPI * ExpLookupHandleTableEntry)(
			__in PHANDLE_TABLE HandleTable,
			__in  HANDLE Handle
		) = reinterpret_cast<PHANDLE_TABLE_ENTRY(*)(PHANDLE_TABLE HandleTable, HANDLE Handle)>(symbols::data_.global.ExpLookupHandleTableEntry);
		if (!MmIsAddressValid(ExpLookupHandleTableEntry))
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

		auto PspCidTable = memory::read_safe<PHANDLE_TABLE>(reinterpret_cast<PVOID>(symbols::data_.global.PspCidTable));
		if(!MmIsAddressValid(PspCidTable))
		{
			break;
		}

		PHANDLE_TABLE_ENTRY ptr = ExpLookupHandleTableEntry(PspCidTable, handle);
		if (ptr == nullptr)
		{
			break;
		}

		// 如果存在则先恢复，理论上不会有这个情况
		if (g_handle_mrg.count(handle) > 0)
		{
			if (NT_SUCCESS(resume_handle_sync(handle)))
			{
				DBG_LOG("find old handle, already resume");
			}
		}

		Handle_Info hi{};
		hi.p_entry = ptr;
		memory::copy_mem_safe(&hi.entry,ptr,sizeof(HANDLE_TABLE_ENTRY));

		// 移除
		status = ExDestroyHandle(PspCidTable, handle, ptr) ? STATUS_SUCCESS : status;
		if(NT_SUCCESS(status))
		{
			// 加入管理器
			g_handle_mrg[handle] = hi;
			DBG_LOG("add handle,index: %d, ptr: %llx", g_handle_mrg.size(),hi.p_entry);
		}
		DBG_LOG("destroy handle: %x ok!", handle);

	} while (false);

	g_handle_lock.leave();
	return status;
}

NTSTATUS utils::unlink_sync(PLIST_ENTRY entryList, PLIST_ENTRY node, ELIST_TYPE type)
{
	g_link_lock.enter();
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

		Custom_LinkValue value{};
		value.node = node;

		// 获取被断链节点的pid，和节点对应的 pid/tid
		if (type == Process)
		{
			PVOID eprocess = reinterpret_cast<PUCHAR>(node) - symbols::data_.eprocess.ActiveProcessLinks;
			if (!NT_SUCCESS(process::get_UniqueProcessId(eprocess, &key.info.id)))
				break;

			value.id = key.info.id;
		}
		else if (type == Thread)
		{
			PVOID ethread = reinterpret_cast<PUCHAR>(node) - symbols::data_.ethread.ThreadListEntry;

			PEPROCESS eprocess = memory::read_safe<PEPROCESS>(static_cast<PUCHAR>(ethread) + symbols::data_.kthread.Process);
			if(!eprocess)
				break;

			if (!NT_SUCCESS(process::get_UniqueProcessId(eprocess, &key.info.id)))
				break;

			CLIENT_ID cid{};
			if (!NT_SUCCESS(thread::get_Cid(ethread, &cid)))
				break;

			value.id = cid.UniqueThread;
		}

		// inster to mrg
		if (g_unlink_mrg.count(key) == 0)
		{
			g_unlink_mrg[key] = {};
		}

		g_unlink_mrg[key].push_back(value);

		RemoveEntryList(node);
		InitializeListHead(node);
		status = STATUS_SUCCESS;
	}
	while (false);

	g_link_lock.leave();
	return status;
}

NTSTATUS utils::link_sync(PLIST_ENTRY entryList, HANDLE id, ELIST_TYPE type)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!MmIsAddressValid(entryList))
	{
		return status;
	}

	g_link_lock.enter();

	// 要恢复的节点
	PLIST_ENTRY node = nullptr;
	for(auto& k : g_unlink_mrg)
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
				CLIENT_ID cid{};
				cid.UniqueProcess = k.first.info.id;
				cid.UniqueThread = k.second[i].id;

				// 如果找到,则删除该节点
				k.second.erase(k.second.begin() + i);

				// 当前节点为空则释放父节点
				if(k.second.empty())
					g_unlink_mrg.erase(k.first);

				// 恢复前确保pid有效
				if (!process::is_alive(cid.UniqueProcess))
				{
					DBG_LOG("target pid: %d,death, pass link", cid.UniqueProcess);
					break;
				}

				if(type == Thread)
				{
					if (!thread::is_alive(cid.UniqueThread))
					{
						DBG_LOG("tid:%d belong to pid:%d was death, pass link", cid.UniqueThread, cid.UniqueProcess);
						break;
					}
				}
				InsertTailList(entryList, node);
				status = STATUS_SUCCESS;
				break;
			}
		}
	}

	g_link_lock.leave();
	return status;
}

void utils::resume_all_unlink_sync()
{
	auto bak = g_unlink_mrg;
	for (const auto& t : bak)
	{
		for (const auto& n : t.second)
		{
			link_sync(t.first.info.node, n.id,t.first.type);
		}
	}
	g_unlink_mrg.clear();
}



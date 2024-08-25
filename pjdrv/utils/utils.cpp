#include "utils.h"

#include <map>
#include <vector>

#include "../module/module.h"
#include "../symbols/symbols.hpp"
#include "../memory/memory.h"
#include "../thread/thread.h"
#include "../process/process.h"
#include "../log/log.hpp"

// ��¼���ж����Ľڵ�
struct Custom_LinkValue
{
	HANDLE id;

	// 1����node����Ϊkeyʱ�����ڶ�Ӧid������ͷ
	// 2����node����Ϊvalueʱ�����ڶ�Ӧid�������Ľڵ�
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

// �Խ���idΪKey�������Ӧ�������� �������� �� �߳�����
std::map<Custom_LinkKey, std::vector<Custom_LinkValue>> g_unlink_mrg{};

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

		Custom_LinkValue info{};
		info.node = node;

		// ��ȡ�������ڵ��pid���ͽڵ��Ӧ�� pid/tid
		if (type == Process)
		{
			PVOID eprocess = reinterpret_cast<PUCHAR>(node) - symbols::data_.eprocess.ActiveProcessLinks;
			if (!NT_SUCCESS(process::get_UniqueProcessId(eprocess, &key.info.id)))
				break;

			info.id = key.info.id;
		}
		else if (type == Thread)
		{
			PVOID ethread = reinterpret_cast<PUCHAR>(node) - symbols::data_.ethread.ThreadListEntry;

			PEPROCESS eprocess = memory::read_safe<PEPROCESS>(static_cast<PUCHAR>(ethread) + symbols::data_.ethread.Process);
			if(!eprocess)
				break;

			if (!NT_SUCCESS(process::get_UniqueProcessId(eprocess, &key.info.id)))
				break;

			CLIENT_ID cid{};
			if (!NT_SUCCESS(thread::get_Cid(ethread, &cid)))
				break;

			info.id = cid.UniqueThread;
		}

		// inster to mrg
		if (g_unlink_mrg.count(key) == 0)
		{
			g_unlink_mrg[key] = {};
		}

		g_unlink_mrg[key].push_back(info);
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

	// Ҫ�ָ��Ľڵ�
	PLIST_ENTRY node = nullptr;
	for(auto& k : g_unlink_mrg)
	{
		// ȷ������ͷ��Դ�����һ��
		if(k.first.info.node == entryList && k.first.type == type)
		{
			// ���Ҷ�Ӧhandle�Ľڵ�
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
				// ����ҵ�,��ɾ���ýڵ�
				k.second.erase(k.second.begin() + i);

				// ��ǰ�ڵ�Ϊ�����ͷŸ��ڵ�
				if(k.second.empty())
					g_unlink_mrg.erase(k.first);

				// �ָ�
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
	auto bak = g_unlink_mrg;
	for (const auto& t : bak)
	{
		for (const auto& n : t.second)
		{
			link(t.first.info.node, n.id,t.first.type);
		}
	}
	g_unlink_mrg.clear();
}
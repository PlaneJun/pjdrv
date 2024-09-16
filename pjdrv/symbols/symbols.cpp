#include "symbols.h"
#include "../log/log.hpp"
#include "../module/module.h"
#include "query-pdb/kquery_pdb.h"

bool symbols::init()
{
	try {

		kqpdb::set_default_server("http://www.zzzou.xyz:9025");

		kqpdb pdb("\\SystemRoot\\System32\\ntoskrnl.exe");

		auto eprocess = pdb.get_struct(
			"_EPROCESS", std::set<std::string>{
				"VadRoot",
				"DirectoryTableBase",
				"ThreadListHead",
				"ActiveProcessLinks",
				"UniqueProcessId",
			}
		);
		data_.eprocess.VadRoot = eprocess["VadRoot"].offset;
		data_.eprocess.DirectoryTableBase = eprocess["DirectoryTableBase"].offset;
		data_.eprocess.ThreadListHead = eprocess["ThreadListHead"].offset;
		data_.eprocess.ActiveProcessLinks = eprocess["ActiveProcessLinks"].offset;
		data_.eprocess.UniqueProcessId = eprocess["UniqueProcessId"].offset;


		auto ethread = pdb.get_struct(
			"_ETHREAD", std::set<std::string>{
			"Cid",
				"ThreadListEntry",
				"Win32StartAddress",
				"StartAddress"
			}
		);
		data_.ethread.Cid = ethread["Cid"].offset;
		data_.ethread.ThreadListEntry = ethread["ThreadListEntry"].offset;
		data_.ethread.Win32StartAddress = ethread["Win32StartAddress"].offset;
		data_.ethread.StartAddress = ethread["StartAddress"].offset;

		auto kthread = pdb.get_struct(
			"_KTHREAD", std::set<std::string>{
			"Process",
				"PreviousMode"
		}
		);
		data_.kthread.Process = kthread["Process"].offset;
		data_.kthread.PreviousMode = kthread["PreviousMode"].offset;

		auto global = pdb.get_symbol(std::set<std::string>{
			"KeServiceDescriptorTable",
				"PspNotifyEnableMask",
				"ExDestroyHandle",
				"ExpLookupHandleTableEntry",
				"PspCidTable",
		});

		uintptr_t krnl_base = reinterpret_cast<uintptr_t>(module::get_ntoskrnl_base(nullptr));
		if(krnl_base == NULL)
		{
			return false;
		}

		data_.global.KeServiceDescriptorTable = krnl_base + global["KeServiceDescriptorTable"];
		data_.global.PspNotifyEnableMask = krnl_base + global["PspNotifyEnableMask"];
		data_.global.ExDestroyHandle = krnl_base + global["ExDestroyHandle"];
		data_.global.ExpLookupHandleTableEntry = krnl_base + global["ExpLookupHandleTableEntry"];
		data_.global.PspCidTable = krnl_base + global["PspCidTable"];

		return true;
	}
	catch (std::exception& e) {
		DBG_LOG("exception: %s\n", e.what());
	}
	catch (...) {
		DBG_LOG("exception\n");
	}

	return false;
}
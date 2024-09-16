#pragma once

namespace symbols
{
	typedef struct _TSYMBOLS
	{
		struct
		{
			unsigned long long VadRoot;
			unsigned long long DirectoryTableBase;
			unsigned long long ThreadListHead;
			unsigned long long ActiveProcessLinks;
			unsigned long long UniqueProcessId;
		}eprocess;

		struct
		{
			unsigned long long Cid;
			unsigned long long ThreadListEntry;
			unsigned long long StartAddress;
			unsigned long long Win32StartAddress;
		}ethread;

		struct
		{
			unsigned long long Process;
			unsigned long long PreviousMode;
		}kthread;

		struct
		{
			unsigned long long KeServiceDescriptorTable;
			unsigned long long PspNotifyEnableMask;
			unsigned long long PspCidTable;
			unsigned long long ExpLookupHandleTableEntry;
			unsigned long long ExDestroyHandle;
		}global;

	}Symbols, * PSymbols;

	inline Symbols data_{};

	bool init();
}
#pragma once

// IO_ahcache表示使用劫持的.rdata ptr进行通讯,否则自创建设备通讯
// #define IO_ahcache

#ifndef IO_ahcache

#define IOCTL_NEITHER_NORMAL(i)	\
	CTL_CODE					\
	(							\
	FILE_DEVICE_UNKNOWN,		\
	0x800 + i + 0x100,			\
	METHOD_NEITHER,				\
	FILE_ANY_ACCESS				\
	)	

#define IOCTL_NEITHER IOCTL_NEITHER_NORMAL(1)

#endif

namespace communicate
{
	enum ECMD : unsigned short
	{
		CMD_CONTROL = 1000,
		CMD_PassPG,							// TODO
		CMD_R3_GetProcessModules,
		CMD_R3_GetExportFunction,
		CMD_R3_ReadMemory,
		CMD_R3_WriteMemory,
		CMD_R3_AllocMemory,
		CMD_R3_FreeMemory,
		CMD_R3_QueryVirtualMemory,
		CMD_R3_ProtectVirtualMemory,
		CMD_R3_CreateThread,
		CMD_R3_CloseHandle,
		CMD_R3_WaitSingleObject,		
		CMD_R3_KbdEvent,
		CMD_R3_MouseEvent,
		cmd_R3_HideThread,				// TODO
		CMD_R3_HideProcess,				// TODO
		CMD_R3_ResumeThread,			// TODO
		CMD_R3_ResumeProcess,			// TODO
		CMD_R3_ProtectProcess,			// TODO
		CMD_R3_ProtectWindowm,			// TODO
		CMD_Symbol
	};

	enum ERWTYPE : unsigned char
	{
		MmCopy = 0,
		Mdl,
		Phycical
	};

	typedef struct _TPARAMS
	{
		unsigned short	cmd;
		unsigned int pid;
		void* buffer;
		int status;          
	}Params, * PParams;

	typedef struct _TMODULE
	{
		void* module_name;  // wchar_t*
		void* module_base;
		unsigned int module_size;
		void* output;
	}Module,*PModule;

	typedef struct _TMEMORY
	{
		void* addr;
		void* buffer;
		unsigned int length;
		void* output;
		unsigned long proctect;
		unsigned long oldprotect;
		unsigned int alloctype;
		ERWTYPE rw_type;
		unsigned long long ret_bytes;
	}Memory,*PMemory;

	typedef struct _TTHREAD
	{
		void* entry;
		void* params;
		void* handler;
		unsigned long threadid;
		bool disable_notify;
		bool hide;
		bool alert;
		unsigned int wait_time;
	}Thread,*PThread;

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
			unsigned long long KeServiceDescriptorTable;
			unsigned long long PspNotifyEnableMask;
			unsigned long long PspCidTable;
			unsigned long long ExMapHandleToPointer;
			unsigned long long ExDestroyHandle;
		}global;

	}Symbols,*PSymbols;

	typedef struct _TDEVICE
	{
		unsigned int mx;
		unsigned int my;
		unsigned int keycode;
		unsigned short flags;
	}Device,*PDevice;
	
}

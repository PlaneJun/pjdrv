#pragma once
#include <ntifs.h>
#include <stdint.h>

class Control
{
public:

	enum ERWTYPE : int
	{
		MmCopy = 0,
		MDL,
		PHYSICAL
	};

	typedef struct _DATA_PARAMENTS_ {

		ULONG64 cmd;
		ULONG64 pid;

		union
		{
			struct
			{
				PVOID64 module_name;
				PVOID64 module_base;
				bool wow64;
				DWORD32 module_size;
				PVOID64 output;
			}m;

			struct
			{
				PVOID64 addr;
				PVOID64 buffer;
				ULONG64 length;
				PVOID64 output;
				ULONG64 proctect;
				ULONG64 alloctype;
				ERWTYPE rw_type;
			}mem;

			struct
			{
				PVOID entry;
				PVOID params;
				HANDLE handler;
			}thread;

			struct {
				uint64_t vad_root;
				uint64_t KeServiceDescriptorTable;
				uint64_t data_base;
			}symbs;

			struct
			{
				uint32_t mx;
				uint32_t my;
				uint32_t keycode;
				uint16_t flags;
			}device;
		}params;

	}DataParams, * PDataParams;


	enum ECMD
	{
		CMD_CONTROL = 1000,
		CMD_GetProcessModules,
		CMD_GetExportFunction,
		CMD_ReadMemory,
		CMD_WriteMemory,
		CMD_AllocMemory,
		CMD_FreeMemory,
		CMD_QueryVirtualMemory,
		CMD_ProtectVirtualMemory,
		CMD_CreateThread,
		CMD_Close,
		CMD_KbdEvent,
		CMD_MouseEvent,
		CMD_Symbol
	};


public:
	void install();

private:
	PVOID AslLogPfnVPrintf_;

	PVOID find_control_ptr();
	
};
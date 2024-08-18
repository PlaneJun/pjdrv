#pragma once
#include <map>
#include <windows.h>
#include <stdint.h>
#include "dll_struct.h"

class drv
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
				ULONG proctect;
				ULONG oldprotect;
				ULONG64 alloctype;
				ERWTYPE rw_type;
				SIZE_T retByte;
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
	enum ERROR_CODE
	{
		CODE_OK,
		CODE_DEVICE_FAILED,
		CODE_CTRL_FAILED,
		CODE_DOWNLOAD_PDB_FAILED,
		CODE_LOAD_PDB_FAILED,
		CODE_GET_SYMBOLS_FAILED,
		CODE_SET_SYMBOLS_FAILED
	};

public:

	ERROR_CODE init();

	PVOID64 get_process_module(DWORD ProcessId, PCWCH ModuleName,bool isWow64);

	bool get_export_address(DWORD ProcessId, PCWCH ModuleName, bool isWow64, PCCH FunctionName, PVOID64 Output);

	bool read_mem(DWORD ProcessId, PVOID64 Address, ULONG ReadSize, PVOID64 Output, ERWTYPE type);

	bool write_mem(DWORD ProcessId, PVOID64 Address, ULONG WriteSize, PVOID64 WriteBuffer, ERWTYPE type);

	bool alloc_mem(DWORD ProcessId, PVOID64 Address, ULONG Size, PVOID64 Output, ULONG AllocationType, ULONG Protect);

	bool protect_mem(DWORD ProcessId, PVOID64 Address, ULONG Size, ULONG newProtect,PULONG oldProtect = NULL);

	uint64_t allc_mem_nearby(DWORD ProcessId, ULONG64 Address, ULONG Size, ULONG AllocationType, ULONG Protect);

	bool free_mem(DWORD ProcessId, PVOID64 Address, ULONG Size);

	bool query_mem(DWORD ProcessId, PVOID64 Address, PVOID64 Output);

	HANDLE create_thread(DWORD ProcessId, PVOID entry, PVOID params);

	bool mouse_event_ex(DWORD x, DWORD y, USHORT flag);

	bool keybd_event_ex(DWORD KeyCode, USHORT flag);

	bool inject(DWORD ProcessId, PVOID64 dll_data, DWORD dll_size);

	bool close_handle(DWORD ProcessId,HANDLE handler);

	bool dump_module(DWORD ProcessId, PCCH module_name, PCCH save_path);

	const char* get_error_msg(ERROR_CODE code)
	{
		if (msg_.count(code) > 0)
			return  msg_[code];
		return "unkown";
	}

	template<typename T>
	T read(uint32_t pid,PVOID64 addr, ERWTYPE type = ERWTYPE::MmCopy)
	{
		T val{};

		read_mem(pid,addr,sizeof(T),&val, type);
		return val;
	}

	template<typename T>
	void write(uint32_t pid, PVOID64 addr,T val,ERWTYPE type = ERWTYPE::MmCopy)
	{
		write_mem(pid, addr,sizeof(T),&val, type);
	}

private:

	HANDLE hFile_;

	std::map<ERROR_CODE, const char*> msg_ = {
		{CODE_OK,"ok"},
		{CODE_DEVICE_FAILED,"open device failed"},
		{CODE_CTRL_FAILED,"ctrl failed"},
		{CODE_DOWNLOAD_PDB_FAILED,"download pdb failed"},
		{CODE_LOAD_PDB_FAILED,"load pdb failed"},
		{CODE_GET_SYMBOLS_FAILED,"get symbols failed"},
	};

	void send_control(const PDataParams dp);

#pragma region dll_inject

	bool get_image_dos_header(PVOID data,PIMAGE_DOS_HEADER* DosHead);

	bool get_image_nt_header(PVOID data, PIMAGE_DOS_HEADER DosHead, PIMAGE_NT_HEADERS* NtHread);

	bool get_section_header(PIMAGE_NT_HEADERS NtHread, PIMAGE_SECTION_HEADER* SectionHeader);

	SIZE_T get_pe_size(PIMAGE_NT_HEADERS NtHread, PIMAGE_SECTION_HEADER SectionHeader, DWORD32 nAlign);

	bool copy_sections(DWORD ProcessId, PIMAGE_NT_HEADERS NtHread, PIMAGE_SECTION_HEADER SectionHeader, PVOID data,PVOID MemoryAddress);

	VOID fix_loc_datas(DWORD ProcessId, PIMAGE_NT_HEADERS NtHread, PVOID MemoryAddress);

	bool fill_params(DWORD ProcessId,Shellparam* param, PVOID MemoryAddress, DWORD e_lfanew);

	bool run_remote_hook(DWORD ProcessId, PVOID Address, Shellparam* param);

	bool run_hook(DWORD ProcessId, PVOID Address, Shellparam* param, PVOID64* HookAddressMemory);

	HookMapdLLparam* hook_params_alloc_memory(DWORD ProcessId, PVOID Address, Shellparam* param);

	bool hook_fix_proxy(DWORD ProcessId, PVOID Poxy, HookMapdLLparam* param, SIZE_T PoxySize);

	bool hook_TranslateMessage(DWORD ProcessId, PVOID Poxy);

#pragma endregion

};
#pragma once
#include <map>
#include <windows.h>
#include <stdint.h>
#include "dll_struct.h"

#include "../../share/communicate.h"

#define DBG_LOG(Format, ...) printf("[" __FUNCTION__ ":%u]: " Format "\n", __LINE__, ## __VA_ARGS__)

class drv
{
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
	drv() {
		drv(NULL, NULL);
	}
	drv(HANDLE h_file, int last_error)
		: hFile_(h_file),
		  lastError_(last_error)
	{
	}

	ERROR_CODE init();

	PVOID64 get_process_module(DWORD ProcessId, PCWCH ModuleName,bool isWow64);

	bool get_export_address(DWORD ProcessId, PCWCH ModuleName, bool isWow64, PCCH FunctionName, PVOID64 Output);

	bool read_mem(DWORD ProcessId, PVOID64 Address, ULONG ReadSize, PVOID64 Output, PSIZE_T retBytes, communicate::ERWTYPE type);

	bool write_mem(DWORD ProcessId, PVOID64 Address, ULONG WriteSize, PVOID64 WriteBuffer,PSIZE_T retBytes, communicate::ERWTYPE type);

	bool alloc_mem(DWORD ProcessId, PVOID64 Address, ULONG Size, PVOID64 Output, ULONG AllocationType, ULONG Protect);

	bool protect_mem(DWORD ProcessId, PVOID64 Address, ULONG Size, ULONG newProtect,PULONG oldProtect = nullptr);

	uint64_t allc_mem_nearby(DWORD ProcessId, ULONG64 Address, ULONG Size, ULONG AllocationType, ULONG Protect);

	bool free_mem(DWORD ProcessId, PVOID64 Address, ULONG Size);

	bool query_mem(DWORD ProcessId, PVOID64 Address, PVOID64 Output);

	HANDLE create_thread(DWORD ProcessId, PVOID entry, PVOID params, bool disable_notify,bool hide, PULONG tid);

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

	int get_last_error() const
	{
		return lastError_;
	}

	template<typename T>
	T read(uint32_t pid,PVOID64 addr, communicate::ERWTYPE type = communicate::ERWTYPE::MmCopy)
	{
		T val{};

		read_mem(pid,addr,sizeof(T),&val,nullptr, type);
		return val;
	}

	template<typename T>
	void write(uint32_t pid, PVOID64 addr,T val, communicate::ERWTYPE type = communicate::ERWTYPE::MmCopy)
	{
		write_mem(pid, addr,sizeof(T),&val, nullptr,type);
	}

private:

	HANDLE hFile_;

	int lastError_;

	std::map<ERROR_CODE, const char*> msg_ = {
		{CODE_OK,"ok"},
		{CODE_DEVICE_FAILED,"open device failed"},
		{CODE_CTRL_FAILED,"ctrl failed"},
		{CODE_DOWNLOAD_PDB_FAILED,"download pdb failed"},
		{CODE_LOAD_PDB_FAILED,"load pdb failed"},
		{CODE_GET_SYMBOLS_FAILED,"get symbols failed"},
	};

	bool send_control(communicate::ECMD cmd,uint32_t pid = NULL,void* buffer = nullptr);

#pragma region dll_inject

	bool get_image_dos_header(PVOID data,PIMAGE_DOS_HEADER* DosHead);

	bool get_image_nt_header(PVOID data, PIMAGE_DOS_HEADER DosHead, PIMAGE_NT_HEADERS* NtHread);

	bool get_section_header(PIMAGE_NT_HEADERS NtHread, PIMAGE_SECTION_HEADER* SectionHeader);

	SIZE_T get_pe_size(PIMAGE_NT_HEADERS NtHread, PIMAGE_SECTION_HEADER SectionHeader, DWORD32 nAlign);

	bool copy_sections(DWORD ProcessId, PIMAGE_NT_HEADERS NtHread, PIMAGE_SECTION_HEADER SectionHeader, PVOID data,PVOID MemoryAddress);

	VOID fix_loc_datas(DWORD ProcessId, PIMAGE_NT_HEADERS NtHread, PVOID MemoryAddress);

	bool fill_params(DWORD ProcessId,Shellparam* param, PVOID MemoryAddress, DWORD e_lfanew);

	HookMapdLLparam* hook_params_alloc_memory(DWORD ProcessId, PVOID Address, Shellparam* param,PVOID hijackAddr);

	bool hook_fix_proxy(DWORD ProcessId, PVOID Poxy, HookMapdLLparam* param, SIZE_T PoxySize);

	bool run_hook(DWORD ProcessId, PVOID Address, Shellparam* param, PVOID64* HookAddressMemory);

#pragma endregion

};
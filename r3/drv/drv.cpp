#include "drv.h"
#include <string>
#include "../pdb/Pdb.h"
#include "dll_shellcode.h"

void drv::send_control(const PDataParams dp)
{
	//写入TEB
	__writegsqword(0x38, reinterpret_cast<DWORD64>(dp));
	DWORD real_bytes = NULL;
	DWORD64 data = NULL;
	DeviceIoControl(hFile_, 0x100, &data, sizeof(data), &data, sizeof(data), &real_bytes, NULL);
}

drv::ERROR_CODE drv::init()
{
	drv::ERROR_CODE status_code = ERROR_CODE::CODE_OK;
	do
	{
		// 是否可以打开设备
		if (!hFile_)
		{
			hFile_ = CreateFile(L"\\\\.\\ahcache",
				GENERIC_READ | GENERIC_WRITE,
				NULL, NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_NORMAL,
				NULL);
			if (hFile_ == INVALID_HANDLE_VALUE)
			{
				status_code = ERROR_CODE::CODE_DEVICE_FAILED;
				break;
			}
		}

		// 获取状态码
		int ctrl_code = NULL;
		DataParams dp = { 0 };
		dp.cmd = CMD_CONTROL;
		send_control(&dp);
		if ((ULONG)dp.cmd != 1 )
		{
			status_code = ERROR_CODE::CODE_CTRL_FAILED;
			break;
		}

		//初始化PDB
		std::string kernel = std::string(std::getenv("systemroot")) + "\\System32\\ntoskrnl.exe";
		std::string pdbPath = EzPdbDownload(kernel);
		if (pdbPath.empty())
		{
			status_code = ERROR_CODE::CODE_DOWNLOAD_PDB_FAILED;
			break;
		}

		// 初始化符号
		EZPDB pdb;
		if (!EzPdbLoad(pdbPath, &pdb))
		{
			status_code = ERROR_CODE::CODE_LOAD_PDB_FAILED;
			break;
		}

		RtlZeroMemory(&dp, sizeof(DataParams));
		dp.params.symbs.vad_root = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"VadRoot");
		dp.params.symbs.data_base = EzPdbGetStructPropertyOffset(&pdb, "_KPROCESS", L"DirectoryTableBase");
		dp.params.symbs.KeServiceDescriptorTable = EzPdbGetRva(&pdb, "KeServiceDescriptorTable");
		printf("vad_root = %x\n", dp.params.symbs.vad_root);
		printf("data_base = %x\n", dp.params.symbs.data_base);
		printf("KeServiceDescriptorTable = %p\n",dp.params.symbs.KeServiceDescriptorTable);
		if (dp.params.symbs.vad_root <= 0)
		{
			status_code = ERROR_CODE::CODE_GET_SYMBOLS_FAILED;
			break;
		}
		EzPdbUnload(&pdb);
		dp.cmd = CMD_Symbol;
		send_control(&dp);

	} while (FALSE);

	return status_code;
}



PVOID64 drv::get_process_module(DWORD ProcessId,PCWCH ModuleName, bool isWow64)
{
	DataParams dp = { 0 };
	dp.cmd = CMD_GetProcessModules;
	dp.pid = ProcessId;
	dp.params.m.module_name = (PVOID64)ModuleName;
	dp.params.m.wow64 = isWow64;

	send_control(&dp);
	return dp.params.m.output;
}
bool drv::get_export_address(DWORD ProcessId, PCWCH ModuleName , bool isWow64,PCCH FunctionName, PVOID64 Output)
{
	DataParams dp = { 0 };

	PVOID64 ModuleBase = get_process_module(ProcessId,  ModuleName, isWow64);
	if (ModuleBase)
	{
		DataParams dp = { 0 };
		dp.cmd = CMD_GetExportFunction;
		dp.pid = ProcessId;
		dp.params.m.module_base = ModuleBase;
		dp.params.m.module_name = (PVOID64)FunctionName;
		dp.params.m.output = Output;
		send_control(&dp);
		return TRUE;
	}
	return FALSE;
}
bool drv::read_mem(DWORD ProcessId, PVOID64 Address, ULONG ReadSize, PVOID64 Output, ERWTYPE type)
{
	DataParams dp = { 0 };
	dp.cmd = CMD_ReadMemory;
	dp.pid = ProcessId;
	dp.params.mem.addr = Address;
	dp.params.mem.length = ReadSize;
	dp.params.mem.output = Output;
	dp.params.mem.rw_type = type;

	send_control(&dp);
	return TRUE;
}
bool drv::write_mem(DWORD ProcessId, PVOID64 Address, ULONG WriteSize, PVOID64 WriteBuffer, ERWTYPE type)
{
	DataParams dp = { 0 };
	dp.cmd = CMD_WriteMemory;
	dp.pid = ProcessId;
	dp.params.mem.addr = Address;
	dp.params.mem.length = WriteSize;
	dp.params.mem.buffer = WriteBuffer;
	dp.params.mem.rw_type = type;

	send_control(&dp);
	return TRUE;
}
bool drv::alloc_mem(DWORD ProcessId, PVOID64 Address, ULONG Size, PVOID64 Output, ULONG AllocationType, ULONG Protect)
{
	DataParams dp = { 0 };
	dp.cmd = CMD_AllocMemory;
	dp.pid = ProcessId;
	dp.params.mem.addr = Address;
	dp.params.mem.length = Size;
	dp.params.mem.output = Output;
	dp.params.mem.alloctype = AllocationType;
	dp.params.mem.proctect = Protect;

	send_control(&dp);
	return TRUE;
}
uint64_t drv::allc_mem_nearby(DWORD ProcessId, ULONG64 Address, ULONG Size, ULONG AllocationType, ULONG Protect)
{
	ULONG64 A = (ULONG64)Address / 65536;
	ULONG64 AllocPtr = A * 65536;
	BOOL Direc = FALSE;
	ULONG64 Increase = 0;
	ULONG64 AllocBase = 0;

	do
	{
		alloc_mem(ProcessId, (PVOID64)AllocPtr, Size, &AllocBase, AllocationType, Protect);
		if (AllocBase == 0)
		{
			if (Direc == FALSE)
			{
				if (Address + 2147483642 >= AllocPtr)
				{
					Increase = Increase + 65536;
				}
				else
				{
					Increase = 0;
					Direc = TRUE;
				}
			}
			else
			{
				if (Address - 2147483642 <= AllocPtr)
				{
					Increase = Increase - 65536;
				}
				else
				{
					return 0;
				}
			}

			AllocPtr = AllocPtr + Increase;
		}


	} while (AllocBase == 0);

	return AllocBase;
}
bool drv::protect_mem(DWORD ProcessId, PVOID64 Address, ULONG Size, ULONG64 newProtect)
{
	DataParams dp = { 0 };
	dp.cmd = CMD_ProtectVirtualMemory;
	dp.pid = ProcessId;
	dp.params.mem.addr = Address;
	dp.params.mem.length = Size;
	dp.params.mem.proctect = newProtect;

	send_control(&dp);
	return TRUE;
}
bool drv::free_mem(DWORD ProcessId, PVOID64 Address, ULONG Size)
{
	DataParams dp = { 0 };
	dp.cmd = CMD_FreeMemory;
	dp.pid = ProcessId;
	dp.params.mem.addr = Address;
	dp.params.mem.length = Size;

	send_control(&dp);
	return TRUE;
}
bool drv::query_mem(DWORD ProcessId, PVOID64 Address, PVOID64 Output)
{
	DataParams dp = { 0 };
	dp.cmd = CMD_QueryVirtualMemory;
	dp.pid = ProcessId;
	dp.params.mem.addr = Address;
	dp.params.mem.output = Output;

	send_control(&dp);
	return TRUE;
}

HANDLE drv::create_thread(DWORD ProcessId, PVOID entry, PVOID params)
{
	HANDLE retHandle = NULL;
	DataParams dp = { 0 };
	dp.cmd = CMD_CreateThread;
	dp.pid = ProcessId;
	dp.params.thread.handler = &retHandle;
	dp.params.thread.entry= entry;
	dp.params.thread.params = params;

	send_control(&dp);
	return dp.params.thread.handler;
}

bool drv::mouse_event_ex(DWORD x, DWORD y, USHORT flag)
{
	DataParams dp = { 0 };
	dp.cmd = CMD_MouseEvent;
	dp.params.device.mx = x;
	dp.params.device.my = y;
	dp.params.device.flags = flag;

	send_control(&dp);
	return TRUE;
}
bool drv::keybd_event_ex(DWORD KeyCode, USHORT flag)
{
	DataParams dp = { 0 };
	dp.cmd = CMD_KbdEvent;
	dp.params.device.keycode = KeyCode;
	dp.params.device.flags = flag;

	send_control(&dp);
	return TRUE;
}
bool drv::inject(DWORD ProcessId, PVOID64 dll_data, DWORD dll_size)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	if (!get_image_dos_header(dll_data ,&pDosHeader))
	{
		return NULL;
	}
	if (!get_image_nt_header(dll_data,pDosHeader, &pNTHeader))
	{
		return NULL;
	}
	if (!get_section_header(pNTHeader, &pSectionHeader))
	{
		return NULL;
	}
	auto nAlign = pNTHeader->OptionalHeader.SectionAlignment;
	auto uSize = get_pe_size(pNTHeader, pSectionHeader, nAlign);
	PVOID pMemoryAddress = NULL;
	alloc_mem(ProcessId, NULL, uSize, &pMemoryAddress,MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,PAGE_EXECUTE_READWRITE);

	if (!pMemoryAddress)
	{
		return false;
	}

	if (!copy_sections(ProcessId,pNTHeader, pSectionHeader, dll_data, pMemoryAddress))
	{
		return false;
	}

	//fix reloc
	fix_loc_datas(ProcessId,pNTHeader, pMemoryAddress);
	Shellparam* param = NULL;
	alloc_mem(ProcessId, NULL, sizeof(Shellparam), &param, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
	if (!param)
	{
		return false;
	}
	// fill shellcode params
	fill_params(ProcessId,param, pMemoryAddress, pDosHeader->e_lfanew);
	PVOID ShllCodeMeory = NULL;
	alloc_mem(ProcessId, NULL, sizeof(g_ShellCodeExDll), &ShllCodeMeory, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
	if (ShllCodeMeory == NULL)
	{
		return false;
	}
	write_mem(ProcessId,ShllCodeMeory, sizeof(g_ShellCodeExDll),g_ShellCodeExDll,ERWTYPE::MDL);
	PVOID64 pHookAddressMemory = NULL;
	run_hook(ProcessId,ShllCodeMeory, param,&pHookAddressMemory);
	Shellparam wait_inject{};
	if (pHookAddressMemory != NULL)
	{
		do
		{
			wait_inject = read<Shellparam>(ProcessId,param);
			Sleep(1000);
		} while (wait_inject.IsOk != 1);
		Sleep(50);

	FreeMem:
		if (param)
		{
			free_mem(ProcessId, param, sizeof(Shellparam));
			param = NULL;
		}

		if (ShllCodeMeory)
		{
			free_mem(ProcessId, ShllCodeMeory, sizeof(g_ShellCodeExDll));
			ShllCodeMeory = NULL;
		}

		if (pHookAddressMemory)
		{
			free_mem(ProcessId, pHookAddressMemory, sizeof(g_HookCode));
			pHookAddressMemory = NULL;
		}

	}
	else
	{
		goto FreeMem;
	}

	return pMemoryAddress;
}

bool drv::dump_module(DWORD ProcessId, PCCH module_name, PCCH save_path)
{
	
	return TRUE;
}

bool drv::get_image_dos_header(PVOID data, PIMAGE_DOS_HEADER* DosHead)
{
	*DosHead = (PIMAGE_DOS_HEADER)data;
	if (DosHead[0]->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;
	return TRUE;
}

bool drv::get_image_nt_header(PVOID data, PIMAGE_DOS_HEADER DosHead, PIMAGE_NT_HEADERS* NtHread)
{
	*NtHread = (PIMAGE_NT_HEADERS)((DWORD64)data + DosHead->e_lfanew);
	if (NtHread[0]->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	if ((NtHread[0]->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
		return FALSE;
	if ((NtHread[0]->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)
		return FALSE;
	if (NtHread[0]->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
		return FALSE;
	return TRUE;
}

bool drv::get_section_header(PIMAGE_NT_HEADERS NtHread, PIMAGE_SECTION_HEADER* SectionHeader)
{
	*SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD64)NtHread + sizeof(IMAGE_NT_HEADERS64));
	return true;
}

SIZE_T drv::get_pe_size(PIMAGE_NT_HEADERS NtHread, PIMAGE_SECTION_HEADER SectionHeader, DWORD32 nAlign)
{
	SIZE_T ImageSize = (NtHread->OptionalHeader.SizeOfHeaders + nAlign - 1) / nAlign * nAlign;//段对齐字节数
	for (int i = 0; i < NtHread->FileHeader.NumberOfSections; ++i)
	{
		int CodeSize = SectionHeader[i].Misc.VirtualSize;
		int LoadSize = SectionHeader[i].SizeOfRawData;
		int MaxSize = (LoadSize > CodeSize) ? (LoadSize) : (CodeSize);
		int SectionSize = (SectionHeader[i].VirtualAddress + MaxSize + nAlign - 1) / nAlign * nAlign;
		if (ImageSize < SectionSize)
			ImageSize = SectionSize;
	}
	return ImageSize;
}

bool drv::copy_sections(DWORD ProcessId, PIMAGE_NT_HEADERS NtHread, PIMAGE_SECTION_HEADER SectionHeader, PVOID data,PVOID MemoryAddress)
{
	auto HeaderSize = NtHread->OptionalHeader.SizeOfHeaders;
	auto SectionSize = NtHread->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	auto MoveSize = HeaderSize + SectionSize;
	//复制头和段信息
	write_mem(ProcessId,MemoryAddress, MoveSize,data, ERWTYPE::MDL);

	//复制每个节
	for (int i = 0; i < NtHread->FileHeader.NumberOfSections; ++i)
	{
		if (SectionHeader[i].VirtualAddress == 0 || SectionHeader[i].SizeOfRawData == 0)
			continue;
		void* pSectionAddress = (void*)((DWORD64)MemoryAddress + SectionHeader[i].VirtualAddress);
		write_mem(ProcessId, pSectionAddress, SectionHeader[i].SizeOfRawData, (PCHAR)data + SectionHeader[i].PointerToRawData, ERWTYPE::MDL);
	}
	return TRUE;
}

VOID drv::fix_loc_datas(DWORD ProcessId, PIMAGE_NT_HEADERS NtHread, PVOID MemoryAddress)
{
	if (NtHread->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0
		&& NtHread->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
	{
		DWORD64 Delta = (DWORD64)MemoryAddress - NtHread->OptionalHeader.ImageBase;
		DWORD64* pAddress;

		//注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址
		PCHAR tmpData = new CHAR[NtHread->OptionalHeader.SizeOfImage];
		read_mem(ProcessId,MemoryAddress, NtHread->OptionalHeader.SizeOfImage,tmpData, ERWTYPE::MDL);

		PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((DWORD64)tmpData
			+ NtHread->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
		{
			PSHORT pLocData = (PSHORT)((DWORD64)pLoc + sizeof(IMAGE_BASE_RELOCATION));
			//计算本节需要修正的重定位项（地址）的数目
			int NumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(SHORT);
			for (int i = 0; i < NumberOfReloc; i++)
			{
				if ((DWORD64)(pLocData[i] & 0xF000) == 0x00003000 || (DWORD64)(pLocData[i] & 0xF000) == 0x0000A000) //这是一个需要修正的地址
				{
					pAddress = (DWORD64*)((DWORD64)MemoryAddress + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
					DWORD64 origin = read<DWORD64>(ProcessId,pAddress);
					write<DWORD64>(ProcessId,pAddress, origin + Delta);
				}
			}
			pLoc = (PIMAGE_BASE_RELOCATION)((DWORD64)pLoc + pLoc->SizeOfBlock);
		}

		delete[] tmpData;
	}
}

bool drv::fill_params(DWORD ProcessId,Shellparam* param, PVOID MemoryAddress, DWORD e_lfanew)
{
	HMODULE DllBase = GetModuleHandleA("ntdll.dll");
	if (DllBase == NULL)
	{
		return FALSE;
	}
	Shellparam temp{};

	temp.LdrGetProcedureAddress = (LdrGetProcedureAddressT)GetProcAddress(DllBase, "LdrGetProcedureAddress");
	printf("[+]LdrGetProcedureAddress %p\n", temp.LdrGetProcedureAddress);

	temp.dwNtAllocateVirtualMemory = (NtAllocateVirtualMemoryT)GetProcAddress(DllBase, "NtAllocateVirtualMemory");
	printf("[+]dwNtAllocateVirtualMemory %p\n", temp.dwNtAllocateVirtualMemory);

	temp.pLdrLoadDll = (LdrLoadDllT)GetProcAddress(DllBase, "LdrLoadDll");
	printf("[+]pLdrLoadDll %p\n", temp.pLdrLoadDll);

	temp.RtlInitAnsiString = (RtlInitAnsiStringT)GetProcAddress(DllBase, "RtlInitAnsiString");
	printf("[+]RtlInitAnsiString %p\n", temp.RtlInitAnsiString);

	temp.RtlAnsiStringToUnicodeString = (RtlAnsiStringToUnicodeStringT)GetProcAddress(DllBase, "RtlAnsiStringToUnicodeString");
	printf("[+]RtlAnsiStringToUnicodeString %p\n", temp.RtlAnsiStringToUnicodeString);

	temp.RtlFreeUnicodeString = (RtlFreeUnicodeStringT)GetProcAddress(DllBase, "RtlFreeUnicodeString");
	printf("[+]RtlFreeUnicodeString %p\n", temp.RtlFreeUnicodeString);

	temp.pNTHeader = (PIMAGE_NT_HEADERS)((DWORD64)MemoryAddress + e_lfanew);
	printf("[+]pNTHeader %p\n", temp.pNTHeader);

	temp.pMemoryAddress = MemoryAddress;
	printf("[+]pMemoryAddress %p\n", temp.pMemoryAddress);

	write<Shellparam>(ProcessId,param, temp);

	return TRUE;
}

bool drv::run_remote_hook(DWORD ProcessId, PVOID Address, Shellparam* param)
{
	return close_handle(ProcessId, create_thread(ProcessId, Address, param));
}

bool drv::run_hook(DWORD ProcessId, PVOID Address, Shellparam* param,PVOID64* HookAddressMemory)
{
	HookMapdLLparam* Hookparam = NULL;
	//alloc hook memory
	PVOID Porx = NULL;
	alloc_mem(ProcessId, NULL, sizeof(g_HookCode), &Porx, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
	if (Porx != NULL)
	{
		//fill hook param
		Hookparam = hook_params_alloc_memory(ProcessId,Address, param);
		if (Hookparam != NULL)
		{
			write_mem(ProcessId, Porx, sizeof(g_HookCode), g_HookCode, ERWTYPE::MDL);
			if (hook_fix_proxy(ProcessId,Porx, Hookparam, sizeof(g_HookCode)))
			{
				*HookAddressMemory = Porx;
				return hook_GetForegroundWindow(ProcessId,Porx);
			}
			else
			{
				free_mem(ProcessId, Hookparam, sizeof(HookMapdLLparam));
				*HookAddressMemory = NULL;
			}
		}
		else
		{
			free_mem(ProcessId,Porx, sizeof(g_HookCode));
		}
	}

	return false;
}

HookMapdLLparam* drv::hook_params_alloc_memory(DWORD ProcessId, PVOID Address, Shellparam* param)
{
	HookMapdLLparam* Parm = NULL;
	PVOID TranslateMessageAddress = NULL;
	HMODULE User32DllBabse = GetModuleHandleA("User32.dll");
	if (!User32DllBabse)
	{
		User32DllBabse = LoadLibraryA("User32.dll");
	}
	printf("[=]User32DllBabse = %p\r\n", User32DllBabse);

	if (User32DllBabse != NULL)
	{
		TranslateMessageAddress = GetProcAddress(User32DllBabse, "TranslateMessage");
		printf("[+]TranslateMessageAddress = %p\r\n", TranslateMessageAddress);
	}

	if (TranslateMessageAddress != NULL)
	{
		Parm = NULL;
		alloc_mem(ProcessId, NULL, sizeof(HookMapdLLparam), &Parm, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
		if (Parm != NULL)
		{
			HookMapdLLparam tempParam = {0};
			tempParam.FuntionAddress = (ULONG64)TranslateMessageAddress;
			tempParam.OrgCodeSize = 12;
			tempParam.pramAddress = param;
			tempParam.ShellCodeAddress = Address;
			tempParam.OrgCode = NULL;
			alloc_mem(ProcessId,NULL, tempParam.OrgCodeSize, &tempParam.OrgCode, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
			tempParam.nRet = false;
			if (tempParam.OrgCode != NULL)
			{
				write_mem(ProcessId, TranslateMessageAddress, tempParam.OrgCodeSize,tempParam.OrgCode, ERWTYPE::MDL);
				write<HookMapdLLparam>(ProcessId,Parm, tempParam);
				return Parm;
			}
		}
	}
	return NULL;
}

bool drv::hook_fix_proxy(DWORD ProcessId, PVOID Poxy, HookMapdLLparam* param, SIZE_T PoxySize)
{
	for (int i = 0; i < PoxySize; i++)
	{
		ULONG64 P = read<ULONG64>(ProcessId,reinterpret_cast<PVOID>((ULONG64)Poxy + i));
		if (P == 0x1122334455667788)
		{
			write<ULONG64>(ProcessId,(PCHAR)Poxy + i, (ULONG64)param);
			return TRUE;
		}
	}
	return FALSE;
}

bool drv::hook_GetForegroundWindow(DWORD ProcessId, PVOID Poxy)
{
	HMODULE User32DllBabse = GetModuleHandleA("User32.dll");
	if (User32DllBabse != NULL)
	{
		PVOID TranslateMessageAddress = GetProcAddress(User32DllBabse, "TranslateMessage");
		if (TranslateMessageAddress != NULL)
		{
			UCHAR HookCode[] = {
				0x48,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,		//mov rax,1111111111111111
				0xff,0xe0												//jmp rax
			};
			*(PVOID*)&HookCode[2] = (PVOID)Poxy;
			//hook
			write_mem(ProcessId,TranslateMessageAddress, sizeof(HookCode),HookCode,ERWTYPE::MDL);
			return TRUE;
		}
	}
	return FALSE;
}

bool drv::close_handle(DWORD ProcessId, HANDLE handler)
{
	DataParams dp = { 0 };
	dp.cmd = CMD_Close;
	dp.pid = ProcessId;
	dp.params.thread.handler = handler;

	send_control(&dp);
	return TRUE;
}

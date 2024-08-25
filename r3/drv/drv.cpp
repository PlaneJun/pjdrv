#include "drv.h"

#include <string>
#include "../pdb/Pdb.h"
#include "dll_shellcode.h"



NTSTATUS drv::send_control(communicate::ECMD cmd, uint32_t pid, void* buffer)
{
	communicate::Params dp{};
	dp.cmd = cmd;
	dp.pid = pid;
	dp.buffer = buffer;

#ifdef IO_ahcache
	//写入TEB
	__writegsqword(0x38, reinterpret_cast<DWORD64>(&dp));
	DWORD real_bytes = NULL;
	DWORD64 data = NULL;
	DeviceIoControl(hFile_, 0x100, &data, sizeof(data), &data, sizeof(data), &real_bytes, nullptr);
#else
	DeviceIoControl(hFile_, IOCTL_NEITHER, &dp, sizeof(communicate::Params), NULL, NULL, NULL, NULL);
#endif

	return dp.status;
}

drv::ERROR_CODE drv::init()
{
	ERROR_CODE status_code = CODE_OK;
	do
	{
		// 是否可以打开设备
		if (!hFile_)
		{
#ifdef IO_ahcache
			wchar_t link_name[] = L"\\\\.\\ahcache";
#else
			wchar_t link_name[] = L"\\\\.\\rongshen_link";
#endif
			hFile_ = CreateFile(link_name,
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
		send_control(communicate::CMD_CONTROL,0,&ctrl_code);
		if (ctrl_code != 1 )
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

		communicate::Symbols symbs{};
		symbs.eprocess.VadRoot = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"VadRoot");
		symbs.eprocess.DirectoryTableBase = EzPdbGetStructPropertyOffset(&pdb, "_KPROCESS", L"DirectoryTableBase");
		symbs.eprocess.ThreadListHead = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"ThreadListHead");
		symbs.eprocess.ActiveProcessLinks = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"ActiveProcessLinks");
		symbs.eprocess.UniqueProcessId = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"UniqueProcessId");
		symbs.ethread.Cid = EzPdbGetStructPropertyOffset(&pdb, "_ETHREAD", L"Cid");
		symbs.ethread.ThreadListEntry = EzPdbGetStructPropertyOffset(&pdb, "_ETHREAD", L"ThreadListEntry");
		symbs.ethread.Win32StartAddress = EzPdbGetStructPropertyOffset(&pdb, "_ETHREAD", L"Win32StartAddress");
		symbs.ethread.StartAddress = EzPdbGetStructPropertyOffset(&pdb, "_ETHREAD", L"StartAddress");
		symbs.ethread.Process = EzPdbGetStructPropertyOffset(&pdb, "_KTHREAD", L"Process");
		symbs.global.KeServiceDescriptorTable = EzPdbGetRva(&pdb, "KeServiceDescriptorTable");
		symbs.global.PspNotifyEnableMask = EzPdbGetRva(&pdb, "PspNotifyEnableMask");
		symbs.global.ExDestroyHandle = EzPdbGetRva(&pdb, "ExDestroyHandle");
		symbs.global.ExMapHandleToPointer = EzPdbGetRva(&pdb, "ExMapHandleToPointer");
		symbs.global.PspCidTable = EzPdbGetRva(&pdb, "PspCidTable");
		
		DBG_LOG("VadRoot = %x", symbs.eprocess.VadRoot);
		DBG_LOG("DirectoryTableBase = %x", symbs.eprocess.DirectoryTableBase);
		DBG_LOG("ThreadListHead = %x", symbs.eprocess.ThreadListHead);
		DBG_LOG("Cid = %x", symbs.ethread.Cid);
		DBG_LOG("ThreadListEntry = %x", symbs.ethread.ThreadListEntry);
		DBG_LOG("Win32StartAddress = %x", symbs.ethread.Win32StartAddress);
		DBG_LOG("StartAddress = %x", symbs.ethread.StartAddress);
		DBG_LOG("Process = %x", symbs.ethread.Process);
		DBG_LOG("KeServiceDescriptorTable = %p", symbs.global.KeServiceDescriptorTable);
		DBG_LOG("PspNotifyEnableMask = %p", symbs.global.PspNotifyEnableMask);
		DBG_LOG("ExMapHandleToPointer = %p", symbs.global.ExMapHandleToPointer);
		DBG_LOG("ExDestroyHandle = %p", symbs.global.ExDestroyHandle);
		DBG_LOG("PspCidTable = %p", symbs.global.PspCidTable);
		if (symbs.eprocess.VadRoot <= 0 || symbs.eprocess.DirectoryTableBase <=0 || symbs.global.KeServiceDescriptorTable <= 0 || symbs.global.PspNotifyEnableMask <= 0)
		{
			status_code = ERROR_CODE::CODE_GET_SYMBOLS_FAILED;
			break;
		}
		EzPdbUnload(&pdb);
		send_control(communicate::ECMD::CMD_Symbol,0,&symbs);

	} while (FALSE);

	return status_code;
}

PVOID64 drv::get_process_module(DWORD ProcessId,PCWCH ModuleName,PSIZE_T size, bool isWow64)
{
	communicate::Module buffer = { 0 };
	buffer.module_name = (void*)(ModuleName);
	NTSTATUS status = send_control(communicate::ECMD::CMD_R3_GetProcessModules,ProcessId,&buffer);
	if(NT_SUCCESS(status))
	{
		if (size != nullptr)
		{
			*size = buffer.module_size;
		}
	}
	return buffer.output;
}

bool drv::get_export_address(DWORD ProcessId, PCWCH ModuleName , bool isWow64,PCCH FunctionName, PVOID64 Output)
{
	PVOID64 ModuleBase = get_process_module(ProcessId,  ModuleName,nullptr, isWow64);
	if (ModuleBase)
	{
		communicate::Module module{};
		module.module_base = ModuleBase;
		module.module_name = (PVOID64)FunctionName;
		module.output = Output;
		return NT_SUCCESS(send_control(communicate::ECMD::CMD_R3_GetExportFunction, ProcessId, &module));
	}
	return FALSE;
}

bool drv::read_mem(DWORD ProcessId, PVOID64 Address, ULONG ReadSize, PVOID64 Output, PSIZE_T retBytes, communicate::ERWTYPE type)
{
	communicate::Memory mem{};
	mem.addr = Address;
	mem.length = ReadSize;
	mem.output = Output;
	mem.rw_type = type;
	NTSTATUS status = send_control(communicate::ECMD::CMD_R3_ReadMemory,ProcessId,&mem);
	if (retBytes) *retBytes = mem.ret_bytes;
	return NT_SUCCESS(status);
}
bool drv::write_mem(DWORD ProcessId, PVOID64 Address, ULONG WriteSize, PVOID64 WriteBuffer, PSIZE_T retBytes, communicate::ERWTYPE type)
{
	communicate::Memory mem{};
	mem.addr = Address;
	mem.length = WriteSize;
	mem.buffer = WriteBuffer;
	mem.rw_type = type;
	NTSTATUS status = send_control(communicate::ECMD::CMD_R3_WriteMemory,ProcessId,&mem);
	if (retBytes) *retBytes = mem.ret_bytes;
	return NT_SUCCESS(status);
}

bool drv::alloc_mem(DWORD ProcessId, PVOID64 Address, ULONG Size, PVOID64 Output, ULONG AllocationType, ULONG Protect)
{
	communicate::Memory mem{};
	mem.addr = Address;
	mem.length = Size;
	mem.output = Output;
	mem.alloctype = AllocationType;
	mem.proctect = Protect;
	NTSTATUS status = send_control(communicate::ECMD::CMD_R3_AllocMemory, ProcessId, &mem);
	return NT_SUCCESS(status);
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
		NTSTATUS status = alloc_mem(ProcessId, reinterpret_cast<PVOID64>(AllocPtr), Size, &AllocBase, AllocationType, Protect);
		if(NT_SUCCESS(status))
		{
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
		}
		else
		{
			break;
		}
	} while (AllocBase == 0);

	return AllocBase;
}
bool drv::protect_mem(DWORD ProcessId, PVOID64 Address, ULONG Size, ULONG newProtect, PULONG oldProtect)
{
	communicate::Memory mem{};
	mem.addr = Address;
	mem.length = Size;
	mem.proctect = newProtect;
	NTSTATUS status = send_control(communicate::ECMD::CMD_R3_ProtectVirtualMemory,ProcessId,&mem);
	if(oldProtect != NULL)
	{
		*oldProtect = mem.oldprotect;
	}
	return NT_SUCCESS(status);
}
bool drv::free_mem(DWORD ProcessId, PVOID64 Address, ULONG Size)
{
	communicate::Memory mem{};
	mem.addr = Address;
	mem.length = Size;
	NTSTATUS status = send_control(communicate::ECMD::CMD_R3_FreeMemory, ProcessId, &mem);
	return NT_SUCCESS(status);
}
bool drv::query_mem(DWORD ProcessId, PVOID64 Address, PVOID64 Output)
{
	communicate::Memory mem{};
	mem.addr = Address;
	mem.output = Output;
	NTSTATUS status = send_control(communicate::ECMD::CMD_R3_QueryVirtualMemory, ProcessId, &mem);
	return NT_SUCCESS(status);
}

HANDLE drv::create_thread(DWORD ProcessId, PVOID entry, PVOID params,bool hide, PHANDLE tid)
{
	HANDLE retHandle = NULL;
	communicate::Thread thread{};
	thread.handler = &retHandle;
	thread.entry= entry;
	thread.params = params;
	thread.hide = hide;
	NTSTATUS status = send_control(communicate::ECMD::CMD_R3_CreateThread, ProcessId, &thread);
	if(NT_SUCCESS(status))
	{
		if(tid != nullptr)
		{
			*tid = thread.threadid;
		}
	}
	return thread.handler;
}

NTSTATUS drv::wait_single_object(DWORD ProcessId, HANDLE handle, bool alert, ULONG wait_time)
{
	HANDLE retHandle = NULL;
	communicate::Thread thread{};
	thread.handler = &retHandle;
	thread.wait_time = wait_time;
	thread.alert = alert;
	NTSTATUS status = send_control(communicate::ECMD::CMD_R3_WaitSingleObject, ProcessId, &thread);
	return status;
}

NTSTATUS drv::hide_thread(DWORD ProcessId, HANDLE tid, bool hide)
{
	communicate::Thread thread{};
	thread.threadid = tid;
	thread.hide = hide;
	NTSTATUS status = send_control(communicate::ECMD::cmd_R3_HideThread, ProcessId, &thread);
	return status;
}

bool drv::mouse_event_ex(DWORD x, DWORD y, USHORT flag)
{
	communicate::Device device{};
	device.mx = x;
	device.my = y;
	device.flags = flag;
	NTSTATUS status = send_control(communicate::ECMD::CMD_R3_MouseEvent, 0, &device);
	return NT_SUCCESS(status);
}
bool drv::keybd_event_ex(DWORD KeyCode, USHORT flag)
{
	communicate::Device device{};
	device.keycode = KeyCode;
	device.flags = flag;
	NTSTATUS status = send_control(communicate::CMD_R3_KbdEvent, 0, &device);
	return NT_SUCCESS(status);
}

bool drv::close_handle(DWORD ProcessId, HANDLE handler)
{
	communicate::Thread thread{};
	thread.handler = handler;
	NTSTATUS status = send_control(communicate::ECMD::CMD_R3_CloseHandle, ProcessId, &thread);
	return NT_SUCCESS(status);
}

bool drv::read_mem_safe(DWORD ProcessId, PVOID64 Address, ULONG ReadSize, PVOID64 Output, PSIZE_T retBytes, communicate::ERWTYPE type)
{
	ULONG readBytes = NULL;
	ULONG bytesToRead = NULL;
	uint64_t next_ptr = reinterpret_cast<uint64_t>(Address);
	do
	{
		MEMORY_BASIC_INFORMATION64 minfos{};
		if (!query_mem(ProcessId, Address, &minfos))
		{
			break;
		}

		bytesToRead = minfos.RegionSize;
		if ((readBytes + bytesToRead) > ReadSize)
		{
			bytesToRead = ReadSize - readBytes;
		}

		if (minfos.State == MEM_COMMIT)
		{
			if (!read_mem(ProcessId, reinterpret_cast<PVOID64>(next_ptr), bytesToRead, static_cast<PUCHAR>(Output) + readBytes, nullptr, type))
			{
				break;
			}
		}
		else
		{
			ZeroMemory(static_cast<PUCHAR>(Output) + readBytes, bytesToRead);
		}

		readBytes += bytesToRead;
		next_ptr += minfos.RegionSize;

	} while (readBytes < ReadSize);

	if (readBytes == ReadSize)
	{
		return TRUE;
	}

	return FALSE;
}

bool drv::dump_module(DWORD ProcessId, PCWCH module_name, PCCH save_path,bool isWow64)
{
	SIZE_T module_size = NULL;
	PVOID moudule_base = get_process_module(ProcessId, module_name,&module_size,isWow64);
	if(!moudule_base)
	{
		return FALSE;
	}
	std::vector<uint8_t> module_data(module_size);
	RtlZeroMemory(module_data.data(),module_size);

	if(read_mem_safe(ProcessId, moudule_base, module_size, module_data.data(),nullptr,communicate::MmCopy))
	{
		FILE* file = nullptr;
		fopen_s(&file, save_path, "wb+");
		if (!file) return FALSE;
		fwrite(module_data.data(), 1, module_data.size(), file);
		fclose(file);
		return TRUE;
	}
	return FALSE;
}

bool drv::dump_memory(DWORD ProcessId, PVOID64 memory_start, SIZE_T size, PCCH save_path)
{
	std::vector<uint8_t> mem_data(size);
	RtlZeroMemory(mem_data.data(), size);
	if (read_mem_safe(ProcessId, memory_start, size, mem_data.data(), nullptr, communicate::MmCopy))
	{
		FILE* file = nullptr;
		fopen_s(&file, save_path, "wb+");
		if (!file) return FALSE;
		fwrite(mem_data.data(), 1, mem_data.size(), file);
		fclose(file);
		return TRUE;
	}
	return FALSE;
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
	getchar();
	auto nAlign = pNTHeader->OptionalHeader.SectionAlignment;
	auto uSize = get_pe_size(pNTHeader, pSectionHeader, nAlign);
	PVOID pMemoryAddress = nullptr;
	if (!alloc_mem(ProcessId, nullptr, uSize, &pMemoryAddress, MEM_COMMIT | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE) && 
		 !pMemoryAddress)
	{
		DBG_LOG("alloc pMemoryAddress failed");
		return false;
	}
	DBG_LOG("alloc pMemoryAddress = %p", pMemoryAddress);

	if (!copy_sections(ProcessId,pNTHeader, pSectionHeader, dll_data, pMemoryAddress))
	{
		return false;
	}
	DBG_LOG("copy_sections ok!");

	//fix reloc
	fix_loc_datas(ProcessId,pNTHeader, pMemoryAddress);
	Shellparam* param = NULL;
	if(!alloc_mem(ProcessId, NULL, sizeof(Shellparam), &param, MEM_COMMIT |  MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE) && 
		!param)
	{
		DBG_LOG("alloc Shellparam failed,err = %x");
		return false;
	}
	DBG_LOG("Shellparam = %p", param);

	// fill shellcode params
	fill_params(ProcessId,param, pMemoryAddress, pDosHeader->e_lfanew);
	PVOID ShllCodeMeory = NULL;
	if(!alloc_mem(ProcessId, NULL, sizeof(g_ShellCodeExDll), &ShllCodeMeory, MEM_COMMIT | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE) &&
		!ShllCodeMeory)
	{
		DBG_LOG("alloc ShllCodeMeory failed,err = %x");
		return false;
	}
	DBG_LOG("ShllCodeMeory = %p", ShllCodeMeory);
	if(!write_mem(ProcessId,ShllCodeMeory, sizeof(g_ShellCodeExDll),g_ShellCodeExDll, NULL,communicate::ERWTYPE::MmCopy))
	{
		DBG_LOG("write ShellCodeExDll failed,err = %x");
		return false;
	}

	PVOID64 pHookAddressMemory = NULL;
	run_hook(ProcessId,ShllCodeMeory, param,&pHookAddressMemory);
	Shellparam wait_inject{};
	if (pHookAddressMemory != NULL)
	{
		DBG_LOG("wait inject");

		do
		{
			wait_inject = read<Shellparam>(ProcessId,param);
			Sleep(1000);
		} while (wait_inject.IsOk != 1);
		Sleep(50);

		DBG_LOG("inject done");
	FreeMem:
		if (param)
		{
			if(free_mem(ProcessId, param, sizeof(Shellparam)))
			{
				param = NULL;
			}
			else
			{
				DBG_LOG("free Shellparam failed,err = %x");
			}
		}

		if (ShllCodeMeory)
		{
			if(free_mem(ProcessId, ShllCodeMeory, sizeof(g_ShellCodeExDll)))
			{
				ShllCodeMeory = NULL;
			}
			else
			{
				DBG_LOG("free ShllCodeMeory failed,err = %x");
			}
		}

		if (pHookAddressMemory)
		{
			if(free_mem(ProcessId, pHookAddressMemory, sizeof(g_HookCode)))
			{
				pHookAddressMemory = NULL;
			}
			else
			{
				DBG_LOG("free pHookAddressMemory failed,err = %x");
			}
		}

	}
	else
	{
		goto FreeMem;
	}

	return pMemoryAddress;
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
	write_mem(ProcessId,MemoryAddress, static_cast<ULONG>(MoveSize),data,NULL,communicate::ERWTYPE::MmCopy);

	//复制每个节
	for (int i = 0; i < NtHread->FileHeader.NumberOfSections; ++i)
	{
		if (SectionHeader[i].VirtualAddress == 0 || SectionHeader[i].SizeOfRawData == 0)
			continue;
		auto pSectionAddress = reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(MemoryAddress) + SectionHeader[i].VirtualAddress);
		write_mem(ProcessId, pSectionAddress, SectionHeader[i].SizeOfRawData, static_cast<PCHAR>(data) + SectionHeader[i].PointerToRawData, NULL, communicate::ERWTYPE::MmCopy);
	}
	return TRUE;
}

VOID drv::fix_loc_datas(DWORD ProcessId, PIMAGE_NT_HEADERS NtHread, PVOID MemoryAddress)
{
	if (NtHread->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0
		&& NtHread->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
	{
		DWORD64 Delta = reinterpret_cast<uint64_t>(MemoryAddress) - NtHread->OptionalHeader.ImageBase;
		DWORD64* pAddress = nullptr;

		//注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址
		PCHAR tmpData = new CHAR[NtHread->OptionalHeader.SizeOfImage];
		ZeroMemory(tmpData, NtHread->OptionalHeader.SizeOfImage);
		read_mem(ProcessId,MemoryAddress, NtHread->OptionalHeader.SizeOfImage,tmpData, NULL, communicate::ERWTYPE::MmCopy);

		auto pLoc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uintptr_t>(tmpData)
			+ NtHread->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
		{
			auto pLocData = reinterpret_cast<PSHORT>(reinterpret_cast<uintptr_t>(pLoc) + sizeof(IMAGE_BASE_RELOCATION));
			//计算本节需要修正的重定位项（地址）的数目
			int NumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(SHORT);
			for (int i = 0; i < NumberOfReloc; i++)
			{
				uint64_t flags = static_cast<uint64_t>(pLocData[i] & 0xF000);
				if (flags == 0x00003000 || flags == 0x0000A000) //这是一个需要修正的地址
				{
					pAddress = reinterpret_cast<DWORD64*>(reinterpret_cast<uintptr_t>(MemoryAddress) + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
					DWORD64 origin = read<DWORD64>(ProcessId,pAddress, communicate::ERWTYPE::MmCopy);
					write<DWORD64>(ProcessId,pAddress, origin + Delta, communicate::ERWTYPE::MmCopy);
				}
			}
			pLoc = reinterpret_cast<decltype(pLoc)>(reinterpret_cast<uintptr_t>(pLoc) + pLoc->SizeOfBlock);
		}

		delete[] tmpData;
	}
}

bool drv::fill_params(DWORD ProcessId,Shellparam* param, PVOID MemoryAddress, DWORD e_lfanew)
{
	const HMODULE DllBase = GetModuleHandleA("ntdll.dll");
	if (DllBase == NULL)
	{
		DBG_LOG("get ntdll base failed,err:%d",GetLastError());
		return FALSE;
	}
	Shellparam temp{};

	temp.LdrGetProcedureAddress = reinterpret_cast<LdrGetProcedureAddressT>(GetProcAddress(DllBase, "LdrGetProcedureAddress"));
	DBG_LOG("LdrGetProcedureAddress %p", temp.LdrGetProcedureAddress);

	temp.dwNtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemoryT>(GetProcAddress(DllBase, "NtAllocateVirtualMemory"));
	DBG_LOG("dwNtAllocateVirtualMemory %p", temp.dwNtAllocateVirtualMemory);

	temp.pLdrLoadDll = reinterpret_cast<LdrLoadDllT>(GetProcAddress(DllBase, "LdrLoadDll"));
	DBG_LOG("pLdrLoadDll %p", temp.pLdrLoadDll);

	temp.RtlInitAnsiString = reinterpret_cast<RtlInitAnsiStringT>(GetProcAddress(DllBase, "RtlInitAnsiString"));
	DBG_LOG("RtlInitAnsiString %p", temp.RtlInitAnsiString);

	temp.RtlAnsiStringToUnicodeString = reinterpret_cast<RtlAnsiStringToUnicodeStringT>(GetProcAddress(DllBase, "RtlAnsiStringToUnicodeString"));
	DBG_LOG("RtlAnsiStringToUnicodeString %p", temp.RtlAnsiStringToUnicodeString);

	temp.RtlFreeUnicodeString = reinterpret_cast<RtlFreeUnicodeStringT>(GetProcAddress(DllBase, "RtlFreeUnicodeString"));
	DBG_LOG("RtlFreeUnicodeString %p", temp.RtlFreeUnicodeString);

	temp.pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(MemoryAddress) + e_lfanew);
	DBG_LOG("pNTHeader %p", temp.pNTHeader);

	temp.pMemoryAddress = MemoryAddress;

	write<Shellparam>(ProcessId,param, temp);

	return TRUE;
}

bool drv::run_hook(DWORD ProcessId, PVOID Address, Shellparam* param,PVOID64* HookAddressMemory)
{
	HookMapdLLparam* Hookparam = nullptr;
	//alloc hook memory
	PVOID Porx = nullptr;
	if(alloc_mem(ProcessId, nullptr, sizeof(g_HookCode), &Porx, MEM_COMMIT | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE) &&
		Porx)
	{
		if(PVOID hijack_func = GetProcAddress(GetModuleHandleA("User32.dll"), "GetForegroundWindow"))
		{
			DBG_LOG("[+]hijack_func = %p\r\n", hijack_func);

			//fill hook param
			Hookparam = hook_params_alloc_memory(ProcessId, Address, param, hijack_func);
			if (Hookparam != nullptr)
			{
				// NOTE:g_HookCode用于恢复hook的hijack_func字节码后手动call hijack_func，最后执行的shellcode(注入)
				write_mem(ProcessId, Porx, sizeof(g_HookCode), g_HookCode, nullptr, communicate::ERWTYPE::MmCopy);
				if (hook_fix_proxy(ProcessId, Porx, Hookparam, sizeof(g_HookCode)))
				{
					*HookAddressMemory = Porx;
					static UCHAR HookCode[] = {
						0x48,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,		//mov rax,1111111111111111
						0xff,0xe0												//jmp rax
					};
					*(PVOID*)&HookCode[2] = Porx;

					//hook
					ULONG old{};
					if (protect_mem(ProcessId, hijack_func, 0x1000, PAGE_EXECUTE_READWRITE, &old))
					{
						write_mem(ProcessId, hijack_func, sizeof(HookCode), HookCode, NULL, communicate::ERWTYPE::MmCopy);
					}
				}
				else
				{
					free_mem(ProcessId, Hookparam, sizeof(HookMapdLLparam));
					*HookAddressMemory = NULL;
				}
			}
		}
		else
		{
			free_mem(ProcessId,Porx, sizeof(g_HookCode));
		}
	}
	else
	{
		DBG_LOG("alloc HookCode failed,err:%d");
	}

	return false;
}

HookMapdLLparam* drv::hook_params_alloc_memory(DWORD ProcessId, PVOID Address, Shellparam* param, PVOID hijackAddr)
{
	HookMapdLLparam* Parm = NULL;
	if (hijackAddr != NULL)
	{
		Parm = NULL;
		if (alloc_mem(ProcessId, NULL, sizeof(HookMapdLLparam), &Parm, MEM_COMMIT | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE) &&
			 Parm)
		{
			DBG_LOG("Param = %p", Parm);
			HookMapdLLparam tempParam = {0};
			tempParam.FuntionAddress = reinterpret_cast<ULONG64>(hijackAddr);
			tempParam.OrgCodeSize = 12;
			tempParam.pramAddress = param;
			tempParam.ShellCodeAddress = Address;
			tempParam.OrgCode = NULL;
			alloc_mem(ProcessId,NULL, static_cast<ULONG>(tempParam.OrgCodeSize), &tempParam.OrgCode, MEM_COMMIT | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
			tempParam.nRet = false;
			if (tempParam.OrgCode != NULL)
			{
				write_mem(ProcessId, tempParam.OrgCode, tempParam.OrgCodeSize, hijackAddr, NULL, communicate::ERWTYPE::MmCopy);
				write<HookMapdLLparam>(ProcessId,Parm, tempParam);
				DBG_LOG("write HookMapdLLparam done");
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
			DBG_LOG("fix pos:%p", (ULONG64)Poxy + i);
			write<ULONG64>(ProcessId,(PCHAR)Poxy + i, (ULONG64)param);
			return TRUE;
		}
	}
	return FALSE;
}


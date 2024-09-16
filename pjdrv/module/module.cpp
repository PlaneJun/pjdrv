#include "module.h"

#include <ntimage.h>
#include <Veil.h>

NTSTATUS module::get_kernel_module(const char* szModuleName, uintptr_t* BaseAddress, size_t* ModuleSize)
{
	ULONG uSize = NULL;
	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &uSize);
	if (uSize <= 0)
	{
		return STATUS_UNSUCCESSFUL;
	}

	PVOID64 pModuleInfo = ExAllocatePoolWithTag(NonPagedPool, uSize, 'GetB');
	if (pModuleInfo == NULL)
	{
		return 0;
	}

	RtlZeroMemory(pModuleInfo, uSize);
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, pModuleInfo, uSize, NULL);
	if (!NT_SUCCESS(status))
	{
		if (pModuleInfo != NULL)
		{
			ExFreePool(pModuleInfo);
			pModuleInfo = NULL;
		}
		return STATUS_UNSUCCESSFUL;
	}

	size_t uNumberOfModules = *(size_t*)pModuleInfo;
	if (uNumberOfModules == 0)
	{
		return STATUS_UNSUCCESSFUL;
	}

	PRTL_PROCESS_MODULE_INFORMATION pStart = (PRTL_PROCESS_MODULE_INFORMATION)((ULONG64)pModuleInfo + sizeof(ULONG64));
	for (size_t uCount = 0; uCount < uNumberOfModules; uCount++)
	{
		if (strstr((const char*)pStart->FullPathName, szModuleName))
		{
			uintptr_t uImageBase = reinterpret_cast<uintptr_t>(pStart->ImageBase);
			ULONG uImageSize = pStart->ImageSize;
			if (pModuleInfo != NULL)
			{
				ExFreePool(pModuleInfo);
				pModuleInfo = NULL;
			}

			*BaseAddress = uImageBase;
			*ModuleSize = uImageSize;
			return STATUS_SUCCESS;
		}
		pStart++;
	}

	if (pModuleInfo != NULL)
	{
		ExFreePool(pModuleInfo);
		pModuleInfo = NULL;
	}

	return STATUS_UNSUCCESSFUL;
}


PVOID module::kernel_load_library(const wchar_t* full_dll_path)
{
	HANDLE hSection = NULL, hFile = NULL;
	UNICODE_STRING dllName = { 0 };
	OBJECT_ATTRIBUTES obj_attr = { sizeof(obj_attr), 0, &dllName, OBJ_CASE_INSENSITIVE };
	IO_STATUS_BLOCK iosb = { 0 };
	RtlInitUnicodeString(&dllName, full_dll_path);
	NTSTATUS status = ZwOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &obj_attr, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status)) {
		return NULL;
	}

	obj_attr.ObjectName = 0;
	status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &obj_attr, 0, PAGE_EXECUTE, 0x1000000, hFile);
	if (!NT_SUCCESS(status)) {
		return NULL;
	}

	PVOID BaseAddress = NULL;
	SIZE_T size = 0;
	status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 1000, 0, &size, (SECTION_INHERIT)1, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		return NULL;
	}
	ZwClose(hSection);
	ZwClose(hFile);
	return BaseAddress;
}

PVOID module::get_module_export(PVOID pBase, const char* name_ord)
{
	PIMAGE_DOS_HEADER pDosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(pBase);
	if (pBase == NULL)
		return NULL;

	/// Not a PE file
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS32 pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
	PIMAGE_NT_HEADERS64 pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);
	// Not a PE file
	if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	ULONG expSize = NULL;
	if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		// 64 bit image
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	else
	{
		// 32 bit image
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	PUSHORT pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
	PULONG pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
	PULONG pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);
	ULONG_PTR pAddress = NULL;
	for (DWORD32 i = 0; i < pExport->NumberOfFunctions; ++i)
	{
		USHORT OrdIndex = 0xFFFF;
		PCHAR  pName = NULL;
		// Find by index
		if ((ULONG_PTR)name_ord <= 0xFFFF)
		{
			OrdIndex = (USHORT)i;
		}
		// Find by name
		else if ((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames)
		{
			pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
			OrdIndex = pAddressOfOrds[i];
		}
		// Weird params
		else
		{
			return NULL;
		}

		if (((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
			((ULONG_PTR)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0))
		{
			pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;
			// Check forwarded export
			if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize)
			{
				return NULL;
			}
			break;
		}
	}
	return (PVOID)pAddress;
}

PVOID module::get_ntoskrnl_base(OUT PULONG pSize)
{
	PVOID krnlBase = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	PVOID checkPtr = NULL;
	UNICODE_STRING routineName;
	ULONG i;


	RtlInitUnicodeString(&routineName, L"NtOpenFile");

	checkPtr = MmGetSystemRoutineAddress(&routineName);
	if (checkPtr == NULL)
		return NULL;

	// Protect from UserMode AV
	status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
	if (bytes == 0)
	{
		return NULL;
	}

	pMods = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, bytes);
	RtlZeroMemory(pMods, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

	if (NT_SUCCESS(status))
	{
		PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

		for (i = 0; i < pMods->NumberOfModules; i++)
		{
			// System routine is inside module
			if (checkPtr >= pMod[i].ImageBase &&
				checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
			{
				krnlBase = pMod[i].ImageBase;
				if(pSize)
				{
					*pSize = pMod[i].ImageSize;
				}
				break;
			}
		}
	}

	if (pMods)
		ExFreePool(pMods);

	return krnlBase;
}
#include "memory.h"
#include <ntimage.h>
#include <stdint.h>

PVOID memory::find_pattern_in_module(uintptr_t base, const char* sec_name, const unsigned char* pattern, size_t size, size_t offset)
{
	if (base == NULL)
	{
		return NULL;
	}

	// 获取dos头
	PIMAGE_DOS_HEADER pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
	if(pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	// 获取NT头
	PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(base + pDos->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((PUCHAR)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);
	for (ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		if (!_stricmp((char*)section->Name, sec_name))
		{
			uint8_t* sec_addr =reinterpret_cast<uint8_t*>(base + section->VirtualAddress);
			if (sec_addr)
			{
				size_t step = 0;
				do
				{
					size_t p = 0;
					for (; p < size; p++)
					{
						uint8_t c = pattern[p];
						if (c != 0xCC && c != sec_addr[step + p])
							break;
					}
					if (p >= size)
					{
						return &sec_addr[step + offset + *(int*)&sec_addr[step + offset + 3] + 7];
					}

					step++;
				} while (step < section->Misc.VirtualSize);
			}
		}
		section++;
	}
	return 0;
}

NTSTATUS memory::translate_addrsss(IN UINT64 DirBase, _Inout_ PUINT64 addr)
{
	UINT16   PML4, PDPE, PDE, PTE, offset;
	UINT64   mask = 0x7fffff000;
	UINT64   uTmp;
	SIZE_T   BytesTransferred;
	NTSTATUS status;

	offset = *addr & 0xfff;
	PTE = (*addr >> 12) & 0x1ff;
	PDE = (*addr >> (12 + 9)) & 0x1ff;
	PDPE = (*addr >> (9 * 2 + 12)) & 0x1ff;
	PML4 = (*addr >> (9 * 3 + 12)) & 0x1ff;

	do
	{
		status = read_physical_addr((PVOID64)(DirBase + PML4 * 8), &uTmp, sizeof(uTmp), &BytesTransferred);
		if (!NT_SUCCESS(status))
			break;

		uTmp &= mask;

		status = read_physical_addr((PVOID64)(uTmp + PDPE * 8), &uTmp, sizeof(uTmp), &BytesTransferred);
		if (!NT_SUCCESS(status))
			break;

		uTmp &= mask;

		status = read_physical_addr((PVOID64)(uTmp + PDE * 8), &uTmp, sizeof(uTmp), &BytesTransferred);
		if (!NT_SUCCESS(status))
			break;

		uTmp &= mask;

		status = read_physical_addr((PVOID64)(uTmp + PTE * 8), &uTmp, sizeof(uTmp), &BytesTransferred);
		if (!NT_SUCCESS(status))
			break;

		uTmp &= mask;

		*addr = uTmp + offset;
	} while (false);
	
	return status;
}

NTSTATUS memory::read_physical_addr(IN PVOID64 address, OUT PVOID64 buffer, IN SIZE_T size, OUT SIZE_T* BytesTransferred)
{
	MM_COPY_ADDRESS Read = { 0 };
	Read.PhysicalAddress.QuadPart = (LONG64)address;
	return MmCopyMemory(
		buffer, Read, size, MM_COPY_MEMORY_PHYSICAL, BytesTransferred);
}

NTSTATUS memory::write_physical_addr(IN PVOID64 address, IN PVOID64 buffer, IN SIZE_T size, OUT SIZE_T* BytesTransferred)
{
	PVOID            map;
	PHYSICAL_ADDRESS Write = { 0 };

	if (!address) {
		return STATUS_UNSUCCESSFUL;
	}

	Write.QuadPart = (LONG64)address;
	map = MmMapIoSpaceEx(Write, size, PAGE_READWRITE);

	if (!map) {
		return STATUS_UNSUCCESSFUL;
	}
	RtlCopyMemory(map, buffer, size);
	*BytesTransferred = size;
	MmUnmapIoSpace(map, size);
	return STATUS_SUCCESS;
}
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


static const uint64_t PMASK = (~0xfull << 8) & 0xfffffffffull;
uint64_t memory::translate_addrsss(uint64_t DirBase, uint64_t addr)
{
	DirBase &= ~0xf;

	uint64_t pageOffset = addr & ~(~0ul << 12);
	uint64_t pte = ((addr >> 12) & (0x1ffll));
	uint64_t pt = ((addr >> 21) & (0x1ffll));
	uint64_t pd = ((addr >> 30) & (0x1ffll));
	uint64_t pdp = ((addr >> 39) & (0x1ffll));

	SIZE_T readsize = 0;
	uint64_t pdpe = 0;
	read_physical_addr(reinterpret_cast<PVOID64>(DirBase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
	if (~pdpe & 1)
		return 0;

	uint64_t pde = 0;
	read_physical_addr(reinterpret_cast<PVOID64>((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
	if (~pde & 1)
		return 0;

	/* 1GB large page, use pde's 12-34 bits */
	if (pde & 0x80)
		return (pde & (~0ull << 42 >> 12)) + (addr & ~(~0ull << 30));

	uint64_t pteAddr = 0;
	read_physical_addr(reinterpret_cast<PVOID64>((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
	if (~pteAddr & 1)
		return 0;

	/* 2MB large page */
	if (pteAddr & 0x80)
		return (pteAddr & PMASK) + (addr & ~(~0ull << 21));

	addr = 0;
	read_physical_addr(reinterpret_cast<PVOID64>((pteAddr & PMASK) + 8 * pte), &addr, sizeof(addr), &readsize);
	addr &= PMASK;

	if (!addr)
		return 0;

	return addr + pageOffset;
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
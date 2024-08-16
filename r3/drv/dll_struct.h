#pragma once
#include <windows.h>
#include <stdint.h>

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef NTSTATUS(WINAPI* LdrGetProcedureAddressT)(PVOID DllHandle, PANSI_STRING ProcedureName OPTIONAL, ULONG ProcedureNumber OPTIONAL, FARPROC* ProcedureAddress);
typedef VOID(WINAPI* RtlFreeUnicodeStringT)(PUNICODE_STRING UnicodeString);
typedef VOID(WINAPI* RtlInitAnsiStringT)(PANSI_STRING DestinationString, const char* SourceString);
typedef NTSTATUS(WINAPI* RtlAnsiStringToUnicodeStringT)(PUNICODE_STRING DestinationString, PANSI_STRING SourceString, bool AllocateDestinationString);
typedef NTSTATUS(WINAPI* LdrLoadDllT)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef bool(APIENTRY* ProcDllMain)(PVOID, DWORD32, PVOID);
typedef NTSTATUS(WINAPI* NtAllocateVirtualMemoryT)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef VOID(*AllocateVirtualMemory)(SIZE_T);
typedef BOOL(WINAPI* DllEntryProc)(HINSTANCE hinstDLL, DWORD32 fdwReason, PVOID lpReserved);
struct Shellparam
{

	LdrGetProcedureAddressT LdrGetProcedureAddress;
	NtAllocateVirtualMemoryT dwNtAllocateVirtualMemory;
	LdrLoadDllT pLdrLoadDll;
	RtlInitAnsiStringT RtlInitAnsiString;
	RtlAnsiStringToUnicodeStringT RtlAnsiStringToUnicodeString;
	RtlFreeUnicodeStringT RtlFreeUnicodeString;
	PIMAGE_NT_HEADERS pNTHeader;
	PVOID pMemoryAddress;
	ULONG64 IsOk;
};

struct HookMapdLLparam
{
	PVOID ShellCodeAddress;
	PVOID pramAddress;
	PVOID OrgCode;
	ULONG64 OrgCodeSize;
	ULONG64 FuntionAddress;
	bool nRet;
};
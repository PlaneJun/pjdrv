#pragma once
#include <cstdint>
#include <ntifs.h>

class ssdt
{

public:
	typedef struct _SYSTEM_SERVICE_TABLE {
		PVOID ServiceTableBase;
		PVOID ServiceCounterTableBase;
		ULONG64	NumberOfServices;
		PVOID  		ParamTableBase;
	} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

public:
	static ssdt* get_instance();

	uintptr_t get_func_by_index(uint32_t index);

	uintptr_t get_func_by_name(const char* funname);

private:
	static ssdt* instance_;

	PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable_;

	VOID GetKeServiceDescriptorTableAddrX64();

};


#pragma once
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
	bool ssdt_init();

	ULONG64 get_func_by_index(ULONG index);

	ULONG64 get_func_by_name(const char* funname);

private:
	PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable_;

	VOID GetKeServiceDescriptorTableAddrX64();

};


#pragma once
#include <ntifs.h>

class Control
{
public:
	NTSTATUS install(PDRIVER_OBJECT pDrv);
	void uninstall();
};
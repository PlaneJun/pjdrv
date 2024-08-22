#pragma once
#include <ntifs.h>

class Control
{
public:
	void install(PDRIVER_OBJECT pDrv);
	void uninstall();
};
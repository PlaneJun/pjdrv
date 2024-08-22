#include <ntifs.h>
#include "control/control.h"
#include "log/log.hpp"


Control* g_con = NULL;

VOID UnLoadDrv(PDRIVER_OBJECT DriverObject)
{
	g_con->uninstall();
	DBG_LOG("unload,%d",1);
}

EXTERN_C NTSTATUS DriverMain(const PDRIVER_OBJECT pDrv, const PUNICODE_STRING pReg)
{
    UNREFERENCED_PARAMETER(pReg);
	NTSTATUS status = STATUS_SUCCESS;
	pDrv->DriverUnload = UnLoadDrv;
	do 
	{
		g_con = new Control;
		g_con->install(pDrv);
	} while (FALSE);
	return status;
}
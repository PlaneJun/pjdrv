#include <ntifs.h>
#include "control/control.h"

VOID UnLoadDrv(PDRIVER_OBJECT DriverObject)
{
	
}

EXTERN_C NTSTATUS DriverMain(const PDRIVER_OBJECT pDrv, const PUNICODE_STRING pReg)
{
    UNREFERENCED_PARAMETER(pReg);
	NTSTATUS status = STATUS_SUCCESS;
	pDrv->DriverUnload = UnLoadDrv;
	do 
	{
		Control con;
		con.install();
	} while (FALSE);
	return status;
}
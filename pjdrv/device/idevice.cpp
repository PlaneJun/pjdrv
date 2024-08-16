#include "idevice.h"
#include <Veil.h>

PVOID IDevice::lpfnClassServiceCallback_ =NULL;

PDEVICE_OBJECT IDevice::dev_klass_ = NULL;

NTSTATUS IDevice::init_device(const wchar_t* hid_name, const wchar_t* class_name)
{
	NTSTATUS status = STATUS_SUCCESS;
	if (lpfnClassServiceCallback_)
	{
		return status;
	}

	PDRIVER_OBJECT pdrv_hid = NULL;
	UNICODE_STRING str_drvMouhid = {0};
	RtlInitUnicodeString(&str_drvMouhid, hid_name);
	status = ObReferenceObjectByName(&str_drvMouhid, OBJ_CASE_INSENSITIVE, 0, FILE_ANY_ACCESS, *IoDriverObjectType, KernelMode, 0, (PVOID*)&pdrv_hid);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	ObDereferenceObject(pdrv_hid);
	PDRIVER_OBJECT pdrv_class = NULL;
	UNICODE_STRING str_drvMouclass = {0};
	RtlInitUnicodeString(&str_drvMouclass, class_name);
	status = ObReferenceObjectByName(&str_drvMouclass, OBJ_CASE_INSENSITIVE, 0, FILE_ANY_ACCESS, *IoDriverObjectType, KernelMode, 0, (PVOID*)&pdrv_class);
	if (!NT_SUCCESS(status))
		return status;
	ObDereferenceObject(pdrv_class);

	status = STATUS_UNSUCCESSFUL;
	PDEVICE_OBJECT pdev_hid = pdrv_hid->DeviceObject;
	while (pdev_hid)
	{
		//获取保存着mouclass设备的设备
		PDEVICE_OBJECT pdev_attach = pdev_hid;
		while (pdev_attach)
		{
			if (!RtlCompareUnicodeString(&pdev_attach->AttachedDevice->DriverObject->DriverName, &str_drvMouclass, TRUE))
				break;
			pdev_attach = pdev_attach->AttachedDevice;
		}
		if (pdev_attach->AttachedDevice && pdev_attach->AttachedDevice == pdrv_class->DeviceObject)
		{
			dev_klass_ = pdrv_class->DeviceObject;
			ULONG_PTR devext = (ULONG_PTR)pdev_attach->DeviceExtension;
			ULONG_PTR drvStart = (ULONG_PTR)pdrv_class->DriverStart;
			ULONG drvSize = pdrv_class->DriverSize;
			for (int i = 0; i < 4096; i++)
			{
				if (!MmIsAddressValid((PVOID)devext))
					break;

				ULONG_PTR tmp = *(PULONG_PTR)devext;
				//如果在设备扩展中找到一个地址位于mouclass模块中，就认为这是我们要的回调函数地址
				if (tmp >= drvStart && tmp < (drvStart + drvSize))
				{
					lpfnClassServiceCallback_ = (PVOID)tmp;
					status = STATUS_SUCCESS;
					break;
				}
				devext++;
			}
		}
		if (NT_SUCCESS(status))
			break;
		pdev_hid = pdev_hid->NextDevice;
	}
	return status;
}
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

	PDRIVER_OBJECT pdrv_dev = NULL;
	UNICODE_STRING str_drvhid = {0};
	RtlInitUnicodeString(&str_drvhid, hid_name);
	status = ObReferenceObjectByName(&str_drvhid, OBJ_CASE_INSENSITIVE, 0, FILE_ANY_ACCESS, *IoDriverObjectType, KernelMode, 0, (PVOID*)&pdrv_dev);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	ObDereferenceObject(pdrv_dev);
	PDRIVER_OBJECT pdrv_class = NULL;
	UNICODE_STRING str_drvclass = {0};
	RtlInitUnicodeString(&str_drvclass, class_name);
	status = ObReferenceObjectByName(&str_drvclass, OBJ_CASE_INSENSITIVE, 0, FILE_ANY_ACCESS, *IoDriverObjectType, KernelMode, 0, (PVOID*)&pdrv_class);
	if (!NT_SUCCESS(status))
		return status;
	ObDereferenceObject(pdrv_class);

	status = STATUS_UNSUCCESSFUL;

	auto vClassDriverStart = reinterpret_cast<PVOID>(pdrv_class->DriverStart);
	auto vClassDriverEnd = reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(vClassDriverStart) + pdrv_class->DriverSize);

	PDEVICE_OBJECT pdev_hid = pdrv_dev->DeviceObject;
	while (pdev_hid)
	{
		auto vDeviceExtBytes = reinterpret_cast<intptr_t>(pdev_hid->DeviceObjectExtension) - reinterpret_cast<intptr_t>(pdev_hid->DeviceExtension);
		if (vDeviceExtBytes > 0)
		{
			auto vDeviceExtPtrCount = vDeviceExtBytes / sizeof(void*) - 1;
			auto vDeviceExt = static_cast<void**>(pdev_hid->DeviceExtension);

			for (auto vClassDevice = pdrv_class->DeviceObject; vClassDevice; vClassDevice = vClassDevice->NextDevice)
			{
				for (auto i = 0u; i < vDeviceExtPtrCount; ++i)
				{
					if (vDeviceExt[i] == vClassDevice &&
						vDeviceExt[i + 1] > vClassDriverStart &&
						vDeviceExt[i + 1] < vClassDriverEnd)
					{
						dev_klass_ = vClassDevice;
						lpfnClassServiceCallback_ = vDeviceExt[i + 1];

						status = STATUS_SUCCESS;
						break;
					}
				}
				if (NT_SUCCESS(status))
				{
					break;
				}
			}
		}
		pdev_hid = pdev_hid->NextDevice;
	}
	return status;
}
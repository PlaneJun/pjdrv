#pragma once
#include <ntifs.h>

class IDevice
{
public:
	static NTSTATUS init_device(const wchar_t* hid_name,const wchar_t* class_name);

protected:

	static PVOID lpfnClassServiceCallback_;

	static PDEVICE_OBJECT dev_klass_;

};
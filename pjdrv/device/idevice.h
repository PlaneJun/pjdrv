#pragma once
#include <ntifs.h>

class IDevice
{
public:
	IDevice() :lpfnClassServiceCallback_(nullptr), dev_klass_(nullptr) {}
	NTSTATUS init_device(const wchar_t* hid_name,const wchar_t* class_name);

protected:

	PVOID lpfnClassServiceCallback_;

	PDEVICE_OBJECT dev_klass_;

};
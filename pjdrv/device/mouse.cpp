#include "mouse.h"

NTSTATUS Mouse::init()
{
	return init_device(L"\\Driver\\mouhid", L"\\Driver\\mouclass");
}

void Mouse::mouse_event_(ULONG x, ULONG y, USHORT flags)
{
	DbgPrintEx(77, 0, "lpfnClassServiceCallback_ = %p\n", lpfnClassServiceCallback_);
	if (!lpfnClassServiceCallback_)
		return;

	ULONG input_data = NULL;
	KIRQL CurrentIrql = KeGetCurrentIrql();
	__writecr8(2);
	MOUSE_INPUT_DATA mid = { 0 };
	mid.LastX = x;
	mid.LastY = y;
	mid.ButtonFlags = flags;
	mid.UnitId = 1;
	((fnMouseClassServiceCallback)lpfnClassServiceCallback_)(dev_klass_, &mid, (PMOUSE_INPUT_DATA)&mid + 1, &input_data);
	__writecr8(CurrentIrql);
}
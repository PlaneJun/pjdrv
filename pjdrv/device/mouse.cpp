#include "mouse.h"

NTSTATUS Mouse::init()
{
	return init_device(L"\\Driver\\mouhid", L"\\Driver\\mouclass");
}
#define KeMRaiseIrql(a,b) *(b) = KfRaiseIrql(a)
void Mouse::mouse_event_(ULONG x, ULONG y, USHORT flags)
{
	DbgPrintEx(77, 0, "lpfnClassServiceCallback_ = %p\n", lpfnClassServiceCallback_);
	if (!lpfnClassServiceCallback_)
		return;

	ULONG input_data = NULL;
	KIRQL CurrentIrql = KeGetCurrentIrql();
	KeMRaiseIrql(DISPATCH_LEVEL, &CurrentIrql);
	//__writecr8(DISPATCH_LEVEL);
	MOUSE_INPUT_DATA mid = { 0 };
	mid.LastX = x;
	mid.LastY = y;
	mid.ButtonFlags = flags;
	mid.UnitId = 1;
	((fnMouseClassServiceCallback)lpfnClassServiceCallback_)(dev_klass_, &mid, (PMOUSE_INPUT_DATA)&mid + 1, &input_data);
	//__writecr8(CurrentIrql);
	KeLowerIrql(CurrentIrql);
}
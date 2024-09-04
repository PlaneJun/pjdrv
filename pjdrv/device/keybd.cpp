#include "keybd.h"

NTSTATUS Keybd::init()
{
	//KdBreakPoint();
	NTSTATUS status = STATUS_SUCCESS;
	status = init_device(L"\\Driver\\kbdhid", L"\\Driver\\kbdclass");
	if(!NT_SUCCESS(status))
	{
		status = init_device(L"\\Driver\\i8042prt", L"\\Driver\\kbdclass");
	}
	return status;
}

void Keybd::keybd_event_(ULONG keyCode, USHORT flags)
{
	DbgPrintEx(77, 0, "lpfnClassServiceCallback_ = %p\n", lpfnClassServiceCallback_);
	if (!lpfnClassServiceCallback_)
		return;

	ULONG input_data = NULL;
	KIRQL CurrentIrql = KeGetCurrentIrql();
	__writecr8(2);
	KEYBOARD_INPUT_DATA kid = { 0 };

	kid.MakeCode = keyCode;
	kid.Flags = flags;
	((fnKeyboardClassServiceCallback)lpfnClassServiceCallback_)(dev_klass_, &kid, (PKEYBOARD_INPUT_DATA)&kid + 1, &input_data);
	__writecr8(CurrentIrql);
}
#pragma once
#include <ntifs.h>
#include "idevice.h"
class Keybd : public IDevice
{
private:
	typedef struct _KEYBOARD_INPUT_DATA {
		USHORT UnitId;
		USHORT MakeCode;
		USHORT Flags;
		USHORT Reserved;
		ULONG  ExtraInformation;
	} KEYBOARD_INPUT_DATA, * PKEYBOARD_INPUT_DATA;

	typedef VOID(*fnKeyboardClassServiceCallback)(PDEVICE_OBJECT DeviceObject, PKEYBOARD_INPUT_DATA InputDataStart, PKEYBOARD_INPUT_DATA InputDataEnd, PULONG InputDataConsumed);

public:
	static NTSTATUS init();

	static void keybd_event_(ULONG keyCode, USHORT flags);
};
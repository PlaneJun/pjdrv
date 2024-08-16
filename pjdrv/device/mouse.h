#pragma once
#include <ntifs.h>
#include "idevice.h"
class Mouse : public IDevice
{
private:
	typedef struct _MOUSE_INPUT_DATA
	{
		USHORT UnitId;
		USHORT Flags;
		USHORT ButtonFlags;
		USHORT ButtonData;
		ULONG  RawButtons;
		LONG   LastX;
		LONG   LastY;
		ULONG  ExtraInformation;
	} MOUSE_INPUT_DATA, * PMOUSE_INPUT_DATA;

	typedef VOID(*fnMouseClassServiceCallback)(PDEVICE_OBJECT DeviceObject, PMOUSE_INPUT_DATA InputDataStart, PMOUSE_INPUT_DATA InputDataEnd, PULONG InputDataConsumed);

public:
	static NTSTATUS init();

	static void mouse_event_(ULONG x, ULONG y, USHORT flags);
};
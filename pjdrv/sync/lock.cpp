#include "lock.h"

SpinLock::SpinLock()
{
	// ��ʼ��ͬ���¼����󣬲�����Ϊ���ź�
	KeInitializeEvent(&event_, SynchronizationEvent, TRUE);
}

VOID SpinLock::enter()
{
	KeWaitForSingleObject(&event_, Executive, KernelMode, FALSE, NULL);
}

VOID SpinLock::leave()
{
	KeSetEvent(&event_,IO_NO_INCREMENT,FALSE);
}



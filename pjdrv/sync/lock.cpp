#include "lock.h"

SpinLock::SpinLock()
{
	// 初始化同步事件对象，并设置为无信号
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



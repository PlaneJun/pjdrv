#pragma once
#include <ntifs.h>

class SpinLock
{
public:
	SpinLock();

	VOID enter();

	VOID leave();
private:
	KEVENT event_;
};
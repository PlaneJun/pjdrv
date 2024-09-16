#pragma once
#include <ntifs.h>

#ifdef _DEBUG
#define DBG_LOG(fmt, ...) DbgPrintEx(DPFLTR_DEFAULT_ID,DPFLTR_ERROR_LEVEL, "[LOG] [" __FUNCTION__ ":%u]: " fmt "\n", __LINE__, ## __VA_ARGS__)
#else
#define DBG_LOG(...)
#endif
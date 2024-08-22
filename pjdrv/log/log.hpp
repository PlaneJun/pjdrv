#pragma once
#include <ntifs.h>

#define DBG_LOG(Format, ...) KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[LOG] [" __FUNCTION__ ":%u]: " Format "\n", __LINE__, ## __VA_ARGS__))

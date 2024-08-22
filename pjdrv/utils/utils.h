#pragma once
#include <ntifs.h>

namespace utils
{
	PVOID get_system_function(const wchar_t* funcname);

	VOID disable_notify_routine();

	VOID enable_notify_routine();

	NTSTATUS remove_handle_from_table(HANDLE handle);

	void unlink(PLIST_ENTRY entryList, PLIST_ENTRY node);

	void link(PLIST_ENTRY entryList, PLIST_ENTRY node);

	void resume_all_unlink();
}

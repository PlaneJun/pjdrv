#pragma once
#include <ntifs.h>

namespace utils
{
	enum ELIST_TYPE
	{
		Thread = 0,
		Process
	};

	PVOID get_system_function(const wchar_t* funcname);

	VOID disable_notify_routine();

	VOID enable_notify_routine();

	NTSTATUS resume_handle_sync(HANDLE handle);

	NTSTATUS resume_all_handle_sync();

	NTSTATUS remove_handle_from_table_sync(HANDLE handle);

	NTSTATUS unlink_sync(PLIST_ENTRY entryList, PLIST_ENTRY node, ELIST_TYPE type);

	NTSTATUS link_sync(PLIST_ENTRY entryList, HANDLE id, ELIST_TYPE type);

	void resume_all_unlink_sync();
}

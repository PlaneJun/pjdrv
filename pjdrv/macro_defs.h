#pragma once

#define MACRO_GET_MEMBER(type,struct,member) NTSTATUS get_##member(const PVOID ptr,  ##type* out) \
	{ \
		NTSTATUS status = STATUS_UNSUCCESSFUL; \
		if (!MmIsAddressValid(ptr)) { return status;} \
		if (##struct.##member == NULL)  { return status;} \
		*out = memory::read_safe<##type>(reinterpret_cast<PUCHAR>(ptr) + ##struct.##member); \
		status = STATUS_SUCCESS; \
		return status; \
	}

#define MACRO_GET_PTR(type,struct,member) NTSTATUS get_##member(const PVOID ptr,  ##type* out) \
	{ \
		NTSTATUS status = STATUS_UNSUCCESSFUL; \
		if (!MmIsAddressValid(ptr)) { return status;} \
		if (##struct.##member == NULL)  { return status;} \
		*out = reinterpret_cast<##type>(reinterpret_cast<PUCHAR>(ptr) + ##struct.##member); \
		status = STATUS_SUCCESS; \
		return status; \
	}
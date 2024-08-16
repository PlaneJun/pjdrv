#pragma once
#include<stdint.h>

namespace symbols
{
	namespace offsets
	{
		inline uint64_t data_base_{ 0 };
		inline uint64_t vad_root_{0};
	}

	namespace global
	{
		inline uint64_t KeServiceDescriptorTable_{0};
	}
}
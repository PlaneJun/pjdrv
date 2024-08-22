// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

#include <cstdio>

void test()
{
   AllocConsole();
   FILE* stream;
   freopen_s(&stream, "CON", "w", stdout);

	while(true)
	{
      printf("11\n");
      Sleep(1000);
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	    {
       char buffer[1024]{};
       sprintf(buffer,"%p", test);
        MessageBoxA(NULL, buffer, NULL, NULL);
        break;
	    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


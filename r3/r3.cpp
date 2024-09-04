// r3.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "drv/drv.h"
#include "test_dll.h"

drv g_drv{};

#define DUMPMEMORY_BYTESPERROW 16

BOOL DumpMemory(LPBYTE lpBytes, int nCount)
{
    BOOL bReadException = ::IsBadReadPtr(lpBytes, nCount);
    CHAR szBuffer[DUMPMEMORY_BYTESPERROW * 3 + 1] = { 0 };
    int nIndex = 0;

    if (!bReadException)
    {
        for (nIndex = 0; nIndex < nCount; nIndex++)
        {
            _snprintf_s(szBuffer, DUMPMEMORY_BYTESPERROW * 3, "%s %02x", szBuffer, lpBytes[nIndex]);
        }

        printf("%s\n", szBuffer);
    }

    return bReadException;
}

void DumpMemoryInfo(LPBYTE lpBytes, DWORD dwMemorySize)
{
    int nLoopCount = 0, nLeftBytes = 0, nIndex = 0;
    BOOL bReadException = FALSE;

    nLoopCount = dwMemorySize / DUMPMEMORY_BYTESPERROW;
    nLeftBytes = dwMemorySize % DUMPMEMORY_BYTESPERROW;

    for (nIndex = 0; nIndex < nLoopCount; nIndex++)
    {
        bReadException = DumpMemory(lpBytes + nIndex * DUMPMEMORY_BYTESPERROW, DUMPMEMORY_BYTESPERROW);
        if (bReadException)
        {
            break;
        }
    }

    if (!bReadException && nLeftBytes > 0)
    {
        DumpMemory(lpBytes + nLoopCount * DUMPMEMORY_BYTESPERROW, nLeftBytes);
    }
}

void printf_hex(LPBYTE buffer,size_t len)
{
    uint32_t dwTimes = len / 16 + (len % 16 > 0 ? 1 : 0);

    for (DWORD dwTmpIdx = 0; dwTmpIdx < dwTimes; dwTmpIdx++)
    {
        if (dwTmpIdx != dwTimes - 1)
        {
            DumpMemoryInfo(buffer + dwTmpIdx * 16, 16);
        }
        else
        {
            DumpMemoryInfo(buffer + dwTmpIdx * 16, len - dwTmpIdx * 16);
        }
    }
}

void thread1()
{
    while(1)
    {
        printf("thread start\n");
        Sleep(3000);
    }
   
}

void thread2()
{
   printf("thread start");
   Sleep(3000);
}

int main2()
{
    drv::ERROR_CODE status_code = g_drv.init();
    if (status_code != drv::ERROR_CODE::CODE_OK)
    {
       DBG_LOG("error msg:%s", g_drv.get_error_msg(status_code));
        system("pause");
        return 0;
    }

    DBG_LOG("init ok");

    //uint32_t pid = 0;

    //DBG_LOG("input test pid:");
    //scanf("%d",&pid);

//#pragma region 获取模块地址
//    PVOID64 ntdllBase = g_drv.get_process_module(pid, L"ntdll.dll",nullptr, false);
//    DBG_LOG("ntdll base = %p", ntdllBase);
//#pragma endregion
//
//    printf("-----------------------------------------------------------\n");
//    getchar();
//
//#pragma region 申请内存
//    uint64_t lpNewMem = 0;
//    g_drv.alloc_mem(pid, NULL, 0x100, &lpNewMem, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//    DBG_LOG("alloc_mem = %p", lpNewMem);
//
//    g_drv.write<ULONG64>(pid,reinterpret_cast<PVOID64>(lpNewMem), 0x123456789);
//#pragma endregion
//
//    printf("-----------------------------------------------------------\n");
//    getchar();
//
//#pragma region 读写内存
//    BYTE rwBytes[5]{};
//	for(int i =0;i<3;i++)
//    {
//        g_drv.read_mem(pid, reinterpret_cast<PVOID64>(lpNewMem), sizeof(rwBytes), rwBytes, NULL,(communicate::ERWTYPE)i);
//        DBG_LOG("read_mem by type:%d",i);
//        printf_hex(rwBytes, sizeof(rwBytes));
//        rwBytes[0]++;
//        g_drv.write_mem(pid, reinterpret_cast<PVOID64>(lpNewMem), sizeof(rwBytes), rwBytes, NULL,(communicate::ERWTYPE)i);
//        RtlZeroMemory(rwBytes, sizeof(rwBytes));
//        getchar();
//    }
//    g_drv.read_mem(pid, reinterpret_cast<PVOID64>(lpNewMem), sizeof(rwBytes), rwBytes, NULL,communicate::ERWTYPE::Mdl);
//    DBG_LOG("read_mem");
//    printf_hex(rwBytes, sizeof(rwBytes));
//#pragma endregion
//
//    printf("-----------------------------------------------------------\n");
//    getchar();
//
//#pragma region 内存属性
//    g_drv.protect_mem(pid, reinterpret_cast<PVOID64>(lpNewMem), sizeof(lpNewMem), PAGE_EXECUTE_READWRITE);
//    MEMORY_BASIC_INFORMATION64 minfos{};
//    g_drv.query_mem(pid, reinterpret_cast<PVOID64>(lpNewMem), &minfos);
//    DBG_LOG("protect AllocationBase = %p", minfos.AllocationBase);
//    DBG_LOG("protect AllocationProtect = %d", minfos.AllocationProtect);
//    DBG_LOG("protect BaseAddress = %p", minfos.BaseAddress);
//    DBG_LOG("protect Protect = %d", minfos.Protect);
//    DBG_LOG("protect RegionSize = %x", minfos.RegionSize);
//#pragma endregion
//
//    printf("-----------------------------------------------------------\n");
//    getchar();
//
//#pragma region 创建线程
//    HANDLE tid{};
//    auto hThread = g_drv.create_thread(GetCurrentProcessId(), thread2, nullptr,true,&tid);
//    g_drv.close_handle(pid, hThread);
//    DBG_LOG("create thread:%p,tdi:%d",hThread, tid);
//#pragma endregion
//
//#pragma region 隐藏_显示线程
//    NTSTATUS status = g_drv.hide_thread(GetCurrentProcessId(),tid,true);
//    DBG_LOG("hide thread ok! threadid = %x,status = %x", tid, status);
//#pragma endregion
//
//    printf("-----------------------------------------------------------\n");
//    getchar();
//
//#pragma region 隐藏_显示线程
//    status = g_drv.hide_thread(GetCurrentProcessId(), tid, false); // false就为显示
//    if(NT_SUCCESS(status))
//        DBG_LOG("show thread ok!");
//    else
//        DBG_LOG("show thread failed,maybe its not be hide?");
//
//
//    printf("-----------------------------------------------------------\n");
//    getchar();
//
//
//    CloseHandle(CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)thread1, NULL, NULL, (LPDWORD)&tid));
//    DBG_LOG("thread id = %d\n", tid);
//
//    printf("-----------------------------------------------------------\n");
//    getchar();
//
//    status = g_drv.hide_thread(GetCurrentProcessId(), reinterpret_cast<HANDLE>(tid), true);
//    DBG_LOG("thread hide,%x\n", status);
//
//    printf("-----------------------------------------------------------\n");
//    getchar();
//
//    status = g_drv.hide_thread(GetCurrentProcessId(), reinterpret_cast<HANDLE>(tid), false);
//    DBG_LOG("thread show,%x\n", status);
//
//
//#pragma endregion
//
//    
//
//#pragma region device_键鼠
//    g_drv.mouse_event_ex(100, 100, MOUSE_MOVE_RELATIVE);
//#pragma endregion
//
//    printf("-----------------------------------------------------------\n");
//    getchar();

//#pragma region 注入DLL
//
//    // 一个弹窗dll
//	 bool inject = g_drv.inject(pid, hexData, sizeof(hexData));
//    DBG_LOG("inject = %d\n", inject);
//#pragma endregion


    printf("start\n");
    Sleep(1000);
    char test_input[] = {'A','B','C','D','E'};
    for(int i=0;i<sizeof(test_input);i++)
    {
	    g_drv.keybd_event_ex(test_input[i],RI_KEY_MAKE);
        Sleep(100);
        g_drv.keybd_event_ex(test_input[i], RI_KEY_BREAK);
    }

    g_drv.keybd_event_ex(VK_LWIN, RI_KEY_MAKE);
    Sleep(100);
    g_drv.keybd_event_ex(VK_LWIN, RI_KEY_BREAK);
    getchar();
    system("pause");
}

int main()
{
	main2();
}
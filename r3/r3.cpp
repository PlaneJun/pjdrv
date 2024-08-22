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

int main()
{
    drv::ERROR_CODE status_code = g_drv.init();
    if (status_code != drv::ERROR_CODE::CODE_OK)
    {
       DBG_LOG("error msg:%s,err:%d", g_drv.get_error_msg(status_code),g_drv.get_last_error());
        system("pause");
        return 0;
    }

    DBG_LOG("init ok");
    getchar();
    uint32_t pid = 0;

    DBG_LOG("input test pid:");
    scanf("%d",&pid);

#pragma region 获取模块地址
    PVOID64 ntdllBase = g_drv.get_process_module(pid, L"ntdll.dll", false);
    DBG_LOG("ntdll base = %p", ntdllBase);
#pragma endregion

    printf("-----------------------------------------------------------\n");
    getchar();

#pragma region 申请内存
    uint64_t lpNewMem = 0;
    g_drv.alloc_mem(pid, NULL, 0x100, &lpNewMem, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DBG_LOG("alloc_mem = %p", lpNewMem);

    g_drv.write<ULONG64>(pid,reinterpret_cast<PVOID64>(lpNewMem), 0x123456789);
#pragma endregion

    printf("-----------------------------------------------------------\n");
    getchar();

#pragma region 读写内存
    BYTE rwBytes[5]{};
	for(int i =0;i<3;i++)
    {
        g_drv.read_mem(pid, reinterpret_cast<PVOID64>(lpNewMem), sizeof(rwBytes), rwBytes, NULL,(communicate::ERWTYPE)i);
        DBG_LOG("read_mem by type:%d",i);
        printf_hex(rwBytes, sizeof(rwBytes));
        rwBytes[0]++;
        g_drv.write_mem(pid, reinterpret_cast<PVOID64>(lpNewMem), sizeof(rwBytes), rwBytes, NULL,(communicate::ERWTYPE)i);
        RtlZeroMemory(rwBytes, sizeof(rwBytes));
        getchar();
    }
    g_drv.read_mem(pid, reinterpret_cast<PVOID64>(lpNewMem), sizeof(rwBytes), rwBytes, NULL,communicate::ERWTYPE::Mdl);
    DBG_LOG("read_mem");
    printf_hex(rwBytes, sizeof(rwBytes));
#pragma endregion

    printf("-----------------------------------------------------------\n");
    getchar();

#pragma region 内存属性
    g_drv.protect_mem(pid, reinterpret_cast<PVOID64>(lpNewMem), sizeof(lpNewMem), PAGE_EXECUTE_READWRITE);
    MEMORY_BASIC_INFORMATION64 minfos{};
    g_drv.query_mem(pid, reinterpret_cast<PVOID64>(lpNewMem), &minfos);
    DBG_LOG("protect AllocationBase = %p", minfos.AllocationBase);
    DBG_LOG("protect AllocationProtect = %d", minfos.AllocationProtect);
    DBG_LOG("protect BaseAddress = %p", minfos.BaseAddress);
    DBG_LOG("protect Protect = %d", minfos.Protect);
    DBG_LOG("protect RegionSize = %x", minfos.RegionSize);
#pragma endregion

    printf("-----------------------------------------------------------\n");
    getchar();

#pragma region 创建线程
    ULONG tid{};
    auto hThread = g_drv.create_thread(GetCurrentProcessId(), thread2, NULL, true,false,&tid);
    g_drv.close_handle(pid, hThread);
    DBG_LOG("create thread:%p,tdi:%d",hThread, tid);
#pragma endregion

    printf("-----------------------------------------------------------\n");
    getchar();

#pragma region device_键鼠
    g_drv.mouse_event_ex(100, 100, MOUSE_MOVE_RELATIVE);
#pragma endregion

    printf("-----------------------------------------------------------\n");
    getchar();

#pragma region 注入DLL

    // 一个弹窗dll
	 bool inject = g_drv.inject(pid, hexData, sizeof(hexData));
    DBG_LOG("inject = %d\n", inject);
#pragma endregion

    system("pause");
}

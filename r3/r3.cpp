// r3.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "drv/drv.h"

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

void inject(uint32_t pid)
{
    FILE* f = NULL;
    fopen_s(&f,"Dll1.dll", "rb+");
    if (f)
    {

        fseek(f, 0, SEEK_END);
        auto size = ftell(f);
        fseek(f, 0, SEEK_SET);

        char* buffer = new char[size];
        fread(buffer, 1, size, f);
        fclose(f);

        g_drv.inject(pid, buffer, size);
        printf("inject ok!\n");
    }
    else
    {
        printf("open file failed!\n");
    }
}

void thread1()
{
    printf("thread start\n");
}

int main()
{
    drv::ERROR_CODE status_code = g_drv.init();
    if (status_code != drv::ERROR_CODE::CODE_OK)
    {
        printf("error msg:%s\n", g_drv.get_error_msg(status_code));
        system("pause");
        return 0;
    }

    printf("init ok\n");
    getchar();
    uint32_t pid = GetCurrentProcessId();

//#pragma region 获取模块地址
//    PVOID64 ntdllBase = g_drv.get_process_module(pid, L"ntdll.dll", false);
//    printf("ntdll base = %p\n", ntdllBase);
//#pragma endregion
//
//    printf("-----------------------------------------------------------\n");
//    getchar();
//
//#pragma region 读写内存
//    BYTE rwBytes[5]{};
//    for(int i =0;i<3;i++)
//    {
//        g_drv.read_mem(pid, ntdllBase, sizeof(rwBytes), rwBytes, (drv::ERWTYPE)i);
//        printf("read_mem by type:%d\n",i);
//        printf_hex(rwBytes, sizeof(rwBytes));
//        rwBytes[0]++;
//        g_drv.write_mem(pid, ntdllBase, sizeof(rwBytes), rwBytes, (drv::ERWTYPE)i);
//        RtlZeroMemory(rwBytes, sizeof(rwBytes));
//    }
//    g_drv.read_mem(pid, ntdllBase, sizeof(rwBytes), rwBytes, drv::ERWTYPE::MmCopy);
//    printf("read_mem\n");
//    printf_hex(rwBytes, sizeof(rwBytes));
//#pragma endregion
//
//    printf("-----------------------------------------------------------\n");
//    getchar();
//
//#pragma region 申请内存
//    uint64_t lpNewMem = 0;
//    g_drv.alloc_mem(pid, NULL, 0x100, &lpNewMem, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//    printf("alloc_mem = %p\n", lpNewMem);
//
//#pragma endregion
//
//    printf("-----------------------------------------------------------\n");
//    getchar();
//
//#pragma region 内存属性
//    g_drv.protect_mem(pid, reinterpret_cast<PVOID64>(lpNewMem), sizeof(lpNewMem), PAGE_EXECUTE_READWRITE);
//    MEMORY_BASIC_INFORMATION64 minfos{};
//    g_drv.query_mem(pid, reinterpret_cast<PVOID64>(lpNewMem), &minfos);
//    printf("protect AllocationBase = %p\n", minfos.AllocationBase);
//    printf("protect AllocationProtect = %d\n", minfos.AllocationProtect);
//    printf("protect BaseAddress = %p\n", minfos.BaseAddress);
//    printf("protect Protect = %d\n", minfos.Protect);
//    printf("protect RegionSize = %x\n", minfos.RegionSize);
//#pragma endregion
//
//    printf("-----------------------------------------------------------\n");
//    getchar();
//
//    g_drv.close_handle(pid, g_drv.create_thread(pid, thread1, NULL));

    //getchar();

    g_drv.mouse_event_ex(100, 100, MOUSE_MOVE_RELATIVE);


    getchar();
}

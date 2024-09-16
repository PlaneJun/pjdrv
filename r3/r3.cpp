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
        DBG_LOG("thread1 start\n");
        Sleep(3000);
    }
   
}

void thread2()
{
	DBG_LOG("thread2 start");
   Sleep(5000);
   DBG_LOG("thread2 end");
}

void wait_until_enter()
{
    DBG_LOG("<按下回车继续>");
    while (1)
    {
        if (GetAsyncKeyState(VK_RETURN) & 1)
        {
            break;
        }
    }
}

void query_test(DWORD pid, uintptr_t addr)
{
    g_drv.protect_mem(pid, reinterpret_cast<PVOID64>(addr), sizeof(addr), PAGE_EXECUTE_READWRITE);
    MEMORY_BASIC_INFORMATION64 minfos{};
    g_drv.query_mem(pid, reinterpret_cast<PVOID64>(addr), &minfos);
    DBG_LOG("protect AllocationBase = %p", minfos.AllocationBase);
    DBG_LOG("protect AllocationProtect = %d", minfos.AllocationProtect);
    DBG_LOG("protect BaseAddress = %p", minfos.BaseAddress);
    DBG_LOG("protect Protect = %d", minfos.Protect);
    DBG_LOG("protect RegionSize = %x", minfos.RegionSize);
    wait_until_enter();
}

uint64_t alloc_test(DWORD pid)
{
    uint64_t lpNewMem = 0;
    g_drv.alloc_mem(pid, NULL, 0x100, &lpNewMem, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DBG_LOG("alloc_mem = %p", lpNewMem);
    wait_until_enter();
    return lpNewMem;
}

void rw_test(DWORD pid,uintptr_t addr)
{
    BYTE rwBytes[5]{};
    for (int i = 0; i < 3; i++)
    {
        g_drv.read_mem(pid, reinterpret_cast<PVOID64>(addr), sizeof(rwBytes), rwBytes, NULL, (communicate::ERWTYPE)i);
        DBG_LOG("read_mem by type:%d", i);
        printf_hex(rwBytes, sizeof(rwBytes));
        rwBytes[0]++;
        g_drv.write_mem(pid, reinterpret_cast<PVOID64>(addr), sizeof(rwBytes), rwBytes, NULL, (communicate::ERWTYPE)i);
        RtlZeroMemory(rwBytes, sizeof(rwBytes));
        wait_until_enter();
    }
    g_drv.read_mem(pid, reinterpret_cast<PVOID64>(addr), sizeof(rwBytes), rwBytes, NULL, communicate::ERWTYPE::Mdl);
    DBG_LOG("read_mem");
    printf_hex(rwBytes, sizeof(rwBytes));

    wait_until_enter();
}

void device_test()
{
    DBG_LOG("3s后鼠标自动移动一次");
    Sleep(3000);
    g_drv.mouse_event_ex(100, 100, MOUSE_MOVE_RELATIVE);

    DBG_LOG("3s后键盘自动输入 ABCDE");
    Sleep(3000);
    char test_input[] = { 'A','B','C','D','E' };
    for (int i = 0; i < sizeof(test_input); i++)
    {
        g_drv.keybd_event_ex(test_input[i], RI_KEY_MAKE);
        Sleep(100);
        g_drv.keybd_event_ex(test_input[i], RI_KEY_BREAK);
    }

    DBG_LOG("3s后键盘自动按下 WIN键");
    Sleep(3000);
    g_drv.keybd_event_ex(VK_LWIN, RI_KEY_MAKE);
    Sleep(100);
    g_drv.keybd_event_ex(VK_LWIN, RI_KEY_BREAK);

    wait_until_enter();
}

void thread_test()
{
    DBG_LOG("3s后开始创建线程测试开始");
    Sleep(3000);
    HANDLE tid{};
    auto hThread = g_drv.create_thread(GetCurrentProcessId(), thread2, nullptr, true, &tid);
    g_drv.close_handle(GetCurrentProcessId(), hThread);
    DBG_LOG("create thread:%p,tdi:%d", hThread, tid);

    hThread = g_drv.create_thread(GetCurrentProcessId(), thread1, nullptr, true, &tid);
    g_drv.close_handle(GetCurrentProcessId(), hThread);
    DBG_LOG("create thread:%p,tdi:%d", hThread, tid);

    DBG_LOG("按下回车后开始隐藏");
    wait_until_enter();

    NTSTATUS status = 0;
	status = g_drv.hide_thread(GetCurrentProcessId(), reinterpret_cast<HANDLE>(tid), true);
    DBG_LOG("hide thread id:%d,%x\n", tid,status);

    DBG_LOG("按下回车后开始恢复");
    wait_until_enter();

    status = g_drv.hide_thread(GetCurrentProcessId(), reinterpret_cast<HANDLE>(tid), false);
    DBG_LOG("resume thread id:%d,%x\n", tid,status);

    wait_until_enter();
}

void process_test(DWORD pid)
{
    DBG_LOG("按下回车后开始隐藏");
    wait_until_enter();
    auto ret = g_drv.hide_process(pid, true);
    DBG_LOG("hide process :%d ret = %llx\n", pid,ret);

    DBG_LOG("按下回车后开始恢复");
    wait_until_enter();

    g_drv.hide_process(pid, false);
    DBG_LOG("resume process :%d ret = %llx\n", pid, ret);

    wait_until_enter();
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

    DBG_LOG("input test pid:");
    uint32_t pid = 0;
    std::cin >> pid;

	PVOID64 ntdllBase = g_drv.get_process_module(pid, L"ntdll.dll",nullptr, false);
	DBG_LOG("ntdll base = %p", ntdllBase);

	/*uint64_t lpNewMem = alloc_test(pid);
    if(lpNewMem)
    {
    	rw_test(pid, lpNewMem);
        query_test(pid, lpNewMem);
    }*/

    thread_test();

    process_test(pid);

    //device_test();


//#pragma region 注入DLL
//
//    // 一个弹窗dll
//	 bool inject = g_drv.inject(pid, hexData, sizeof(hexData));
//    DBG_LOG("inject = %d\n", inject);
//#pragma endregion

}

int main()
{
	main2();
}
#include <QCoreApplication>
#include "windows.h"
#include "psapi.h"

// DLL注入
void InjectDLL(HANDLE hProcess, PCWSTR dllPath) {
  // 先做进程提权，获取令牌
  HANDLE hToken;
  OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);

  // 查询进程的特权值
  LUID luid;
  LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

  // 调整访问令牌的特权值
  TOKEN_PRIVILEGES tkp;
  tkp.PrivilegeCount = 1;
  tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  tkp.Privileges[0].Luid = luid;
  AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);

  // 在目标进程中申请内存
  LPVOID lpAddr = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);

  // 将DLL路径写入申请好的内存中
  WriteProcessMemory(hProcess, lpAddr, dllPath, lstrlenW(dllPath) * 2 + 1, NULL);

  // 远程进程中开辟一个进程，执行LoadLibraryW
  CreateRemoteThread(hProcess, NULL, 0,(LPTHREAD_START_ROUTINE)
                     GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW"),
                     lpAddr, 0, NULL);
}

// 注入到当前系统所有的进程中
void InjectIntoExistingProcesses(PCWSTR dllPath)
{
  // 列举当前所有的进程
  DWORD aProcesses[1024], cbNeeded;
  EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded);
  DWORD cProcesses = cbNeeded / sizeof(DWORD);

  // 遍历进程
  for (size_t i = 0; i < cProcesses; i++)
  {
    // 打开进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, aProcesses[i]);

    // 获取进程名字
    TCHAR processNameW[256];
    GetModuleBaseNameW(hProcess, NULL, processNameW, 256);
    QString processName = QString::fromWCharArray(processNameW);
    qDebug() << processName;

    if (processName == "Notepad.exe") {
      InjectDLL(hProcess, dllPath);
    }

    // 关闭进程句柄
    CloseHandle(hProcess);
  }
}

int main(int argc, char *argv[])
{
  QCoreApplication a(argc, argv);
  InjectIntoExistingProcesses(LR"(D:\Qt\QtProjects\build-HookAPI-Desktop_Qt_6_2_0_MinGW_64_bit-Debug\debug\HookAPI.dll)");
}

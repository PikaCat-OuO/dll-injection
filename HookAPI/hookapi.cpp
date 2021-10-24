#include "hookapi.h"
#include "windows.h"
#include "psapi.h"
#include "tchar.h"
#include "dbghelp.h"
#include "stdio.h"

extern "C" HOOKAPI_EXPORT HANDLE WINAPI createFileW(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
    ) {
  MessageBoxW(NULL, L"调用了createFileW", L"调用了createFileW", MB_OK);

  TCHAR processName[256];
  GetModuleBaseNameW(GetCurrentProcess(), NULL, processName, 256);

  FILE* file = _wfopen(L"D:\\log.txt", L"a+");
  _wsetlocale(0, L"chs");
  fwprintf(file, L"%ls读取了%ls\n", processName, lpFileName);
  fflush(file);
  fclose(file);

  return CreateFileW(lpFileName,
                     dwDesiredAccess,
                     dwShareMode,
                     lpSecurityAttributes,
                     dwCreationDisposition,
                     dwFlagsAndAttributes,
                     hTemplateFile);
}

void ModifyIAT()
{
  HMODULE hMods[1024];

  HANDLE hProcess = GetCurrentProcess();

  TCHAR szLibFile[MAX_PATH];
  HMODULE hModule = GetModuleHandle(TEXT("HookAPI.dll"));
  GetModuleFileName(hModule,szLibFile,sizeof(szLibFile));

  DWORD cbNeeded = 0;
  ULONG ulSize = 0;
  if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
  {
    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
    {
      TCHAR szModName[MAX_PATH];
      // Get the full path to the module's file.
      if ( GetModuleFileNameEx( hProcess, hMods[i], szModName, sizeof(szModName)))
      {
        // We must skip the IAT of HookAPI.dll
        // from being modified as it contains
        // the wrapper functions for Windows AOIs being hooked.
        if(_tcscmp(szModName, szLibFile) == 0)
        {
          i++;
        }
      }
      // Get the address of the module's import section
      PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)
          ImageDirectoryEntryToData(hMods[i], TRUE,
                                    IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);
      if(NULL != pImportDesc)
      {
        while (pImportDesc->Name)
        {
          PSTR pszModName = (PSTR)((PBYTE) hMods[i] + pImportDesc->Name);
          if(lstrcmpA(pszModName, "KERNEL32.dll") != 0) {
            ++pImportDesc;
            continue;
          }

          // Get caller's IAT
          PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
              ( (PBYTE) hMods[i] + pImportDesc->FirstThunk );
          while (pThunk->u1.AddressOfData)
          {
            // Get the address of the function address
            PROC* pfnAddress = (PROC*) &pThunk->u1.AddressOfData;

            // replace function
            if (*pfnAddress == (PROC)CreateFileW) {
              MEMORY_BASIC_INFORMATION mbi;
              VirtualQuery( pfnAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION) );
              VirtualProtect( mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,
                             &mbi.Protect);

              // Replace the original address of API with the address of corresponding
              // wrapper function
              *pfnAddress = (PROC)createFileW;

              DWORD dwOldProtect = 0;
              VirtualProtect( mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &dwOldProtect );
            }
            pThunk++;
          }
          pImportDesc++;
        }
      }
    }
  }
}

extern "C" HOOKAPI_EXPORT BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
  // Perform actions based on the reason for calling.
  switch( fdwReason )
  {
  case DLL_PROCESS_ATTACH:
      // Initialize once for each new process.
      // Return FALSE to fail DLL load.
    ModifyIAT();
    MessageBoxA(NULL, "dll loaded", "dll loaded", MB_OK);
    break;

  case DLL_THREAD_ATTACH:
      // Do thread-specific initialization.
    break;

  case DLL_THREAD_DETACH:
      // Do thread-specific cleanup.
    break;

  case DLL_PROCESS_DETACH:
      // Perform any necessary cleanup.
    break;
  }
  return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

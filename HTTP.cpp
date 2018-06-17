#include "HTTP.h"

BOOL HttpSubmitRequest(HttpRequestData &httpRequestData)
{
   // return value is false (an error occurred)
   BOOL ret = FALSE;
   WSADATA wsa;
   SOCKET s;

   char request[1024] = { 0 };

   httpRequestData.outputBodySize = 0;
   // set http method
   Funcs::pLstrcpyA(request, (httpRequestData.post ? Strs::postSpace : Strs::getSpace));
   // set path version host and other header fields
   Funcs::pLstrcatA(request, httpRequestData.path);
   Funcs::pLstrcatA(request, Strs::httpReq1);
   Funcs::pLstrcatA(request, Strs::httpReq2);
   Funcs::pLstrcatA(request, httpRequestData.host);
   Funcs::pLstrcatA(request, Strs::httpReq3);

   // set content length
   if(httpRequestData.post && httpRequestData.inputBody)
   {
      Funcs::pLstrcatA(request, Strs::httpReq4);
      char sizeStr[10];
      Funcs::pWsprintfA(sizeStr, Strs::sprintfIntEscape, httpRequestData.inputBodySize);
      Funcs::pLstrcatA(request, sizeStr);
      Funcs::pLstrcatA(request, Strs::winNewLine);
   }
   Funcs::pLstrcatA(request, Strs::winNewLine);

   // init wsadata
   if(Funcs::pWSAStartup(MAKEWORD(2, 2), &wsa) != 0)
      goto exit;

   // create socket
   if((s = Funcs::pSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
      goto exit;

   // get host
   hostent *he = Funcs::pGethostbyname(httpRequestData.host);
   if(!he)
      goto exit;

   // init socket
   struct sockaddr_in addr;
   Funcs::pMemcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
   addr.sin_family = AF_INET;
   addr.sin_port = Funcs::pHtons(httpRequestData.port);

   // open connetion
   if(Funcs::pConnect(s, (struct sockaddr *) &addr, sizeof(addr)) == SOCKET_ERROR)
      goto exit;
   // send the header
   if(Funcs::pSend(s, request, Funcs::pLstrlenA(request), 0) <= 0)
      goto exit;

   // send the body if it presents
   if(httpRequestData.inputBody)
   {
      if(Funcs::pSend(s, (char *) httpRequestData.inputBody, httpRequestData.inputBodySize, 0) <= 0)
         goto exit;
   }
   
   char header[1024] = { 0 };
   int contentLength = -1;
   int lastPos = 0;
   BOOL firstLine = TRUE;
   BOOL transferChunked = FALSE;

   for(int i = 0;; ++i)
   {
      // header is too long
      if(i > sizeof(header) - 1)
         goto exit;
      // receive one byte from socket
      if(Funcs::pRecv(s, header + i, 1, 0) <= 0)
         goto exit;
      // if this is the end of header field
      if(i > 0 && header[i - 1] == '\r' && header[i] == '\n')
      {
         // terminate the string after the end of the header field
         header[i - 1] = 0;
         // exit if status code is not 200
         if(firstLine)
         {
            if(Funcs::pLstrcmpiA(header, Strs::httpReq5))
               goto exit;
            firstLine = FALSE;
         }
         else
         {
            char *field = header + lastPos + 2;
            // terminate the loop if the body received
            if(Funcs::pLstrlenA(field) == 0)
            {
               if(contentLength < 0 && !transferChunked)
                  goto exit;
               break;
            }
            char *name;
            char *value;
            // parse the header field
            if((value = (char *) Funcs::pStrStrA(field, Strs::httpReq6)))
            {
               name = field;
               name[value - field] = 0;
               value += 2;
               if(!Funcs::pLstrcmpiA(name, Strs::httpReq7))
               {
                  char *endPtr;
                  contentLength = Funcs::pStrtol(value, &endPtr, 10);
                  if(endPtr == value)
                     goto exit;
                  if(value < 0)
                     goto exit;
               }
               else if(!Funcs::pLstrcmpiA(name, Strs::httpReq8))
               {
                  if(!Funcs::pLstrcmpiA(value, Strs::httpReq9))
                     transferChunked = TRUE;
               }
               value += 2;
            }
         }
         lastPos = i - 1;
      }
   }
   // if body is chunked
   if(transferChunked)
   {
      const int reallocSize = 16394;

      char sizeStr[10] = { 0 };
      int allocatedSize = reallocSize;
      int read = 0;

      // allocate some space for received data
      httpRequestData.outputBody = (BYTE *) Alloc(reallocSize);
      for(int i = 0;;)
      {
         if(i > sizeof(sizeStr) - 1)
            goto exit;
         // keep receiving the body
         if(Funcs::pRecv(s, sizeStr + i, 1, 0) <= 0)
            goto exit;
         if(i > 0 && sizeStr[i - 1] == '\r' && sizeStr[i] == '\n')
         {
            sizeStr[i - 1] = 0;
            char *endPtr;
            // get the chunk size
            int size = Funcs::pStrtol(sizeStr, &endPtr, 16);
            if(endPtr == sizeStr)
               goto exit;
            if(size < 0)
               goto exit;
            // terminate the loop if the last chunk is received
            if(size == 0)
            {
               httpRequestData.outputBody[httpRequestData.outputBodySize] = 0;
               break;
            }
            // allocate enough space to store the next chunk (if necessary)
            httpRequestData.outputBodySize += size;
            if(allocatedSize < httpRequestData.outputBodySize + 1)
            {
               allocatedSize += httpRequestData.outputBodySize + reallocSize;
               httpRequestData.outputBody = (BYTE *) ReAlloc(httpRequestData.outputBody, allocatedSize);
            }
            int chunkRead = 0;
            // receive the next chunk
            do
            {
               int read2 = Funcs::pRecv(s, (char *) httpRequestData.outputBody + read + chunkRead, size - chunkRead, 0);
               if(read2 <= 0)
                  goto exit;
               chunkRead += read2;
            } while(chunkRead != size);
            // skip \r\n
            if(Funcs::pRecv(s, sizeStr, 2, 0) <= 0)
               goto exit;
            read += size;
            i = 0;
            continue;
         }
         ++i;
      }
   }
   // the body is not chunked
   else
   {
      if(contentLength > 0)
      {
         // allocate enough memory to store the body
         httpRequestData.outputBody = (BYTE *) Alloc(contentLength + 1);
         httpRequestData.outputBodySize = contentLength;
         httpRequestData.outputBody[httpRequestData.outputBodySize] = 0;
         int totalRead = 0;
         // read the body
         do
         {
            int read = Funcs::pRecv(s, (char *) httpRequestData.outputBody + totalRead, contentLength - totalRead, 0);
            if(read <= 0) goto exit;
            totalRead += read;
         }
         while(totalRead != contentLength);
      }
      else
      {
         httpRequestData.outputBody = (BYTE *) Alloc(1);
         httpRequestData.outputBody[0] = 0;
      }
   }
   // return value is true (the data received successfully)
   ret = TRUE;
exit:
   if(!ret)
   {
      // memory leak
      httpRequestData.outputBody = NULL;
      Funcs::pFree(httpRequestData.outputBody);
   }
   Funcs::pClosesocket(s);
   Funcs::pWSACleanup();
   return ret;
}

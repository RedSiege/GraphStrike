#pragma once

#include "../include.h"

SECTION( D ) HANDLE WINAPI GetProcessHeap_Hook();
SECTION( D ) VOID WINAPI Sleep_Hook( DWORD dwMilliseconds );
SECTION( D ) LPVOID WINAPI HeapAlloc_Hook( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes );
SECTION( D ) PVOID NTAPI RtlAllocateHeap_Hook( PVOID heapHandle, ULONG flags, SIZE_T size );
SECTION( D ) HINTERNET InternetConnectA_Hook( HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext );
SECTION( D ) HINTERNET HttpOpenRequestA_Hook( HINTERNET hInternet, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext );
SECTION( D ) BOOL HttpSendRequestA_Hook( HINTERNET hInternet, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength );
SECTION( D ) BOOL InternetReadFile_Hook( HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead );
SECTION( D ) LPVOID MakeWebRequest(HANDLE hInternet, PVOID site, PVOID uri, PVOID verb, PVOID headers, PVOID content, struct MemAddrs* pMemAddrs);
SECTION( D ) NTSTATUS NtWaitForSingleObject_Hook( HANDLE handle, BOOLEAN alertable, PLARGE_INTEGER timeout );

extern PVOID pMemAddrs2;
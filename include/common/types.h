#pragma once

#include <Windows.h>
#include <Fci.h>
#include <Fdi.h>
#include <Iphlpapi.h>
#include <TlHelp32.h>

#ifdef __cplusplus
#include <gdiplus.h>
using namespace Gdiplus;
#endif

#include <Shlwapi.h>
#include <Wtsapi32.h>
//#include <Winhttp.h>
#include <common/ntdll.h>
#undef Process32First
#undef Process32Next
#undef PROCESSENTRY32
#undef LPPROCESSENTRY32


typedef VOID(WINAPI *typeExitProcess)(UINT uExitCode); //KERNEL32
typedef BOOL(WINAPI *typeGetComputerNameA)(LPSTR lpBuffer, LPDWORD lpnSize); //KERNEL32
typedef BOOL(WINAPI *typeGetComputerNameW)(LPWSTR lpBuffer, LPDWORD lpnSize); //KERNEL32
typedef LANGID(WINAPI *typeGetUserDefaultUILanguage)(); //KERNEL32
typedef DWORD(WINAPI *typeGetCurrentThreadId)(); //KERNEL32
typedef LPSTR(WINAPI *typeGetCommandLineA)(); //KERNEL32
typedef HANDLE(WINAPI *typeGetCurrentProcess)(); //KERNEL32
typedef VOID(WINAPI *typeSleep)(DWORD dwMilliseconds); //KERNEL32
typedef HMODULE(WINAPI *typeLoadLibraryA)(LPCSTR lpFileName); //KERNEL32
typedef HMODULE(WINAPI *typeLoadLibraryW)(LPCWSTR lpFileName); //KERNEL32
typedef BOOL(WINAPI *typeFreeLibrary)(HMODULE hModule); //KERNEL32
typedef FARPROC(WINAPI *typeGetProcAddress)(HMODULE hModule, LPCSTR lpProcName); //KERNEL32
typedef BOOL(WINAPI *typeMoveFileA)(LPSTR lpExistingFileName, LPSTR lpNewFileName); //KERNEL32
typedef HANDLE(WINAPI *typeCreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPSTR lpName); //KERNEL32
typedef HANDLE(WINAPI *typeCreateFileMappingW)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName); //KERNEL32
typedef LPVOID(WINAPI *typeMapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap); //KERNEL32
typedef BOOL(WINAPI *typeUnmapViewOfFile)(LPCVOID lpBaseAddress); //KERNEL32
typedef BOOL(WINAPI *typeCloseHandle)(HANDLE hObject); //KERNEL32
typedef DWORD(WINAPI *typeGetLastError)(); //KERNEL32
typedef HANDLE(WINAPI *typeCreateEventA)(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPSTR lpName); //KERNEL32
typedef DWORD(WINAPI *typeWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds); //KERNEL32
typedef BOOL(WINAPI *typeSetEvent)(HANDLE hEvent); //KERNEL32
typedef BOOL(WINAPI *typeWritePrivateProfileStringA)(LPSTR lpAppName, LPSTR lpKeyName, LPSTR lpString, LPSTR lpFileName); //KERNEL32
typedef HMODULE(WINAPI *typeGetModuleHandleA)(LPSTR lpModuleName); //KERNEL32
typedef HMODULE(WINAPI *typeGetModuleHandleW)(LPCWSTR lpModuleName); //KERNEL32
typedef DWORD(WINAPI *typeGetFileAttributesA)(LPCSTR lpFileName); //KERNEL32

typedef DWORD(WINAPI *typeGetPrivateProfileStringA)(
	LPSTR lpAppName,
	LPSTR lpKeyName,
	LPSTR lpDefault,
	LPSTR lpReturnedString,
	DWORD nSize,
	LPSTR lpFileName
	); //KERNEL32

typedef DWORD(WINAPI *typeGetTempPathA)(DWORD nBufferLength, LPSTR lpBuffer); //KERNEL32
typedef UINT(WINAPI *typeGetTempFileNameA)(LPSTR lpPathName, LPCSTR lpPrefixString, UINT uUnique, LPSTR lpTempFileName); //KERNEL32

typedef BOOL(WINAPI *typeMoveFileExA)(LPCSTR lpExistingFileName, LPSTR lpNewFileName, DWORD dwFlags); //KERNEL32
typedef BOOL(WINAPI *typeSetCurrentDirectoryA)(LPSTR lpPathName); //KERNEL32
typedef BOOL(WINAPI *typeGetVersionExA)(LPOSVERSIONINFOA lpVersionInfo); //KERNEL32

typedef BOOL(WINAPI *typeWriteFile)(
	HANDLE hFile,
	LPCVOID lpBuffer,
	DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
	); //KERNEL32

typedef HANDLE(WINAPI *typeCreateFileA)(
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
	); //KERNEL32

typedef HANDLE(WINAPI *typeCreateFileW)(LPCWSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile); //KERNEL32

typedef void (WINAPI *typeOutputDebugStringA)(LPSTR lpOutputString); //KERNEL32
typedef LPVOID(WINAPI *typeVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect); //KERNEL32
typedef BOOL(WINAPI *typeDeviceIoControl)(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped); //KERNEL32
typedef BOOL(WINAPI *typeIsWow64Process)(HANDLE hProcess, PBOOL Wow64Process); //KERNEL32
typedef BOOL(WINAPI *typeVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType); //KERNEL32
typedef BOOL(WINAPI *typeVirtualFreeEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType); //KERNEL32
typedef void (WINAPI *typeGetSystemInfo)(LPSYSTEM_INFO lpSystemInfo); //KERNEL32
typedef HMODULE(WINAPI *typeLoadLibraryExA)(LPSTR lpFileName, HANDLE hFile, DWORD dwFlags); //KERNEL32
typedef DWORD(WINAPI *typeGetProcessId)(HANDLE Process); //KERNEL32
typedef DWORD(WINAPI *typeResumeThread)(HANDLE hThread); //KERNEL32
typedef BOOL(WINAPI *typeTerminateThread)(HANDLE hThread, DWORD dwExitCode); //KERNEL32
typedef BOOL(WINAPI *typeReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped); //KERNEL32
typedef DWORD(WINAPI *typeGetFileSize)(HANDLE hFile, LPDWORD lpFileSizeHigh); //KERNEL32
typedef BOOL(WINAPI *typeDeleteFileA)(LPCSTR lpFileName); //KERNEL32
typedef BOOL(WINAPI *typeCopyFileA)(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists); //KERNEL32
typedef BOOL(WINAPI *typeSetFileAttributesA)(LPCSTR lpFileName, DWORD dwFileAttributes); //KERNEL32

typedef HANDLE(WINAPI *typeFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData); //KERNEL32
typedef HANDLE(WINAPI *typeFindFirstFileW)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData); //KERNEL32
typedef BOOL(WINAPI *typeFindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData); //KERNEL32
typedef BOOL(WINAPI *typeFindNextFileW)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData); //KERNEL32


typedef BOOL(WINAPI *typeFindClose)(HANDLE hFindFile); //KERNEL32
typedef BOOL(WINAPI *typeVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect); //KERNEL32
typedef BOOL(WINAPI *typeReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead); //KERNEL32
typedef SIZE_T(WINAPI *typeVirtualQueryEx)(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength); //KERNEL32
typedef SIZE_T(WINAPI *typeVirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength); //KERNEL32
typedef HANDLE(WINAPI *typeOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId); //KERNEL32
typedef HANDLE(WINAPI *typeOpenEventA)(DWORD dwDesiredAccess, BOOL bInheritHandle, LPSTR lpName); //KERNEL32
typedef BOOL(WINAPI *typeWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten); //KERNEL32
typedef HANDLE(WINAPI *typeCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId); //KERNEL32
typedef HANDLE(WINAPI *typeHeapCreate)(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize); //KERNEL32
typedef BOOL(WINAPI *typeHeapDestroy)(HANDLE hHeap); //KERNEL32
typedef LPVOID(WINAPI *typeHeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes); //KERNEL32
typedef LPVOID(WINAPI *typeHeapReAlloc)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes); //KERNEL32
typedef BOOL(WINAPI *typeHeapFree)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem); //KERNEL32
typedef BOOL(WINAPI *typeDuplicateHandle)(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions); //KERNEL32
typedef HANDLE(WINAPI *typeCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId); //KERNEL32
typedef void (WINAPI *typeInitializeCriticalSection)(LPCRITICAL_SECTION lpCriticalSection); //KERNEL32
typedef void (WINAPI *typeEnterCriticalSection)(LPCRITICAL_SECTION lpCriticalSection); //KERNEL32
typedef void (WINAPI *typeLeaveCriticalSection)(LPCRITICAL_SECTION lpCriticalSection); //KERNEL32
typedef UINT(WINAPI *typeGetSystemDirectoryA)(LPSTR lpBuffer, UINT uSize); //KERNEL32
typedef DWORD(WINAPI *typeGetModuleFileNameA)(HMODULE hModule, LPSTR lpFilename, DWORD nSize); //KERNEL32
typedef DWORD(WINAPI *typeGetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename, DWORD nSize); //KERNEL32
typedef BOOL(WINAPI *typeFlushFileBuffers)(HANDLE hFile); //KERNEL32
typedef HANDLE(WINAPI *typeCreateNamedPipeA)(LPSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes); //KERNEL32
typedef BOOL(WINAPI *typeConnectNamedPipe)(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped); //KERNEL32
typedef BOOL(WINAPI *typeDisconnectNamedPipe)(HANDLE hNamedPipe); //KERNEL32
typedef BOOL(WINAPI *typeCreateProcessA)
(
	LPSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles, DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	); //KERNEL32

typedef BOOL(WINAPI *typeGetExitCodeProcess)(HANDLE hProcess, LPDWORD lpExitCode); //KERNEL32
typedef DWORD(WINAPI *typeGetCurrentProcessId)(); //KERNEL32
typedef HANDLE(WINAPI *typeCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID); //KERNEL32
typedef BOOL(WINAPI *typeProcess32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe); //KERNEL32
typedef BOOL(WINAPI *typeProcess32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe); //KERNEL32
typedef BOOL(WINAPI *typeTerminateProcess)(HANDLE hProcess, UINT uExitCode); //KERNEL32
typedef BOOL(WINAPI *typeThread32First)(HANDLE hSnapshot, LPTHREADENTRY32 lpte); //KERNEL32
typedef HANDLE(WINAPI *typeOpenThread)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId); //KERNEL32
typedef DWORD(WINAPI *typeSuspendThread)(HANDLE hThread); //KERNEL32
typedef BOOL(WINAPI *typeGetThreadContext)(HANDLE hThread, LPCONTEXT lpContext); //KERNEL32
typedef LPVOID(WINAPI *typeVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect); //KERNEL32
typedef BOOL(WINAPI *typeThread32Next)(HANDLE hSnapshot, LPTHREADENTRY32 lpte); //KERNEL32
typedef DWORD(WINAPI *typeGetTickCount)(); //KERNEL32
typedef int (WINAPI *typeMultiByteToWideChar)(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar); //KERNEL32
typedef int (WINAPI *typeWideCharToMultiByte)(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPSTR lpDefaultChar, LPBOOL lpUsedDefaultChar); //KERNEL32
typedef void (WINAPI *typeGetLocalTime)(LPSYSTEMTIME lpSystemTime); //KERNEL32
typedef HLOCAL(WINAPI *typeLocalFree)(HLOCAL hMem); //KERNEL32
typedef HLOCAL(WINAPI *typeLocalAlloc)(UINT uFlags, SIZE_T uBytes); //KERNEL32
typedef HANDLE(WINAPI *typeCreateMutexA)(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPSTR lpName); //KERNEL32
typedef BOOL(WINAPI *typeReleaseMutex)(HANDLE hMutex); //KERNEL32
typedef BOOL(WINAPI *typeFlushViewOfFile)(LPCVOID lpBaseAddress, SIZE_T dwNumberOfBytesToFlush); //KERNEL32
typedef UINT(WINAPI* typeWinExec)(LPSTR lpCmdLine, UINT uCmdShow); //KERNEL32
typedef LONG(WINAPI *typeInterlockedExchange)(LONG volatile* Target, LONG Value); //KERNEL32
typedef SIZE_T(WINAPI *typeVirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength); //KERNEL32
typedef BOOL(WINAPI *typeGetComputerNameExA)(COMPUTER_NAME_FORMAT NameType, LPSTR lpBuffer, LPDWORD nSize); //KERNEL32
typedef DWORD(WINAPI *typeSetFilePointer)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod); //KERNEL32
typedef BOOL(WINAPI *typeGetExitCodeThread)(HANDLE hThread, LPDWORD lpExitCode); //KERNEL32
typedef BOOL(WINAPI *typeCreatePipe)(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize); //KERNEL32
typedef BOOL(WINAPI *typePeekNamedPipe)(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage); //KERNEL32
typedef BOOL(WINAPI *typeVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect); //KERNEL32
typedef DWORD(WINAPI *typeGetLogicalDriveStringsA)(DWORD nBufferLength, LPSTR lpBuffer); //KERNEL32
typedef BOOL(WINAPI *typeGetFileTime)(HANDLE hFile, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime, LPFILETIME lpLastWriteTime); //KERNEL32
typedef BOOL(WINAPI *typeFileTimeToSystemTime)(const FILETIME* lpFileTime, LPSYSTEMTIME lpSystemTime); //KERNEL32
typedef DWORD(WINAPI *typeGetLogicalDrives)(void); //KERNEL32
typedef UINT(WINAPI *typeGetDriveTypeA)(LPSTR lpRootPathName); //KERNEL32
typedef BOOL(WINAPI *typeGetDiskFreeSpaceExA)(LPSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailable, PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes); //KERNEL32
typedef void (WINAPI *typeGetSystemTime)(LPSYSTEMTIME lpSystemTime); //KERNEL32
typedef BOOL(WINAPI *typeReadDirectoryChangesW)
(
	HANDLE hDirectory,
	LPVOID lpBuffer,
	DWORD nBufferLength,
	BOOL bWatchSubtree,
	DWORD dwNotifyFilter,
	LPDWORD lpBytesReturned,
	LPOVERLAPPED lpOverlapped,
	LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine

	); //KERNEL32


typedef BOOL(WINAPI *typeGetKeyboardState)(PBYTE lpKeyState); //USER32
typedef HKL(WINAPI *typeGetKeyboardLayout)(DWORD idThread); //USER32
typedef int (WINAPI *typeToAsciiEx)(UINT uVirtKey, UINT uScanCode, const BYTE* lpKeyState, LPWORD lpChar, UINT uFlags, HKL dwhkl); //USER32
typedef BOOL(WINAPI *typeEnumChildWindows)(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam); //USER32
typedef BOOL(WINAPI *typeEnumWindows)(WNDENUMPROC lpEnumFunc, LPARAM lParam); //USER32
typedef BOOL(WINAPI *typeIsWindowEnabled)(HWND hWnd); //USER32
typedef HWND(WINAPI *typeFindWindowA)(LPSTR lpClassName, LPSTR lpWindowName); //USER32
typedef BOOL(WINAPI *typeExitWindowsEx)(UINT uFlags, DWORD dwReason); //USER32
typedef BOOL(WINAPI *typeDestroyWindow)(HWND hWnd); //USER32
typedef LRESULT(WINAPI *typeDispatchMessageA)(const MSG* lpmsg); //USER32
typedef LRESULT(WINAPI *typeDispatchMessageW)(const MSG* lpmsg); //USER32
typedef BOOL(WINAPI *typeGetMessageA)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax); //USER32
typedef BOOL(WINAPI *typeGetMessageW)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax); //USER32
typedef BOOL(WINAPI *typePeekMessageA)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg); //USER32
typedef BOOL(WINAPI *typePeekMessageW)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg); //USER32
typedef LONG(WINAPI *typeGetWindowLongA)(HWND hWnd, int nIndex); //USER32
typedef LONG(WINAPI *typeSetWindowLongA)(HWND hWnd, int nIndex, LONG dwNewLong); //USER32
typedef BOOL(WINAPI *typeSendNotifyMessageA)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam); //USER32
typedef DWORD(WINAPI *typeGetWindowThreadProcessId)(HWND hWnd, LPDWORD lpdwProcessId); //USER32
typedef HWND(WINAPI *typeFindWindowA)(LPSTR lpClassName, LPSTR lpWindowName); //USER32
typedef BOOL(WINAPI *typeAttachThreadInput)(DWORD idAttach, DWORD idAttachTo, BOOL fAttach); //USER32
typedef BOOL(WINAPI *typeBlockInput)(BOOL fBlockIt); //USER32
typedef BOOL(WINAPI *typePostMessageA)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam); //USER32
typedef DWORD(WINAPI *typeWaitForInputIdle)(HANDLE hProcess, DWORD dwMilliseconds); //USER32
typedef int (WINAPI *typewvsprintfA)(LPSTR lpOutput, LPCSTR lpFmt, va_list arglist); //USER32
typedef int (WINAPI *typeGetWindowTextA)(HWND hWnd, LPSTR lpString, int nMaxCount); //USER32
typedef int (WINAPI *typeGetClassNameA)(HWND hWnd, LPSTR lpClassName, int nMaxCount); //USER32
typedef HWND(WINAPI *typeGetParent)(HWND hWnd); //USER32
typedef HWND(WINAPI *typeGetDesktopWindow)(); //USER32
typedef HDC(WINAPI *typeGetWindowDC)(HWND hWnd); //USER32
typedef BOOL(WINAPI *typeGetWindowRect)(HWND hWnd, LPRECT lpRect); //USER32
typedef int (WINAPI *typeReleaseDC)(HWND hWnd, HDC hDC); //USER32
typedef int (WINAPI *typewvsprintfW)(LPWSTR lpOutput, LPCWSTR lpFmt, va_list arglist); //USER32
typedef HDC(WINAPI *typeGetDC)(HWND hWnd); //USER32
typedef HWND(WINAPI *typeGetForegroundWindow)(); //USER32
typedef BOOL(WINAPI *typeSetThreadDesktop)(HDESK hDesktop); //USER32
typedef HDESK(WINAPI *typeCreateDesktopA)(LPSTR lpszDesktop, LPSTR lpszDevice, DEVMODE* pDevmode, DWORD dwFlags, ACCESS_MASK dwDesiredAccess, LPSECURITY_ATTRIBUTES lpsa); //USER32
typedef LRESULT(WINAPI *typeDefWindowProcA)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam); //USER32
typedef HMENU(WINAPI *typeCreatePopupMenu)(void); //USER32
typedef BOOL(WINAPI *typeInsertMenuItemA)(HMENU hMenu, UINT uItem, BOOL fByPosition, LPCMENUITEMINFOA lpmii); //USER32
typedef BOOL(WINAPI *typeDestroyMenu)(HMENU hMenu); //USER32
typedef LRESULT(WINAPI *typeCallWindowProcA)(WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam); //USER32
typedef BOOL(WINAPI *typeEndMenu)(void); //USER32
typedef BOOL(WINAPI *typeUnhookWindowsHook)(int nCode, HOOKPROC pfnFilterProc); //USER32
typedef LONG(WINAPI *typeSetWindowLongA)(HWND hWnd, int nIndex, LONG dwNewLong); //USER32
typedef LRESULT(WINAPI *typeCallNextHookEx)(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam); //USER32
typedef ATOM(WINAPI *typeRegisterClassA)(const WNDCLASSA* lpWndClass); //USER32
typedef HWND(WINAPI *typeCreateWindowExA)(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam); //USER32
typedef HHOOK(WINAPI *typeSetWindowsHookExA)(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId); //USER32
typedef BOOL(WINAPI *typeTrackPopupMenu)(HMENU hMenu, UINT uFlags, int x, int y, int nReserved, HWND hWnd, const RECT* prcRect); //USER32
typedef int (WINAPI *typeGetSystemMetrics)(int nIndex); //USER32
typedef HWINSTA(WINAPI *typeOpenWindowStationA)(LPSTR lpszWinSta, BOOL fInherit, ACCESS_MASK dwDesiredAccess); //USER32
typedef HWINSTA(WINAPI *typeGetProcessWindowStation)(void); //USER32
typedef BOOL(WINAPI *typeSetProcessWindowStation)(HWINSTA hWinSta); //USER32
typedef HDESK(WINAPI *typeOpenInputDesktop)(DWORD dwFlags, BOOL fInherit, ACCESS_MASK dwDesiredAccess); //USER32
typedef HDESK(WINAPI *typeGetThreadDesktop)(DWORD dwThreadId);//USER32
typedef BOOL(WINAPI *typeCloseWindowStation)(HWINSTA hWinSta); //USER32
typedef BOOL(WINAPI *typeCloseDesktop)(HDESK hDesktop); //USER32


														///////////////////////////////
														// NTDLL
														//////////////////////////////

typedef NTSTATUS(WINAPI *typeRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation); //NTDLL

typedef NTSTATUS(WINAPI *typeRtlAdjustPrivilege)(ULONG Privilege, BOOLEAN NewValue, BOOLEAN ForThread, PBOOLEAN OldValue); //NTDLL
typedef VOID(WINAPI *typeRtlGetNtVersionNumbers)(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild); //NTDLL
typedef BOOL(WINAPI *typeNtQuerySystemInformation)(SYSTEMINFOCLASS SystemInformationClass, PVOID pSystemInformation, ULONG uSystemInformationLength, PULONG puReturnLength); //NTDLL
typedef NTSTATUS(WINAPI *typeNtQueryIntervalProfile)(KPROFILE_SOURCE ProfileSource, PULONG Interval); //NTDLL
typedef NTSTATUS(WINAPI *typeZwResumeThread)(DWORD ThreadHandle, DWORD PreviousSuspendCount); //NTDLL
typedef VOID(WINAPI *typeKiUserApcDispatcher)(PVOID Unused1, PVOID Unused2, PVOID Unused3, PVOID ContextStart, PVOID ContextBody); //NTDLL
typedef PVOID(WINAPI *typeRtlImageNtHeader)(PVOID BaseAddress); //NTDLL
typedef VOID(WINAPI *typeRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString); //NTDLL
typedef NTSTATUS(WINAPI *typeNtOpenSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes); //NTDLL
typedef NTSTATUS(WINAPI *typeNtMapViewOfSection)
(
	IN HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG ZeroBits,
	ULONG CommitSize,
	PLARGE_INTEGER SectionOffset,
	PULONG_PTR ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType, ULONG Protect
	); //NTDLL

typedef NTSTATUS(WINAPI *typeNtClose)(HANDLE hObject); //NTDLL
typedef NTSTATUS(WINAPI* typeRtlCreateUserThread)
(
	HANDLE ProcessHandle,
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	BOOLEAN CreateSuspended,
	ULONG StackZeroBits,
	PULONG StackReserved,
	PULONG StackCommit,
	PVOID StartAddress,
	PVOID StartParameter,
	PHANDLE ThreadHandle,
	PCLIENT_ID ClientID
	); //NTDLL
typedef NTSTATUS(WINAPI *typeNtUnmapViewOfSection)(HANDLE hProcess, PVOID pBaseAddress); //NTDLL
typedef NTSTATUS(WINAPI *typeZwAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect); //NTDLL
typedef NTSTATUS(WINAPI *typeZwWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten); //NTDLL
typedef NTSTATUS(WINAPI *typeZwMapViewOfSection)
(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG ZeroBits,
	ULONG CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Protect
	); //NTDLL
typedef NTSTATUS(WINAPI *typeZwOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId); //NTDLL
typedef NTSTATUS(WINAPI *typeZwClose)(HANDLE Handle); //NTDLL
typedef NTSTATUS(WINAPI *typeZwQueueApcThread)(HANDLE hThread, PKNORMAL_ROUTINE ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2); //NTDLL
typedef NTSTATUS(WINAPI *typeZwSetContextThread)(HANDLE ThreadHandle, PCONTEXT Context); //NTDLL
typedef NTSTATUS(WINAPI *typeZwQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG Length, PULONG ReturnLength); //NTDLL
typedef NTSTATUS(WINAPI *typeZwQueryInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass); //NTDLL
typedef DWORD(WINAPI *typeZwQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength); //NTDLL
typedef NTSTATUS(WINAPI *typeNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PULONG AllocationSize, ULONG AllocationType, ULONG Protect); //NTDLL
typedef ULONG(WINAPI *typeNtFreeVirtualMemory)(HANDLE, PVOID, PULONG, ULONG); //NTDLL
typedef NTSTATUS(WINAPI *typeNtQueryInformationProcess)(HANDLE hProcess, PROCESSINFOCLASS ProcessInformationClass, PVOID pProcessInformation, ULONG uProcessInformationLength, PULONG puReturnLength); //NTDLL
typedef PPEB(WINAPI *typeRtlGetCurrentPeb)(); //NTDLL
typedef NTSTATUS(WINAPI *typeNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength); //NTDLL
typedef int (WINAPIV *type_wcsicmp)(const wchar_t* string1, const wchar_t* string2); //NTDLL
typedef DWORD(NTAPI * typeNtFlushInstructionCache)(HANDLE, PVOID, ULONG); //NTDLL



typedef  char* (WINAPI *typestrpbrk)(const char *str, const char *strCharSet); //NTDLL
typedef  wchar_t * (WINAPI *typewcspbrk)(const wchar_t *str, const wchar_t *strCharSet); //NTDLL
																						 /////////////////
																						 //SHLWAPI
																						 /////////////////

typedef BOOL(WINAPI *typePathMatchSpecA)(LPCSTR pszFile, LPCSTR pszSpec); //SHLWAPI
typedef BOOL(WINAPI *typePathMatchSpecW)(LPCWSTR pszFile, LPCWSTR pszSpec); //SHLWAPI


typedef LPSTR(WINAPI *typePathFindFileNameA)(LPCSTR pPath); //SHLWAPI
typedef LPSTR(WINAPI *typePathFindExtensionA)(LPCSTR pszPath); //SHLWAPI
typedef BOOL(WINAPI *typeStrToIntExA)(PCSTR pszString, STIF_FLAGS dwFlags, int* piRet); //SHLWAPI


typedef int (WINAPI *typewvnsprintfA)(LPSTR pszDest, int cchDest, LPCSTR pszFmt, va_list arglist); //SHLWAPI
typedef int (WINAPI *typewvnsprintfW)(LPWSTR pszDest, int cchDest, LPCWSTR pszFmt, va_list arglist); //SHLWAPI


																									 /////////////////
																									 //IPHLPAPI
																									 /////////////////
typedef DWORD(WINAPI *typeGetAdaptersInfo)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen);//IPHLPAPI


																							 /////////////////
																							 //URLMON
																							 /////////////////

typedef HRESULT(WINAPI *typeObtainUserAgentString)(DWORD dwOption, LPSTR pcszUAOut, DWORD* cbSize); //URLMON

																									///////////////
																									//WS2_32
																									///////////////

typedef int (WINAPI *typeWSAStartup)(WORD wVersionRequested, LPWSADATA lpWSAData); //WS2_32
typedef int (WINAPI *typeWSACleanup)(); //WS2_32
typedef struct hostent* (WINAPI *typegethostbyname)(const char* name); //WS2_32
typedef char* (WINAPI *typeinet_ntoa)(struct in_addr in); //WS2_32
typedef SOCKET(WINAPI *typesocket)(int af, int type, int protocol); //WS2_32
typedef u_short(WINAPI *typehtons)(u_short hostshort); //WS2_32
typedef u_short(WINAPI* typentohs)(u_short netshort); //WS2_32
typedef unsigned long (WINAPI *typeinet_addr)(const char* cp); //WS2_32
typedef int (WINAPI *typeconnect)(SOCKET s, const struct sockaddr* name, int namelen); //WS2_32
typedef int (WINAPI *typeclosesocket)(SOCKET s); //WS2_32
typedef int (WINAPI *typesend)(SOCKET s, const char* buf, int len, int flags); //WS2_32
typedef int (WINAPI *typeselect)(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout); //WS2_32
typedef int (WINAPI *typerecv)(SOCKET s, char* buf, int len, int flags); //WS2_32
typedef int (WINAPI *typebind)(SOCKET s, const struct sockaddr* name, int namelen); //WS2_32
typedef int (WINAPI *typelisten)(SOCKET s, int backlog); //WS2_32
typedef SOCKET(WINAPI *typeaccept)(SOCKET s, struct sockaddr* addr, int* addrlen); //WS2_32
typedef int (WINAPI* typegethostname)(char* name, int namelen); //WS2_32
typedef int (WINAPI* typeioctlsocket)(SOCKET s, long cmd, u_long* argp); //WS2_32
typedef int (WINAPI *typegetsockname)(SOCKET s, struct sockaddr* name, int* namelen); //WS2_32

																					  ///////////////
																					  //CRYPT32
																					  ///////////////
typedef BOOL(WINAPI *typeCryptBinaryToStringA)(const BYTE* pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD* pcchString); //CRYPT32
typedef BOOL(WINAPI *typeCryptStringToBinaryA)(LPSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags); //CRYPT32


																																									///////////////
																																									//SHELL32
																																									///////////////
typedef HRESULT(WINAPI *typeSHGetFolderPathA)(HWND hwndOwner, int nFolder, HANDLE hToken, DWORD dwFlags, LPSTR pszPath);//SHELL32
typedef HRESULT(WINAPI *typeSHGetFolderPathW)(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPWSTR pszPath); //SHELL32

typedef int (WINAPI *typeSHCreateDirectoryExA)(HWND hwnd, LPCSTR pszPath, const SECURITY_ATTRIBUTES* psa); //SHELL32
typedef int (WINAPI *typeSHFileOperationA)(LPSHFILEOPSTRUCTA lpFileOp); //SHELL32
typedef HRESULT(WINAPI* typeSHCreateItemFromParsingName)(PCWSTR pszPath, IBindCtx* pbc, REFIID riid, void** ppv); //SHELL32
typedef BOOL(WINAPI* typeShellExecuteExA)(SHELLEXECUTEINFOA* pExecInfo); //SHELL32


																		 ///////////////
																		 //ADVAPI32
																		 ///////////////
typedef SC_HANDLE(WINAPI *typeOpenSCManagerA)(LPSTR lpMachineName, LPSTR lpDatabaseName, DWORD dwDesiredAccess); //ADVAPI32
typedef SC_HANDLE(WINAPI *typeOpenSCManagerW)(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess); //ADVAPI32
typedef SC_HANDLE(WINAPI *typeOpenServiceA)(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess); //ADVAPI32
typedef SC_HANDLE(WINAPI *typeOpenServiceW)(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess); //ADVAPI32
typedef BOOL(WINAPI *typeChangeServiceConfig2A)(SC_HANDLE hService, DWORD dwInfoLevel, LPVOID lpInfo); //ADVAPI32
typedef BOOL(WINAPI *typeCloseServiceHandle)(SC_HANDLE hSCObject); //ADVAPI32
typedef BOOL(WINAPI *typeEnumServicesStatusExA)
(
	SC_HANDLE hSCManager,
	SC_ENUM_TYPE InfoLevel,
	DWORD dwServiceType,
	DWORD dwServiceState,
	LPBYTE lpServices,
	DWORD cbBufSize,
	LPDWORD pcbBytesNeeded,
	LPDWORD lpServicesReturned,
	LPDWORD lpResumeHandle,
	LPSTR pszGroupName
	); //ADVAPI32

typedef BOOL(WINAPI *typeSetServiceStatus)(SERVICE_STATUS_HANDLE hServiceStatus, LPSERVICE_STATUS lpServiceStatus); //ADVAPI32
typedef SERVICE_STATUS_HANDLE(WINAPI *typeRegisterServiceCtrlHandlerA)(LPSTR lpServiceName, LPHANDLER_FUNCTION lpHandlerProc); //ADVAPI32
typedef BOOL(WINAPI *typeControlService)(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus); //ADVAPI32
typedef BOOL(WINAPI *typeStartServiceCtrlDispatcherA)(const SERVICE_TABLE_ENTRY* lpServiceTable); //ADVAPI32
typedef LONG(WINAPI *typeRegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult); //ADVAPI32
typedef LONG(WINAPI *typeRegSetValueExA)(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData); //ADVAPI32
typedef LONG(WINAPI *typeRegEnumKeyExA)(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcName, LPDWORD lpReserved, LPSTR lpClass, LPDWORD lpcClass, PFILETIME lpftLastWriteTime); //ADVAPI32
typedef LONG(WINAPI *typeRegCloseKey)(HKEY hKey); //ADVAPI32
typedef BOOL(WINAPI *typeCryptAcquireContextA)(HCRYPTPROV* phProv, LPSTR pszContainer, LPSTR pszProvider, DWORD dwProvType, DWORD dwFlags); //ADVAPI32
typedef BOOL(WINAPI *typeCryptImportKey)(HCRYPTPROV hProv, BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey); //ADVAPI32
typedef BOOL(WINAPI *typeCryptSetKeyParam)(HCRYPTKEY hKey, DWORD dwParam, const BYTE* pbData, DWORD dwFlags); //ADVAPI32
typedef BOOL(WINAPI *typeCryptDestroyKey)(HCRYPTKEY hKey); //ADVAPI32
typedef BOOL(WINAPI *typeCryptReleaseContext)(HCRYPTPROV hProv, DWORD dwFlags); //ADVAPI32
typedef BOOL(WINAPI *typeCryptEncrypt)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen); //ADVAPI32
typedef BOOL(WINAPI *typeCryptDecrypt)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen); //ADVAPI32
typedef BOOL(WINAPI *typeInitializeSecurityDescriptor)(PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision); //ADVAPI32
typedef BOOL(WINAPI *typeSetSecurityDescriptorDacl)(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bDaclPresent, PACL pDacl, BOOL bDaclDefaulted); //ADVAPI32
typedef BOOL(WINAPI *typeOpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle); //ADVAPI32
typedef BOOL(WINAPI *typeDuplicateTokenEx)
(
	HANDLE hExistingToken, DWORD dwDesiredAccess,
	LPSECURITY_ATTRIBUTES lpTokenAttributes,
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
	TOKEN_TYPE TokenType, PHANDLE phNewToken
	); //ADVAPI32
typedef BOOL(WINAPI *typeCreateProcessAsUserA)
(
	HANDLE hToken,
	LPSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	); //ADVAPI32
typedef LONG(WINAPI *typeRegCreateKeyExA)
(
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD Reserved,
	LPSTR lpClass,
	DWORD dwOptions,
	REGSAM samDesired,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY phkResult, LPDWORD lpdwDisposition);
//ADVAPI32

typedef LONG(WINAPI *typeRegQueryValueExA)(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData); //ADVAPI32
typedef LONG(WINAPI *typeRegDeleteValueA)(HKEY hKey, LPCSTR lpValueName); //ADVAPI32
typedef BOOL(WINAPI *typeQueryServiceStatusEx)(SC_HANDLE hService, SC_STATUS_TYPE InfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded); //ADVAPI32
typedef BOOL(WINAPI *typeStartServiceA)(SC_HANDLE hService, DWORD dwNumServiceArgs, LPSTR* lpServiceArgVectors); //ADVAPI32
typedef BOOL(WINAPI *typeChangeServiceConfigA)
(
	SC_HANDLE hService,
	DWORD dwServiceType,
	DWORD dwStartType,
	DWORD dwErrorControl,
	LPSTR lpBinaryPathName,
	LPSTR lpLoadOrderGroup,
	LPDWORD lpdwTagId,
	LPSTR lpDependencies,
	LPSTR lpServiceStartName,
	LPSTR lpPassword,
	LPSTR lpDisplayName
	); //ADVAPI32
typedef BOOL(WINAPI *typeLookupAccountSidW)(LPCWSTR lpSystemName, PSID lpSid, LPWSTR lpName, LPDWORD cchName, LPWSTR lpReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse); //ADVAPI32
typedef BOOL(WINAPI *typeCreateWellKnownSid)(WELL_KNOWN_SID_TYPE WellKnownSidType, PSID DomainSid, PSID pSid, DWORD* cbSid); //ADVAPI32
typedef BOOL(WINAPI *typeConvertSidToStringSidW)(PSID Sid, LPWSTR* StringSid); //ADVAPI32
typedef BOOL(WINAPI *typeDeleteService)(SC_HANDLE hService); //ADVAPI32
typedef BOOL(WINAPI *typeGetUserNameA)(LPSTR lpBuffer, LPDWORD pcbBuffer); //ADVAPI32
typedef BOOL(WINAPI *typeIsTextUnicode)(const VOID* lpv, int iSize, LPINT lpiResult); //ADVAPI32
typedef BOOL(WINAPI *typeCryptGenKey)(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey); //ADVAPI32
typedef BOOL(WINAPI *typeCryptExportKey)(HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwBlobType, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen); //ADVAPI32
typedef BOOL(WINAPI *typeCryptCreateHash)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash); //ADVAPI32
typedef BOOL(WINAPI *typeCryptHashData)(HCRYPTHASH hHash, BYTE* pbData, DWORD dwDataLen, DWORD dwFlags); //ADVAPI32
typedef BOOL(WINAPI *typeCryptGetHashParam)(HCRYPTHASH hHash, DWORD dwParam, BYTE* pbData, DWORD* pdwDataLen, DWORD dwFlags); //ADVAPI32
typedef BOOL(WINAPI *typeCryptDestroyHash)(HCRYPTHASH hHash); //ADVAPI32
typedef BOOL(WINAPI *typeGetTokenInformation)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength); //ADVAPI32
typedef BOOL(WINAPI *typeLookupAccountSidA)(LPSTR lpSystemName, PSID lpSid, LPSTR lpName, LPDWORD cchName, LPSTR lpReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse); //ADVAPI32
typedef SC_HANDLE(WINAPI *typeCreateServiceA)
(
	SC_HANDLE hSCManager,
	LPSTR lpServiceName,
	LPSTR lpDisplayName,
	DWORD dwDesiredAccess,
	DWORD dwServiceType,
	DWORD dwStartType,
	DWORD dwErrorControl,
	LPSTR lpBinaryPathName,
	LPSTR lpLoadOrderGroup,
	LPDWORD lpdwTagId,
	LPSTR lpDependencies,
	LPSTR lpServiceStartName,
	LPSTR lpPassword
	);//ADVAPI32


	  ///////////////////////////
	  //GDIPLUS
	  ///////////////////////////
#ifdef __cplusplus
typedef GpStatus(WINAPI *typeGdipCreateBitmapFromHBITMAP)(HBITMAP hbm, HPALETTE hpal, GpBitmap** bitmap); //GDIPLUS
typedef GpStatus(WINAPI *typeGdipSaveImageToStream)(GpImage* image, IStream* stream, GDIPCONST CLSID* clsidEncoder, GDIPCONST EncoderParameters* encoderParams); //GDIPLUS
typedef GpStatus(WINAPI *typeGdipDisposeImage)(GpImage* image); //GDIPLUS
typedef Status(WINAPI *typeGetImageEncodersSize)(UINT* numEncoders, UINT* size); //GDIPLUS
typedef Status(WINAPI *typeGetImageEncoders)(UINT numEncoders, UINT size, ImageCodecInfo* encoders); //GDIPLUS
typedef Status(WINAPI *typeGdiplusStartup)(ULONG_PTR* token, const GdiplusStartupInput* input, GdiplusStartupOutput* output); //GDIPLUS
typedef void (WINAPI *typeGdiplusShutdown)(ULONG_PTR token); //GDIPLUS
#endif


															 ///////////////////////////
															 //GDI32
															 ///////////////////////////
typedef HDC(WINAPI *typeCreateCompatibleDC)(HDC hdc); //GDI32
typedef HBITMAP(WINAPI *typeCreateCompatibleBitmap)(HDC hdc, int nWidth, int nHeight); //GDI32
typedef BOOL(WINAPI *typeDeleteObject)(HGDIOBJ hObject); //GDI32
typedef BOOL(WINAPI *typeBeginPath)(HDC hdc); //GDI32
typedef BOOL(WINAPI *typePolyDraw)(HDC hdc, const POINT* lppt, const BYTE* lpbTypes, int cCount); //GDI32
typedef BOOL(WINAPI *typeEndPath)(HDC hdc); //GDI32
typedef BOOL(WINAPI *typeFlattenPath)(HDC hdc); //GDI32
typedef BOOL(WINAPI *typeDeleteDC)(HDC hdc); //GDI32
typedef BOOL(WINAPI *typeEnableEUDC)(BOOL fEnableEUDC); //GDI32
typedef HGDIOBJ(WINAPI *typeSelectObject)(HDC hdc, HGDIOBJ hgdiobj); //GDI32
typedef BOOL(WINAPI *typeBitBlt)(HDC hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, HDC hdcSrc, int nXSrc, int nYSrc, DWORD dwRop); //GDI32
typedef HRGN(WINAPI *typeCreateRoundRectRgn)(int nLeftRect, int nTopRect, int nRightRect, int nBottomRect, int nWidthEllipse, int nHeightEllipse); //GDI32
typedef int (WINAPI *typeGetDIBits)(HDC hdc, HBITMAP hbmp, UINT uStartScan, UINT cScanLines, LPVOID lpvBits, LPBITMAPINFO lpbi, UINT uUsage); //GDI32

																																			  ////////////////////////////////
																																			  //OLE32
																																			  ////////////////////////////////
typedef HRESULT(WINAPI *typeCreateStreamOnHGlobal)(HGLOBAL hGlobal, BOOL fDeleteOnRelease, LPSTREAM* ppstm); //OLE32
typedef HRESULT(WINAPI* typeCoInitializeEx)(LPVOID pvReserved, DWORD dwCoInit); //OLE32
typedef HRESULT(WINAPI* typeCoGetObject)(LPCWSTR pszName, BIND_OPTS* pBindOptions, REFIID riid, void** ppv); //OLE32
typedef HRESULT(WINAPI* typeCoCreateInstance)(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv); //OLE32
typedef void (WINAPI* typeCoUninitialize)(void); //OLE32


												 ////////////////////////////////
												 //PSAPI
												 ////////////////////////////////
typedef BOOL(WINAPI *typeEnumProcessModules)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded); //PSAPI
typedef DWORD(WINAPI *typeGetModuleFileNameExA)(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize); //PSAPI

																												  ////////////////////////////////
																												  //CABINET
																												  ////////////////////////////////
typedef HFCI(DIAMONDAPI *typeFCICreate)(PERF perf, PFNFCIFILEPLACED pfnfiledest, PFNFCIALLOC pfnalloc, PFNFCIFREE pfnfree, PFNFCIOPEN pfnopen, PFNFCIREAD pfnread, PFNFCIWRITE pfnwrite, PFNFCICLOSE pfnclose, PFNFCISEEK pfnseek, PFNFCIDELETE pfndelete, PFNFCIGETTEMPFILE pfnfcigtf, PCCAB pccab, void FAR * pv); //CABINET
typedef BOOL(DIAMONDAPI *typeFCIFlushCabinet)(HFCI hfci, BOOL fGetNextCab, PFNFCIGETNEXTCABINET GetNextCab, PFNFCISTATUS pfnProgress); //CABINET
typedef BOOL(DIAMONDAPI *typeFCIDestroy)(HFCI hfci); //CABINET
typedef BOOL(DIAMONDAPI *typeFCIAddFile)(HFCI hfci, LPSTR pszSourceFile, LPSTR pszFileName, BOOL fExecute, PFNFCIGETNEXTCABINET GetNextCab, PFNFCISTATUS pfnProgress, PFNFCIGETOPENINFO pfnOpenInfo, TCOMP typeCompress); //CABINET
typedef HFDI(DIAMONDAPI *typeFDICreate)(PFNALLOC pfnalloc, PFNFREE pfnfree, PFNOPEN pfnopen, PFNREAD pfnread, PFNWRITE pfnwrite, PFNCLOSE pfnclose, PFNSEEK pfnseek, int cpuType, PERF perf); //CABINET
typedef BOOL(DIAMONDAPI *typeFDIIsCabinet)(HFDI hfdi, INT_PTR hf, PFDICABINETINFO pfdici); //CABINET
typedef BOOL(DIAMONDAPI *typeFDICopy)(HFDI hfdi, LPSTR pszCabinet, LPSTR pszCabPath, INT flags, PFNFDINOTIFY pfnfdin, PFNFDIDECRYPT pfnfdid, void FAR * pvUser); //CABINET
typedef BOOL(DIAMONDAPI *typeFDIDestroy)(HFDI hfdi); //CABINET


													 /////////////////////////
													 //IMAGEHLP
													 /////////////////////////
typedef PIMAGE_NT_HEADERS(WINAPI *typeCheckSumMappedFile)(PVOID BaseAddress, DWORD FileLength, PDWORD HeaderSum, PDWORD CheckSum); //IMAGEHLP

																																   /////////////////////////
																																   //NETAPI32
																																   /////////////////////////
typedef NET_API_STATUS(WINAPI *typeNetUserAdd)(LMSTR servername, DWORD level, LPBYTE buf, LPDWORD parm_err); //NETAPI32
typedef NET_API_STATUS(WINAPI *typeNetLocalGroupAddMembers)(LPCWSTR servername, LPCWSTR groupname, DWORD level, LPBYTE buf, DWORD totalentries); //NETAPI32
typedef NET_API_STATUS(WINAPI *typeNetUserDel)(LPCWSTR servername, LPCWSTR username); //NETAPI32


																					  /////////////////////////
																					  //WTSAPI32
																					  /////////////////////////
typedef BOOL(WINAPI *typeWTSEnumerateSessionsA)(HANDLE hServer, DWORD Reserved, DWORD Version, PWTS_SESSION_INFOA* ppSessionInfo, DWORD* pCount); //WTSAPI32
typedef void (WINAPI *typeWTSFreeMemory)(PVOID pMemory); //WTSAPI32
typedef BOOL(WINAPI *typeWTSQuerySessionInformationA)(HANDLE hServer, DWORD SessionId, WTS_INFO_CLASS WTSInfoClass, LPSTR* ppBuffer, DWORD* pBytesReturned); //WTSAPI32
typedef BOOL(WINAPI *typeWTSQueryUserToken)(ULONG SessionId, PHANDLE phToken); //WTSAPI32

																			   /////////////////////////
																			   //MPR
																			   /////////////////////////
typedef DWORD(WINAPI *typeWNetAddConnection2A)(LPNETRESOURCEA lpNetResource, LPCSTR lpPassword, LPCSTR lpUsername, DWORD dwFlags); //MPR


/////////////////////////
//WINHTTP
//////

typedef LPVOID(WINAPI *typeWinHttpOpen)(LPCWSTR pwszUserAgent, DWORD dwAccessType, LPCWSTR pwszProxyName, LPCWSTR pwszProxyBypass, DWORD dwFlags); //WINHTTP
typedef LPVOID(WINAPI *typeWinHttpConnect)(LPVOID hSession, LPCWSTR pswzServerName, WORD nServerPort, DWORD dwReserved); //WINHTTP
typedef LPVOID(WINAPI *typeWinHttpOpenRequest)(LPVOID hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags); //WINHTTP
typedef BOOL(WINAPI *typeWinHttpQueryOption)(LPVOID hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength); //WINHTTP
typedef BOOL(WINAPI *typeWinHttpSetOption)(LPVOID hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength); //WINHTTP
typedef BOOL(WINAPI *typeWinHttpAddRequestHeaders)(LPVOID hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength, DWORD dwModifiers); //WINHTTP
typedef BOOL(WINAPI *typeWinHttpSendRequest)(LPVOID hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext); //WINHTTP
typedef BOOL(WINAPI *typeWinHttpReadData)(LPVOID hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead); //WINHTTP
typedef BOOL(WINAPI *typeWinHttpCloseHandle)(LPVOID hInternet); //WINHTTP
typedef BOOL(WINAPI *typeWinHttpQueryHeaders)(LPVOID hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex); //WINHTTP
typedef BOOL(WINAPI *typeWinHttpReceiveResponse)(LPVOID hRequest, LPVOID lpReserved); //WINHTTP
typedef BOOL(WINAPI *typeWinHttpQueryDataAvailable)(LPVOID hRequest, LPDWORD lpdwNumberOfBytesAvailable); //WINHTTP
typedef BOOL(WINAPI *typeWinHttpWriteData)(LPVOID hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten); //WINHTTP
typedef BOOL(WINAPI *typeWinHttpReadData)(LPVOID hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead); //WINHTTP

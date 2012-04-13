#include <windows.h>

// See also
//	http://recyclebin.jugem.jp/?eid=341
//	http://recyclebin.jugem.jp/?day=20120309
//	http://tedwvc.wordpress.com/2012/03/11/how-to-get-visual-c-2012-vc-11-beta-statically-linked-crt-and-mfc-applications-to-run-on-windows-xp/
//	http://blog.livedoor.jp/blackwingcat/archives/1192179.html
//	http://stackoverflow.com/questions/2484511/can-i-use-visual-studio-2010s-c-compiler-with-visual-studio-2008s-c-runtim/3502056#3502056

#define PROC_PTR_UNINITIALIZED ((void*)1)


static void *
getModuleProcAddress (void *procPtr, const char *szModule, const char *szProc)
{
	if (PROC_PTR_UNINITIALIZED == procPtr) {
		void *p = 0;
		HMODULE h = GetModuleHandleA (szModule);
		if (h) {
			p = GetProcAddress (h, szProc);
		}
		procPtr = p;
	}
	return procPtr;
}


// http://msdn.microsoft.com/en-us/library/bb432254(v=vs.85).aspx
extern "C" void * __stdcall
xyzzyEncodePointer (void *ptr)
{
	const char szModule[] = "KERNEL32";
	const char szProc[] = "EncodePointer";
	typedef void *(WINAPI *FUNC)(void *);
	static void *procPtr = PROC_PTR_UNINITIALIZED;

	procPtr = getModuleProcAddress (procPtr, szModule, szProc);
	if (procPtr) {
		ptr = ((FUNC)procPtr)(ptr);
	}
	return ptr;
}


// http://msdn.microsoft.com/en-us/library/bb432242(v=VS.85).aspx
extern "C" void * __stdcall
xyzzyDecodePointer (void *ptr)
{
	const char szModule[] = "KERNEL32";
	const char szProc[] = "DecodePointer";
	typedef void *(WINAPI *FUNC)(void *);
	static void *procPtr = PROC_PTR_UNINITIALIZED;

	procPtr = getModuleProcAddress (procPtr, szModule, szProc);
	if (procPtr) {
		ptr = ((FUNC)procPtr)(ptr);
	}
	return ptr;
}


// http://msdn.microsoft.com/en-us/library/windows/desktop/ms686203(v=vs.85).aspx
extern "C" BOOL __stdcall
xyzzySetDllDirectoryA (const char *lpPathName)
{
	const char szModule[] = "KERNEL32";
	const char szProc[] = "SetDllDirectoryA";
	typedef BOOL (WINAPI *FUNC)(const char*);
	static void *procPtr = PROC_PTR_UNINITIALIZED;

	procPtr = getModuleProcAddress (procPtr, szModule, szProc);
	BOOL ret = 0;
	if (procPtr) {
		ret = ((FUNC)procPtr)(lpPathName);
	}
	return ret;
}


// http://msdn.microsoft.com/en-us/library/windows/desktop/ms682664(v=vs.85).aspx
extern "C" DWORD __stdcall
xyzzyFlsAlloc (PFLS_CALLBACK_FUNCTION lpCallback)
{
	const char szModule[] = "KERNEL32";
	const char szProc[] = "FlsAlloc";
	typedef DWORD (WINAPI *FUNC)(PFLS_CALLBACK_FUNCTION);
	static void *procPtr = PROC_PTR_UNINITIALIZED;

	procPtr = getModuleProcAddress (procPtr, szModule, szProc);
	DWORD ret = 0;
	if (procPtr) {
		ret = ((FUNC)procPtr)(lpCallback);
	} else {
		ret = TlsAlloc();
	}
	return ret;
}


// http://msdn.microsoft.com/en-us/library/windows/desktop/ms682667(v=vs.85).aspx
extern "C" BOOL __stdcall
xyzzyFlsFree (DWORD dwFlsIndex)
{
	const char szModule[] = "KERNEL32";
	const char szProc[] = "FlsFree";
	typedef BOOL (WINAPI *FUNC)(DWORD);
	static void *procPtr = PROC_PTR_UNINITIALIZED;

	procPtr = getModuleProcAddress (procPtr, szModule, szProc);
	BOOL ret = 0;
	if (procPtr) {
		ret = ((FUNC)procPtr)(dwFlsIndex);
	} else {
		ret = TlsFree(dwFlsIndex);
	}
	return ret;
}


// http://msdn.microsoft.com/en-us/library/windows/desktop/ms683141(v=vs.85).aspx
extern "C" PVOID __stdcall
xyzzyFlsGetValue (DWORD dwFlsIndex)
{
	const char szModule[] = "KERNEL32";
	const char szProc[] = "FlsGetValue";
	typedef PVOID (WINAPI *FUNC)(DWORD);
	static void *procPtr = PROC_PTR_UNINITIALIZED;

	procPtr = getModuleProcAddress (procPtr, szModule, szProc);
	PVOID ret = 0;
	if (procPtr) {
		ret = ((FUNC)procPtr)(dwFlsIndex);
	} else {
		ret = TlsGetValue(dwFlsIndex);
	}
	return ret;
}


// http://msdn.microsoft.com/en-us/library/windows/desktop/ms683146(v=vs.85).aspx
extern "C" BOOL __stdcall
xyzzyFlsSetValue (DWORD dwFlsIndex, PVOID lpFlsData)
{
	const char szModule[] = "KERNEL32";
	const char szProc[] = "FlsSetValue";
	typedef BOOL (WINAPI *FUNC)(DWORD, PVOID);
	static void *procPtr = PROC_PTR_UNINITIALIZED;

	procPtr = getModuleProcAddress (procPtr, szModule, szProc);
	BOOL ret = 0;
	if (procPtr) {
		ret = ((FUNC)procPtr)(dwFlsIndex, lpFlsData);
	} else {
		ret = TlsSetValue(dwFlsIndex, lpFlsData);
	}
	return ret;
}


// http://msdn.microsoft.com/en-us/library/windows/desktop/ms683200(v=vs.85).aspx
extern "C" BOOL __stdcall
xyzzyGetModuleHandleExW (DWORD dwFlags, LPCWSTR lpwModuleName, HMODULE *phModule)
{
	const char szModule[] = "KERNEL32";
	const char szProc[] = "GetModuleHandleExW";
	typedef BOOL (WINAPI *FUNC)(DWORD, LPCWSTR, HMODULE*);
	static void *procPtr = PROC_PTR_UNINITIALIZED;

	procPtr = getModuleProcAddress (procPtr, szModule, szProc);
	BOOL ret = 0;
	if (procPtr) {
		ret = ((FUNC)procPtr)(dwFlags, lpwModuleName, phModule);
	} else {
		if(dwFlags == 0) {
			// dwFlags == 0 ÇÃÉPÅ[ÉXÇÃÇ›ëŒâûÇ∑ÇÈ
			HMODULE hModule = GetModuleHandleW(lpwModuleName);
			if(hModule) {
				if(phModule) {
					*phModule = hModule;
				}
				ret = TRUE;
			}
		}
	}

	return ret;
}


// http://msdn.microsoft.com/en-us/library/windows/desktop/ms724411(v=vs.85).aspx
extern "C" ULONGLONG __stdcall
xyzzyGetTickCount64 (void)
{
	const char szModule[] = "KERNEL32";
	const char szProc[] = "GetTickCount64";
	typedef ULONGLONG (WINAPI *FUNC)(void);
	static void *procPtr = PROC_PTR_UNINITIALIZED;

	procPtr = getModuleProcAddress (procPtr, szModule, szProc);
	ULONGLONG ret = 0;
	if (procPtr) {
		ret = ((FUNC)procPtr)();
	} else {
		ret = GetTickCount();
	}
	return ret;
}


// http://msdn.microsoft.com/en-us/library/windows/desktop/dd318702(v=vs.85).aspx
extern "C" int __stdcall
xyzzyLCMapStringEx (
	LPCWSTR lpLocaleName, DWORD dwMapFlags, LPCWSTR lpSrcStr, int cchSrc,
	LPWSTR lpDestStr, int cchDest, LPNLSVERSIONINFO lpVersionInformation,
	LPVOID lpReserved, LPARAM sortHandle )
{
	const char szModule[] = "KERNEL32";
	const char szProc[] = "LCMapStringEx";
	typedef int (WINAPI *FUNC)(LPCWSTR, DWORD, LPCWSTR, int, LPWSTR, int, LPNLSVERSIONINFO, LPVOID, LPARAM);
	static void *procPtr = PROC_PTR_UNINITIALIZED;

	procPtr = getModuleProcAddress (procPtr, szModule, szProc);
	int ret = 0;
	if (procPtr) {
		ret = ((FUNC)procPtr)(lpLocaleName, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest, lpVersionInformation, lpReserved, sortHandle);
	} else {
		ret = LCMapStringW(GetUserDefaultLCID(), dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest);
	}
	return ret;
}

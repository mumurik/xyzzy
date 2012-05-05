#include "stdafx.h"

//
//	VC++2010で作るバイナリを2000で
//	http://recyclebin.jugem.jp/?eid=341
//
//	VC++ 2010 再頒布可能パッケージ と Windows 2000
//	http://blog.livedoor.jp/blackwingcat/archives/1192179.html
//
//	Can I use Visual Studio 2010's C++ compiler with Visual Studio 2008's C++ Runtime Library?
//	http://stackoverflow.com/questions/2484511/can-i-use-visual-studio-2010s-c-compiler-with-visual-studio-2008s-c-runtim/3502056#3502056
//
//	VC++11βで作った実行ファイルをXPで　動かそうと思ったけどめんどくさくなった
//	http://recyclebin.jugem.jp/?day=20120309
//
//	How to get Visual C++ 2012 (VC 11 Beta) statically linked CRT and MFC applications to run on Windows XP
//	http://tedwvc.wordpress.com/2012/03/11/how-to-get-visual-c-2012-vc-11-beta-statically-linked-crt-and-mfc-applications-to-run-on-windows-xp/
//

#define IS_VC2010_OR_LATER (_MSC_VER >= 1600)
#define IS_VC2011_OR_LATER (_MSC_VER >= 1700)
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


//
// SetDllDirectory
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms686203(v=vs.85).aspx
//
extern "C" BOOL __stdcall
xyzzySetDllDirectoryA (LPCSTR lpPathName)
{
  static const char szModule[] = "KERNEL32";
  static const char szProc[] = "SetDllDirectoryA";
  typedef BOOL (WINAPI *FUNC)(LPCSTR);
  static void *procPtr = PROC_PTR_UNINITIALIZED;

  procPtr = getModuleProcAddress (procPtr, szModule, szProc);
  BOOL ret = 0;
  if (procPtr) {
    ret = ((FUNC)procPtr)(lpPathName);
  }
  return ret;
}


//
// GetNativeSystemInfo
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms724340(v=vs.85).aspx
//
extern "C" void __stdcall
xyzzyGetNativeSystemInfo (LPSYSTEM_INFO lpSystemInfo)
{
  static const char szModule[] = "KERNEL32";
  static const char szProc[] = "GetNativeSystemInfo";
  typedef void (WINAPI *FUNC)(LPSYSTEM_INFO);
  static void *procPtr = PROC_PTR_UNINITIALIZED;

  procPtr = getModuleProcAddress (procPtr, szModule, szProc);
  if (procPtr) {
    ((FUNC)procPtr)(lpSystemInfo);
  } else {
    GetSystemInfo (lpSystemInfo);
  }
}


#if IS_VC2010_OR_LATER
//
// EncodePointer
// http://msdn.microsoft.com/en-us/library/bb432254(v=vs.85).aspx
//
extern "C" PVOID __stdcall
xyzzyEncodePointer (PVOID ptr)
{
  static const char szModule[] = "KERNEL32";
  static const char szProc[] = "EncodePointer";
  typedef PVOID (WINAPI *FUNC)(PVOID);
  static void *procPtr = PROC_PTR_UNINITIALIZED;

  procPtr = getModuleProcAddress (procPtr, szModule, szProc);
  if (procPtr) {
    ptr = ((FUNC)procPtr)(ptr);
  }
  return ptr;
}
#endif // IS_VC2010_OR_LATER


#if IS_VC2010_OR_LATER
//
// DecodePointer
// http://msdn.microsoft.com/en-us/library/bb432242(v=VS.85).aspx
//
extern "C" PVOID __stdcall
xyzzyDecodePointer (PVOID ptr)
{
  static const char szModule[] = "KERNEL32";
  static const char szProc[] = "DecodePointer";
  typedef PVOID (WINAPI *FUNC)(PVOID);
  static void *procPtr = PROC_PTR_UNINITIALIZED;

  procPtr = getModuleProcAddress (procPtr, szModule, szProc);
  if (procPtr) {
    ptr = ((FUNC)procPtr)(ptr);
  }
  return ptr;
}
#endif // IS_VC2010_OR_LATER


#if IS_VC2011_OR_LATER
//
// GetModuleHandleExW
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms683200(v=vs.85).aspx
//
extern "C" BOOL __stdcall
xyzzyGetModuleHandleExW (DWORD dwFlags, LPCWSTR lpwModuleName, HMODULE *phModule)
{
  static const char szModule[] = "KERNEL32";
  static const char szProc[] = "GetModuleHandleExW";
  typedef BOOL (WINAPI *FUNC)(DWORD, LPCWSTR, HMODULE*);
  static void *procPtr = PROC_PTR_UNINITIALIZED;

  procPtr = getModuleProcAddress (procPtr, szModule, szProc);
  BOOL ret = 0;
  if (procPtr) {
    ret = ((FUNC)procPtr)(dwFlags, lpwModuleName, phModule);
  } else {
    if(dwFlags == 0) {
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
#endif


#if IS_VC2011_OR_LATER
//
// FlsAlloc
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms682664(v=vs.85).aspx
//
extern "C" DWORD __stdcall
xyzzyFlsAlloc (PFLS_CALLBACK_FUNCTION lpCallback)
{
  static const char szModule[] = "KERNEL32";
  static const char szProc[] = "FlsAlloc";
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
#endif // IS_VC2011_OR_LATER


#if IS_VC2011_OR_LATER
//
// FlsFree
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms682667(v=vs.85).aspx
//
extern "C" BOOL __stdcall
xyzzyFlsFree (DWORD dwFlsIndex)
{
  static const char szModule[] = "KERNEL32";
  static const char szProc[] = "FlsFree";
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
#endif // IS_VC2011_OR_LATER


#if IS_VC2011_OR_LATER
//
// FlsGetValue
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms683141(v=vs.85).aspx
//
extern "C" PVOID __stdcall
xyzzyFlsGetValue (DWORD dwFlsIndex)
{
  static const char szModule[] = "KERNEL32";
  static const char szProc[] = "FlsGetValue";
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
#endif // IS_VC2011_OR_LATER


#if IS_VC2011_OR_LATER
//
// FlsSetValue
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms683146(v=vs.85).aspx
//
extern "C" BOOL __stdcall
xyzzyFlsSetValue (DWORD dwFlsIndex, PVOID lpFlsData)
{
  static const char szModule[] = "KERNEL32";
  static const char szProc[] = "FlsSetValue";
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
#endif // IS_VC2011_OR_LATER


#if IS_VC2011_OR_LATER
//
// GetTickCount64
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms724411(v=vs.85).aspx
//
extern "C" ULONGLONG __stdcall
xyzzyGetTickCount64 (void)
{
  static const char szModule[] = "KERNEL32";
  static const char szProc[] = "GetTickCount64";
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
#endif // IS_VC2011_OR_LATER


#if IS_VC2011_OR_LATER
//
// LCMapStringEx
// http://msdn.microsoft.com/en-us/library/windows/desktop/dd318702(v=vs.85).aspx
//
extern "C" int __stdcall
xyzzyLCMapStringEx (
  LPCWSTR lpLocaleName, DWORD dwMapFlags, LPCWSTR lpSrcStr, int cchSrc,
  LPWSTR lpDestStr, int cchDest, LPNLSVERSIONINFO lpVersionInformation,
  LPVOID lpReserved, LPARAM sortHandle )
{
  static const char szModule[] = "KERNEL32";
  static const char szProc[] = "LCMapStringEx";
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
#endif // IS_VC2011_OR_LATER

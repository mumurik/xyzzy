.model flat
.data

VCVER = PLATVER / 10

;
; VC10 + Windows 2000 SP4 Update Rollup 1
;
EXTRN _xyzzySetDllDirectoryA@4:PROC
EXTRN _xyzzyGetNativeSystemInfo@4:PROC
EXTERNDEF __imp__SetDllDirectoryA@4:DWORD
EXTERNDEF __imp__GetNativeSystemInfo@4:DWORD
__imp__SetDllDirectoryA@4       dd _xyzzySetDllDirectoryA@4
__imp__GetNativeSystemInfo@4    dd _xyzzyGetNativeSystemInfo@4


ifdef VCVER
if VCVER ge 10

EXTRN _xyzzyEncodePointer@4:PROC
EXTRN _xyzzyDecodePointer@4:PROC

EXTERNDEF __imp__EncodePointer@4:DWORD
EXTERNDEF __imp__DecodePointer@4:DWORD

__imp__EncodePointer@4          dd _xyzzyEncodePointer@4
__imp__DecodePointer@4          dd _xyzzyDecodePointer@4

endif ; VCVER ge 10
endif ; VCVER


;
; VC11 + Windows 2000 SP4 Update Rollup 1
;
ifdef VCVER
if VCVER ge 11

EXTRN _xyzzyGetModuleHandleExW@12:PROC
EXTERNDEF __imp__GetModuleHandleExW@12:DWORD
__imp__GetModuleHandleExW@12    dd _xyzzyGetModuleHandleExW@12

endif ; VCVER ge 11
endif ; VCVER


;
; VC11 + Windows XP
;
ifdef VCVER
if VCVER ge 11

EXTRN _xyzzyFlsAlloc@4:PROC
EXTRN _xyzzyFlsFree@4:PROC
EXTRN _xyzzyFlsGetValue@4:PROC
EXTRN _xyzzyFlsSetValue@8:PROC
EXTRN _xyzzyGetTickCount64@0:PROC
EXTRN _xyzzyLCMapStringEx@36:PROC

EXTERNDEF __imp__FlsAlloc@4:DWORD
EXTERNDEF __imp__FlsFree@4:DWORD
EXTERNDEF __imp__FlsGetValue@4:DWORD
EXTERNDEF __imp__FlsSetValue@8:DWORD
EXTERNDEF __imp__GetTickCount64@0:DWORD
EXTERNDEF __imp__LCMapStringEx@36:DWORD

__imp__FlsAlloc@4               dd _xyzzyFlsAlloc@4
__imp__FlsFree@4                dd _xyzzyFlsFree@4
__imp__FlsGetValue@4            dd _xyzzyFlsGetValue@4
__imp__FlsSetValue@8            dd _xyzzyFlsSetValue@8
__imp__GetTickCount64@0         dd _xyzzyGetTickCount64@0
__imp__LCMapStringEx@36         dd _xyzzyLCMapStringEx@36

endif ; VCVER ge 11
endif ; VCVER

end

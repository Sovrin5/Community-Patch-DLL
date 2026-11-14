/*	-------------------------------------------------------------------------------------------------------
	© 1991-2012 Take-Two Interactive Software and its subsidiaries.  Developed by Firaxis Games.  
	Sid Meier's Civilization V, Civ, Civilization, 2K Games, Firaxis Games, Take-Two Interactive Software 
	and their respective logos are all trademarks of Take-Two interactive Software, Inc.  
	All other marks and trademarks are the property of their respective owners.  
	All rights reserved. 
	------------------------------------------------------------------------------------------------------- */
#include "CvGameCoreDLLPCH.h"
#include "CvGlobals.h"
#include "ICvDLLUserInterface.h"
#include "Win32/FDebugHelper.h"
#include "CvDllContext.h"

// must be included after all other headers
#include "LintFree.h"

//------------------------------------------------------------------------------
extern "C" ICvGameContext1* DllGetGameContext()
{
	return CvDllGameContext::GetSingleton();
}
// ---- Hidden-desktop mouse fix (14 Nov 2026). When the game runs on a desktop that is NOT the user's input desktop
// (Claude's hidden test desktop) its ClipCursor calls locked the user's real mouse to one monitor. Only the game exe
// imports ClipCursor (checked: no other game module names it), so we redirect that ONE import slot to a stub that drops
// lock requests while the game is not on the input desktop. The slot is put back on DLL unload (mods on/off reload this
// DLL; a slot left pointing into an unloaded DLL would crash the game). On the user's own desktop nothing changes.
typedef BOOL (WINAPI* HDF_ClipCursorFn)(const RECT*);
static HDF_ClipCursorFn s_pHdfRealClipCursor = NULL;
static DWORD_PTR* s_pHdfSlot = NULL;
// The engine's Windows header settings hide the desktop API, so it is looked up at runtime (user32 is always loaded).
typedef HANDLE (WINAPI* HDF_OpenInputDesktopFn)(DWORD, BOOL, DWORD);
typedef HANDLE (WINAPI* HDF_GetThreadDesktopFn)(DWORD);
typedef BOOL (WINAPI* HDF_GetUserObjectInformationAFn)(HANDLE, int, PVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI* HDF_CloseDesktopFn)(HANDLE);
static bool HDF_OnInputDesktop()
{
	static HDF_OpenInputDesktopFn pOpen = NULL; static HDF_GetThreadDesktopFn pThread = NULL;
	static HDF_GetUserObjectInformationAFn pInfo = NULL; static HDF_CloseDesktopFn pClose = NULL;
	if (!pOpen)
	{
		HMODULE hUser = GetModuleHandleA("user32.dll"); if (!hUser) return true;
		pThread = (HDF_GetThreadDesktopFn)GetProcAddress(hUser, "GetThreadDesktop");
		pInfo = (HDF_GetUserObjectInformationAFn)GetProcAddress(hUser, "GetUserObjectInformationA");
		pClose = (HDF_CloseDesktopFn)GetProcAddress(hUser, "CloseDesktop");
		pOpen = (HDF_OpenInputDesktopFn)GetProcAddress(hUser, "OpenInputDesktop");
		if (!pOpen || !pThread || !pInfo || !pClose) { pOpen = NULL; return true; } // API missing: behave like the stock game
	}
	const DWORD kDesktopReadObjects = 0x0001; const int kUoiName = 2;
	HANDLE hIn = pOpen(0, FALSE, kDesktopReadObjects);
	if (!hIn) return false; // cannot see the input desktop: treat as hidden (never lock)
	HANDLE hMine = pThread(GetCurrentThreadId());
	char a[256] = {0}, b[256] = {0}; DWORD n = 0;
	pInfo(hIn, kUoiName, a, sizeof(a) - 1, &n);
	pInfo(hMine, kUoiName, b, sizeof(b) - 1, &n);
	pClose(hIn);
	return _stricmp(a, b) == 0;
}
static BOOL WINAPI HDF_ClipCursor(const RECT* pRect)
{
	if (pRect != NULL && !HDF_OnInputDesktop()) return TRUE;
	return s_pHdfRealClipCursor ? s_pHdfRealClipCursor(pRect) : TRUE;
}
static bool HDF_WriteSlot(DWORD_PTR* pSlot, DWORD_PTR value)
{
	DWORD old = 0;
	if (!VirtualProtect(pSlot, sizeof(DWORD_PTR), PAGE_READWRITE, &old)) return false;
	*pSlot = value;
	VirtualProtect(pSlot, sizeof(DWORD_PTR), old, &old);
	return true;
}
static void HDF_Install()
{
	HMODULE hUser = GetModuleHandleA("user32.dll"); if (!hUser) return;
	s_pHdfRealClipCursor = (HDF_ClipCursorFn)GetProcAddress(hUser, "ClipCursor"); if (!s_pHdfRealClipCursor) return;
	BYTE* base = (BYTE*)GetModuleHandleA(NULL); if (!base) return;
	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)base; if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return;
	IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)(base + pDos->e_lfanew); if (pNt->Signature != IMAGE_NT_SIGNATURE) return;
	IMAGE_DATA_DIRECTORY& dir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (!dir.VirtualAddress) return;
	for (IMAGE_IMPORT_DESCRIPTOR* pImp = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress); pImp->Name && !s_pHdfSlot; pImp++)
	{
		if (_stricmp((const char*)(base + pImp->Name), "user32.dll") != 0) continue;
		for (IMAGE_THUNK_DATA* pT = (IMAGE_THUNK_DATA*)(base + pImp->FirstThunk); pT->u1.Function; pT++)
		{
			if ((DWORD_PTR)pT->u1.Function != (DWORD_PTR)s_pHdfRealClipCursor) continue;
			if (HDF_WriteSlot((DWORD_PTR*)&pT->u1.Function, (DWORD_PTR)&HDF_ClipCursor)) s_pHdfSlot = (DWORD_PTR*)&pT->u1.Function;
			break;
		}
	}
	if (!HDF_OnInputDesktop()) s_pHdfRealClipCursor(NULL); // release a lock taken before we loaded
	OutputDebugStringA(s_pHdfSlot ? "HiddenDesktopFix: exe ClipCursor redirected\n" : "HiddenDesktopFix: exe ClipCursor slot NOT found\n");
}
static void HDF_Uninstall()
{
	if (s_pHdfSlot && *s_pHdfSlot == (DWORD_PTR)&HDF_ClipCursor) HDF_WriteSlot(s_pHdfSlot, (DWORD_PTR)s_pHdfRealClipCursor);
	s_pHdfSlot = NULL;
}
//------------------------------------------------------------------------------
BOOL APIENTRY DllMain(HANDLE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID)
{
	switch(ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		// The DLL is being loaded into the virtual address space of the current process as a result of the process starting up
		OutputDebugString("DLL_PROCESS_ATTACH\n");
		FDebugHelper::GetInstance().LoadSymbols((HMODULE)hModule);
		// set timer precision
		MMRESULT iTimeSet = timeBeginPeriod(1);		// set timeGetTime and sleep resolution to 1 ms, otherwise it's 10-16ms
		DEBUG_VARIABLE(iTimeSet);
		ASSERT(iTimeSet==TIMERR_NOERROR, "failed setting timer resolution to 1 ms");
		CvDllGameContext::InitializeSingleton();
		HDF_Install();
	}
	break;
	case DLL_THREAD_ATTACH:
		OutputDebugString("DLL_THREAD_ATTACH\n");
		break;
	case DLL_THREAD_DETACH:
		OutputDebugString("DLL_THREAD_DETACH\n");
		break;
	case DLL_PROCESS_DETACH:
		OutputDebugString("DLL_PROCESS_DETACH\n");
		HDF_Uninstall();
		timeEndPeriod(1);
		CvDllGameContext::DestroySingleton();
		GC.setDLLIFace(NULL);
		break;
	}

	return TRUE;	// success
}

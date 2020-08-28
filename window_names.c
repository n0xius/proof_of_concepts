#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI* NtUserBuildHwndListWin10_t)(
	IN HDESK hDesk,
	IN HWND hwndNext,
	IN BOOL bEnumChildren,
	IN DWORD dwUnknown,
	IN DWORD dwThreadId,
	IN UINT cHwndMax,
	OUT HWND* phwndFirst,
	OUT ULONG* pcHwndNeeded
	);

typedef INT (WINAPI* NtUserGetClassName_t)(
	HWND hWnd,
	BOOL Real,
	PUNICODE_STRING ClassName 
	);

typedef ULONG_PTR (WINAPI* NtUserCallOneParam_t)(
	IN ULONG Param,
	IN ULONG Routine
	);

NTSTATUS CallNtUserBuildHwndList(UINT _Size, HWND* _HwndList, ULONG* _Count)
{
	HMODULE win32u = LoadLibraryA("win32u.dll");

	if (!win32u)
		return STATUS_DLL_NOT_FOUND;
	
	NtUserBuildHwndListWin10_t ntUserBuildHwndList = (NtUserBuildHwndListWin10_t)GetProcAddress(win32u, "NtUserBuildHwndList");

	if (!ntUserBuildHwndList)
		return STATUS_ENTRYPOINT_NOT_FOUND;

	return ntUserBuildHwndList(0, 0, 1, 0, 0, _Size, _HwndList, _Count);
}

int main(int argv, char* argc[])
{
	HMODULE win32u = LoadLibraryA("win32u.dll");

	if (!win32u)
		return 1;
	
	NtUserGetClassName_t ntUserGetClassName = (NtUserGetClassName_t)GetProcAddress(win32u, "NtUserGetClassName");

	if (!ntUserGetClassName)
		return 1;
	
	NtUserCallOneParam_t ntUserCallOneParam = (NtUserCallOneParam_t)GetProcAddress(win32u, "NtUserCallOneParam");

	if (!ntUserCallOneParam)
		return 1;

	DWORD dwSize = 64;
	HWND* hwndList = (HWND*)malloc(sizeof(HWND) * dwSize);

	if (!hwndList)
		return 1;

	DWORD dwCount;

	if (CallNtUserBuildHwndList(dwSize, hwndList, &dwCount) != 0xC0000023)
	{
		printf("CallNtUserBuildHwndList status: %x\n", GetLastError());
		return 1;
	}

	hwndList = (HWND*)realloc(hwndList, sizeof(HWND) * (dwCount + 2));
	dwSize = dwCount;

	if (!hwndList)
		return 1;

	// NOTE: recall the function with a correct sized buffer
	if (!NT_SUCCESS(CallNtUserBuildHwndList(dwSize, hwndList, &dwCount)))
	{
		printf("CallNtUserBuildHwndList status: %x", GetLastError());
		return 1;
	}

	for (DWORD i = 0; i < dwCount; ++i)
	{
		if (!hwndList[i])
			continue;
		
		wchar_t windowText[260];
		const int wndLen = GetWindowTextW(hwndList[i], windowText, 260);

		wchar_t classText[260];
		UNICODE_STRING className;

		className.Buffer = &classText;
		className.MaximumLength = sizeof(classText);

		const int classLen = ntUserGetClassName(hwndList[i], TRUE, &className);

		printf("%04x: %S %S\n", i, classText, windowText);
	}

	free(hwndList);

	return 0;
}

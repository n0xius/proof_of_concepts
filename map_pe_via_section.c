#include <windows.h>
#include <winnt.h>
#include <winternl.h>

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

NTSTATUS NTAPI NtCreateSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
	IN OPTIONAL PLARGE_INTEGER MaximumSize,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN OPTIONAL HANDLE FileHandle
);

NTSTATUS NTAPI NtMapViewOfSection(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	OUT PVOID* BaseAddress,
	IN SIZE_T ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT OPTIONAL  PLARGE_INTEGER SectionOffset,
	IN OUT PSIZE_T ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Win32Protect
);

NTSTATUS NTAPI NtUnmapViewOfSection(
	IN HANDLE ProcessHandle,
	IN OPTIONAL PVOID BaseAddress
);

NTSTATUS NTAPI NtCreateTransaction (
    OUT PHANDLE TransactionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL LPGUID Uow,
    IN OPTIONAL HANDLE TmHandle,
    IN OPTIONAL ULONG CreateOptions,
    IN OPTIONAL ULONG IsolationLevel,
    IN OPTIONAL ULONG IsolationFlags,
    IN OPTIONAL PLARGE_INTEGER Timeout,
    IN OPTIONAL PUNICODE_STRING Description
);

NTSTATUS NTAPI RtlSetCurrentTransaction (
    IN HANDLE TransactionHandle
);

int main(int argv, char* argc[])
{
	wchar_t universalNtPath[MAX_PATH];

	memset(universalNtPath, 0, sizeof(universalNtPath));

	wcscat(universalNtPath, L"\\??\\");
	wcscat(universalNtPath, L"C:\\Windows\\System32\\ntoskrnl.exe");

	// NOTE: who the fuck needs RtlInitUnicodeString in usermode lol?
	UNICODE_STRING ntPath = {
		(USHORT)(wcslen(universalNtPath) * sizeof(wchar_t)),
		(USHORT)(MAX_PATH * sizeof(wchar_t)),
		universalNtPath
	};

	OBJECT_ATTRIBUTES objectAttributes = {
		sizeof(OBJECT_ATTRIBUTES),
		0,
		&ntPath,
		OBJ_CASE_INSENSITIVE,
		0,
		0
	};

	IO_STATUS_BLOCK ioStatusBlock;
	HANDLE fileHandle = INVALID_HANDLE_VALUE;

	// NOTE: create file handle as read-only and open if exists
	NTSTATUS status = NtCreateFile(&fileHandle,
		FILE_GENERIC_READ | SYNCHRONIZE,
		&objectAttributes,
		&ioStatusBlock,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0
	);

	if (!NT_SUCCESS(status))
		return status;

	HANDLE sectionHandle = INVALID_HANDLE_VALUE;

	// NOTE: create read-only, non image marked section
	//		 image will have file name etc. if alloction attributes is SEC_IMAGE
	status = NtCreateSection(&sectionHandle,
		SECTION_MAP_READ,
		0,
		0,
		PAGE_READONLY,
		SEC_IMAGE_NO_EXECUTE,
		fileHandle
	);

	if (!NT_SUCCESS(status))
		return status;

	status = NtClose(fileHandle);

	if (!NT_SUCCESS(status))
		return status;

	PVOID sectionAddress = 0; // NOTE: address of mapped section
	SIZE_T sectionSize = 0; // NOTE: size of mapped section

	// NOTE: GetCurrentProcess = NtCurrentProcess = INVALID_HANDLE_VALUE
	HANDLE processHandle = INVALID_HANDLE_VALUE;

	// NOTE: map view of section into our process address space
	//		 InheritDisposition = ViewUnmap since we don't want share the section
	//		 Win32Protect = PAGE_READONLY since we only want to read the section
	status = NtMapViewOfSection(sectionHandle,
		processHandle,
		&sectionAddress,
		0,
		0,
		0,
		&sectionSize,
		ViewUnmap,
		0,
		PAGE_READONLY
	);

	if (!NT_SUCCESS(status))
		return status;

	status = NtClose(sectionHandle);

	if (!NT_SUCCESS(status))
		return status;

	// TODO: parse mapped pe image here...

	// NOTE: unmap view of section
	status = NtUnmapViewOfSection(
		processHandle, 
		sectionAddress
	);

	if (!NT_SUCCESS(status))
		return status;

	return 0;
}

#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <stdio.h>

NTSTATUS
NTAPI
NtDeleteFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS
NTAPI
NtReadFile(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
);

NTSTATUS
NTAPI
NtWriteFile(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
);

NTSTATUS
NTAPI
NtCreateTransaction(
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

NTSTATUS
NTAPI
RtlSetCurrentTransaction(
	IN HANDLE TransactionHandle
);

NTSTATUS
NTAPI
NtCommitTransaction(
	IN HANDLE  TransactionHandle,
	IN BOOLEAN Wait
);

NTSTATUS
NTAPI
NtRollbackTransaction(
	IN HANDLE  TransactionHandle,
	IN BOOLEAN Wait
);

void DumpHex(const void* data, size_t size)
{
	char ascii[17];
	
	ascii[16] = '\0';

	for (size_t i = 0; i < size; ++i)
	{
		const BYTE* byteData = (BYTE*)data;

		printf("%02X ", byteData[i]);

		if (byteData[i] >= ' ' && byteData[i] <= '~')
			ascii[i % 16] = (char)byteData[i];
		else
			ascii[i % 16] = '.';

		if ((i + 1) % 8 != 0)
			continue;

		if ((i + 1) % 16 == 0)
			printf("|  %s \n", ascii);
		else if (i + 1 == size)
		{
			ascii[(i + 1) % 16] = '\0';

			if ((i + 1) % 16 <= 8)
				printf(" ");

			for (size_t j = (i + 1) % 16; j < 16; ++j)
				printf("   ");

			printf("|  %s \n", ascii);
		}
	}
}

NTSTATUS ReadAndPrintFile(const wchar_t* _FileWithPath)
{
	wchar_t universalNtPath[MAX_PATH];

	memset(universalNtPath, 0, sizeof(universalNtPath));

	wcscat(universalNtPath, L"\\??\\");
	wcscat(universalNtPath, _FileWithPath);

	HANDLE fileHandle = INVALID_HANDLE_VALUE;
	IO_STATUS_BLOCK IoStatusBlock;

	UNICODE_STRING ntPath = {
		(USHORT)(wcslen(universalNtPath) * sizeof(wchar_t)),
		(USHORT)(MAX_PATH * sizeof(wchar_t)),
		universalNtPath
	};

	OBJECT_ATTRIBUTES ObjectAttributes = {
		sizeof(OBJECT_ATTRIBUTES),
		0,
		&ntPath,
		OBJ_CASE_INSENSITIVE,
		0,
		0
	};

	NTSTATUS status = NtCreateFile(&fileHandle,
		GENERIC_READ | SYNCHRONIZE | 0x80,
		&ObjectAttributes,
		&IoStatusBlock,
		0,
		FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN_IF,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0
	);

	if (!NT_SUCCESS(status))
	{
		printf("%s: %s failed with status %lx", __FUNCTION__, "NtCreateFile", status);
		return status;
	}

	BYTE readBuffer[64];

	memset(readBuffer, 0, sizeof(readBuffer));

	status = NtReadFile(fileHandle,
		0,
		0,
		0,
		&IoStatusBlock,
		readBuffer,
		sizeof(readBuffer),
		0,
		0
	);

	if (!NT_SUCCESS(status))
	{
		printf("%s: %s failed with status %lx", __FUNCTION__, "NtReadFile", status);
		return status;
	}

	DumpHex(readBuffer, sizeof(readBuffer));

	status = NtClose(fileHandle);

	return status;
}

int main(int argv, char* argc[])
{
	wchar_t fileDir[MAX_PATH];

	memset(fileDir, 0, sizeof(fileDir));

	if (!GetTempPathW(MAX_PATH, fileDir))
	{
		printf("failed to get temp directory\n");
		return 0;
	}

	wcscat(fileDir, L"testfile.dat");

	wchar_t universalNtPath[MAX_PATH];

	memset(universalNtPath, 0, sizeof(universalNtPath));

	wcscat(universalNtPath, L"\\??\\");
	wcscat(universalNtPath, fileDir);

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

	NTSTATUS status = NtCreateFile(&fileHandle,
		GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE | 0x80,
		&objectAttributes,
		&ioStatusBlock,
		0,
		FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OVERWRITE_IF,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0
	);

	if (!NT_SUCCESS(status))
	{
		printf("%s failed with status %lx", "NtCreateFile", status);
		return status;
	}

	BYTE writeBuffer[] = { "this is a test file" };

	status = NtWriteFile(fileHandle,
		0,
		0,
		0,
		&ioStatusBlock,
		writeBuffer,
		sizeof(writeBuffer),
		0,
		0
	);

	if (!NT_SUCCESS(status))
	{
		printf("%s failed with status %lx", "NtWriteFile", status);
		return status;
	}

	status = NtClose(fileHandle);

	if (!NT_SUCCESS(status))
	{
		printf("%s failed with status %lx", "NtClose", status);
		return status;
	}

	fileHandle = INVALID_HANDLE_VALUE;

	if (!NT_SUCCESS(status))
	{
		printf("%s failed with status %lx", "NtWriteFile", status);
		return status;
	}

	printf("original text:\n");

	status = ReadAndPrintFile(fileDir);

	if (!NT_SUCCESS(status))
		return status;

	HANDLE transactionHandle = INVALID_HANDLE_VALUE;

	status = NtCreateTransaction(&transactionHandle,
		SYNCHRONIZE | STANDARD_RIGHTS_REQUIRED | FILE_READ_EA | FILE_WRITE_EA | FILE_EXECUTE | FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0
	);

	if (!NT_SUCCESS(status))
	{
		printf("%s failed with status %lx", "NtCreateTransaction", status);
		return status;
	}

	status = RtlSetCurrentTransaction(transactionHandle);

	if (!NT_SUCCESS(status))
	{
		printf("%s failed with status %lx", "RtlSetCurrentTransaction", status);
		return status;
	}

	status = NtCreateFile(&fileHandle,
		GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE | 0x80,
		&objectAttributes,
		&ioStatusBlock,
		0,
		FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OVERWRITE_IF,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0
	);

	if (!NT_SUCCESS(status))
	{
		printf("%s failed with status %lx", "NtCreateFile", status);
		return status;
	}

	BYTE buffer[] = { "this will be removed" };

	status = NtWriteFile(fileHandle,
		0,
		0,
		0,
		&ioStatusBlock,
		buffer,
		sizeof(buffer),
		0,
		0
	);

	if (!NT_SUCCESS(status))
	{
		printf("%s failed with status %lx", "NtWriteFile", status);
		return status;
	}

	status = NtClose(fileHandle);

	if (!NT_SUCCESS(status))
	{
		printf("%s failed with status %lx", "NtClose", status);
		return status;
	}

	printf("\ntransacted text:\n");

	status = ReadAndPrintFile(fileDir);

	if (!NT_SUCCESS(status))
		return status;

	// NOTE: NtCommitTransaction will commit/save any modifications to the file
	/*status = NtCommitTransaction(transactionHandle, TRUE);

	if (!NT_SUCCESS(status))
	{
		printf("%s failed with status %lx", "NtRollbackTransaction", status);
		return status;
	}*/

	// NOTE: NtRollbackTransaction will rollback/remove any modifications to the file
	status = NtRollbackTransaction(transactionHandle, TRUE);

	if (!NT_SUCCESS(status))
	{
		printf("%s failed with status %lx", "NtRollbackTransaction", status);
		return status;
	}

	status = NtClose(transactionHandle);

	if (!NT_SUCCESS(status))
	{
		printf("%s failed with status %lx", "NtClose", status);
		return status;
	}

	// NOTE: reset transaction handle
	status = RtlSetCurrentTransaction(0);

	if (!NT_SUCCESS(status))
	{
		printf("%s failed with status %lx", "RtlSetCurrentTransaction", status);
		return status;
	}

	printf("\nrollback text:\n");

	status = ReadAndPrintFile(fileDir);

	if (!NT_SUCCESS(status))
		return status;

	status = NtDeleteFile(&objectAttributes);

	if (!NT_SUCCESS(status))
	{
		printf("%s failed with status %lx", "NtDeleteFile", status);
		return status;
	}

	return 0;
}

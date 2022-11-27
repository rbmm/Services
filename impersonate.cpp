#include "stdafx.h"

_NT_BEGIN

#include "impersonate.h"

extern const SECURITY_QUALITY_OF_SERVICE sqos = {
	sizeof (sqos), SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE
};

extern const OBJECT_ATTRIBUTES oa_sqos = { sizeof(oa_sqos), 0, 0, 0, 0, const_cast<SECURITY_QUALITY_OF_SERVICE*>(&sqos) };

BEGIN_PRIVILEGES(tp_Debug, 3)
	LAA(SE_DEBUG_PRIVILEGE),
	LAA(SE_IMPERSONATE_PRIVILEGE),
	LAA(SE_TAKE_OWNERSHIP_PRIVILEGE),
END_PRIVILEGES

NTSTATUS RtlRevertToSelf()
{
	HANDLE hToken = 0;
	return NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
}

NTSTATUS GetToken(_In_ PVOID buf, _In_ const TOKEN_PRIVILEGES* RequiredSet, _Out_ PHANDLE phToken)
{
	NTSTATUS status;

	union {
		PVOID pv;
		PBYTE pb;
		PSYSTEM_PROCESS_INFORMATION pspi;
	};

	pv = buf;
	ULONG NextEntryOffset = 0;

	do 
	{
		pb += NextEntryOffset;

		HANDLE hProcess, hToken, hNewToken;

		CLIENT_ID ClientId = { pspi->UniqueProcessId };

		if (ClientId.UniqueProcess)
		{
			if (0 <= NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, 
				const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), &ClientId))
			{
				status = NtOpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);

				NtClose(hProcess);

				if (0 <= status)
				{
					status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES|TOKEN_IMPERSONATE|TOKEN_QUERY, 
						const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), FALSE, TokenImpersonation, &hNewToken);

					NtClose(hToken);

					if (0 <= status)
					{
						status = NtAdjustPrivilegesToken(hNewToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(RequiredSet), 0, 0, 0);

						if (STATUS_SUCCESS == status)	
						{
							*phToken = hNewToken;
							return STATUS_SUCCESS;
						}

						NtClose(hNewToken);
					}
				}
			}
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS AdjustPrivileges()
{
	NTSTATUS status;
	HANDLE hToken;

	if (0 <= (status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)))
	{
		status = NtAdjustPrivilegesToken(hToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(&tp_Debug), 0, 0, 0);

		NtClose(hToken);
	}

	return status;
}

NTSTATUS GetToken(_In_ const TOKEN_PRIVILEGES* RequiredSet, _Out_ PHANDLE phToken)
{
	NTSTATUS status;

	ULONG cb = 0x40000;

	do 
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (PBYTE buf = new BYTE[cb += PAGE_SIZE])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cb, &cb)))
			{
				status = GetToken(buf, RequiredSet, phToken);

				if (status == STATUS_INFO_LENGTH_MISMATCH)
				{
					status = STATUS_UNSUCCESSFUL;
				}
			}

			delete [] buf;
		}

	} while(status == STATUS_INFO_LENGTH_MISMATCH);

	return status;
}

_NT_END
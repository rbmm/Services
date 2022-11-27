#include "stdafx.h"

_NT_BEGIN

#include "impersonate.h"

extern volatile const UCHAR guz;

struct SID6 : public SID {
	DWORD SubAuthority[5];
};

struct SID2 : public SID {
	DWORD SubAuthority[1];
};

const SID6 TrustedInstallerSid = {
	{ 
		SID_REVISION, SECURITY_SERVICE_ID_RID_COUNT, SECURITY_NT_AUTHORITY, { SECURITY_SERVICE_ID_BASE_RID } 
	},
	{ 
		SECURITY_TRUSTED_INSTALLER_RID1, 
			SECURITY_TRUSTED_INSTALLER_RID2, 
			SECURITY_TRUSTED_INSTALLER_RID3, 
			SECURITY_TRUSTED_INSTALLER_RID4, 
			SECURITY_TRUSTED_INSTALLER_RID5, 
	}
};

const SID2 AdministratorsSid = {
	{ 
		SID_REVISION, 2, SECURITY_NT_AUTHORITY, { SECURITY_BUILTIN_DOMAIN_RID } 
	},
	{ 
		DOMAIN_ALIAS_RID_ADMINS, 
	}
};

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtCreateToken(
	_Out_ PHANDLE  	TokenHandle,
	_In_ ACCESS_MASK  	DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES  	ObjectAttributes,
	_In_ TOKEN_TYPE  	TokenType,
	_In_ PLUID  	AuthenticationId,
	_In_ PLARGE_INTEGER  	ExpirationTime,
	_In_ PTOKEN_USER  	User,
	_In_ PTOKEN_GROUPS  	Groups,
	_In_ PTOKEN_PRIVILEGES  	Privileges,
	_In_opt_ PTOKEN_OWNER  	Owner,
	_In_ PTOKEN_PRIMARY_GROUP  	PrimaryGroup,
	_In_opt_ PTOKEN_DEFAULT_DACL  	DefaultDacl,
	_In_ PTOKEN_SOURCE  	TokenSource 
	);

HRESULT GetLastHrEx(BOOL fOk)
{
	if (fOk)
	{
		return S_OK;
	}
	ULONG dwError = GetLastError();
	NTSTATUS status = RtlGetLastNtStatus();
	return RtlNtStatusToDosErrorNoTeb(status) == dwError ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

NTSTATUS SetTrustedToken(_In_ HANDLE hToken, _In_ PSID Sid)
{
	NTSTATUS status;
	PVOID stack = alloca(guz);
	PVOID buf = 0;

	ULONG cb = 0, rcb;

	struct {
		PTOKEN_GROUPS ptg; // must be first
		PTOKEN_DEFAULT_DACL ptdd;
	} s;

	void** ppv = (void**)&s.ptdd;

	static const ULONG rcbV[] = {
		sizeof(TOKEN_GROUPS)+0x80, // must be first
		sizeof(TOKEN_DEFAULT_DACL)+0x40,
	};

	static TOKEN_INFORMATION_CLASS TokenInformationClassV[] = { 
		TokenGroups, 
		TokenDefaultDacl, 
	};

	ULONG n = _countof(TokenInformationClassV);

	BEGIN_PRIVILEGES(tp, 7)
		LAA(SE_CREATE_TOKEN_PRIVILEGE),
		LAA(SE_BACKUP_PRIVILEGE),
		LAA(SE_RESTORE_PRIVILEGE),
		LAA(SE_SECURITY_PRIVILEGE),
		LAA(SE_TAKE_OWNERSHIP_PRIVILEGE),
		LAA(SE_CHANGE_NOTIFY_PRIVILEGE),
		LAA(SE_IMPERSONATE_PRIVILEGE),
	END_PRIVILEGES	

	do 
	{
		TOKEN_INFORMATION_CLASS TokenInformationClas = TokenInformationClassV[--n];

		rcb = rcbV[n], cb = 0;

		do 
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			status = NtQueryInformationToken(hToken, TokenInformationClas, buf, cb, &rcb);

		} while (status == STATUS_BUFFER_TOO_SMALL);

		if (0 > status)
		{
			return status;
		}

		*(ppv--) = buf, stack = buf;

	} while (n);

	if (!RtlEqualSid(Sid, const_cast<SID*>(static_cast<const SID*>(&TrustedInstallerSid))))
	{
		// reserve stack space for extend groups
		alloca(sizeof(SID_AND_ATTRIBUTES));
		PSID_AND_ATTRIBUTES Groups = s.ptg->Groups - 1;
		ULONG GroupCount = s.ptg->GroupCount + 1;
		s.ptg = CONTAINING_RECORD(Groups, TOKEN_GROUPS, Groups);
		s.ptg->GroupCount = GroupCount;

		Groups->Sid = const_cast<SID*>(static_cast<const SID*>(&TrustedInstallerSid));
		Groups->Attributes = SE_GROUP_ENABLED|SE_GROUP_ENABLED_BY_DEFAULT|SE_GROUP_OWNER;
	}

	TOKEN_USER tu = {{ Sid }};
	const static TOKEN_OWNER to = { const_cast<SID*>(static_cast<const SID*>(&TrustedInstallerSid)) };
	const static LUID AuthenticationId = SYSTEM_LUID;
	const static LARGE_INTEGER ExpirationTime = { MAXULONG, MAXLONG };
	const static TOKEN_SOURCE ts = {{ '*', 'S', 'Y', 'S', 'T', 'E', 'M', '*' }};

	if (0 <= (status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken))))
	{
		if (0 <= (status = NtCreateToken(&hToken, TOKEN_ALL_ACCESS, 
			const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), TokenImpersonation, 
			const_cast<PLUID>(&AuthenticationId), const_cast<PLARGE_INTEGER>(&ExpirationTime), 
			&tu, s.ptg, const_cast<PTOKEN_PRIVILEGES>(&tp), 
			const_cast<PTOKEN_OWNER>(&to), (PTOKEN_PRIMARY_GROUP)&to, s.ptdd, const_cast<PTOKEN_SOURCE>(&ts))))
		{
			status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
			NtClose(hToken);
		}

		if (0 > status)
		{
			RtlRevertToSelf();
		}
	}

	return status;
}

HRESULT SetTokenForService(_In_ SC_HANDLE hService, _In_ HANDLE hSystemToken, _In_ ULONG Mask)
{
	ULONG dwError;

	PVOID stack = alloca(guz);

	union {
		PVOID buf;
		PSECURITY_DESCRIPTOR lpSecurityDescriptor;
	};

	ULONG cb = 0, rcb = 0x100;
	do 
	{
		if (cb < rcb)
		{
			cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
		}

		dwError = BOOL_TO_ERROR(QueryServiceObjectSecurity(hService, 
			DACL_SECURITY_INFORMATION|OWNER_SECURITY_INFORMATION, 
			lpSecurityDescriptor, cb, &rcb));

	} while (dwError == ERROR_INSUFFICIENT_BUFFER);

	if (dwError == NOERROR)
	{
		dwError = ERROR_NOT_FOUND;

		BOOLEAN bpresent, bDefaulted;
		union {
			PACL Dacl;
			PSID Owner;
		};
		NTSTATUS status;

		if (0 <= RtlGetDaclSecurityDescriptor(lpSecurityDescriptor, &bpresent, &Dacl, &bDefaulted) && bpresent && Dacl)
		{
			if (USHORT AceCount = Dacl->AceCount)
			{
				union {
					PACCESS_ALLOWED_ACE pAce;
					PACE_HEADER pHead;
					PVOID pv;
					PBYTE pb;
				};

				pv = ++Dacl;

				do
				{
					if (pHead->AceType == ACCESS_ALLOWED_ACE_TYPE)
					{
						if ((pAce->Mask & Mask) == Mask)
						{
							if (0 > (status = SetTrustedToken(hSystemToken, &pAce->SidStart)))
							{
								dwError = HRESULT_FROM_NT(status);
							}
							else
							{
								dwError = NOERROR;
							}
							break;
						}
					}

				} while (pb += pHead->AceSize, --AceCount);
			}
		}

		if (ERROR_NOT_FOUND == dwError && (Mask & WRITE_DAC) &&
			(0 <= RtlGetOwnerSecurityDescriptor(lpSecurityDescriptor, &Owner, &bDefaulted)) && Owner)
		{
			if (0 > (status = SetTrustedToken(hSystemToken, Owner)))
			{
				dwError = HRESULT_FROM_NT(status);
			}
			else
			{
				dwError = NOERROR;
			}
		}
	}

	return HRESULT_FROM_WIN32(dwError);
}

HRESULT SetTokenForService(_In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName, _In_ HANDLE hSystemToken, _In_ ULONG Mask)
{
	ULONG dwError;

	if (SC_HANDLE hService = OpenServiceW(hSCManager, lpServiceName, READ_CONTROL))
	{
		dwError = SetTokenForService(hService, hSystemToken, Mask);

		CloseServiceHandle(hService);
	}
	else
	{
		dwError = GetLastError();
	}

	return HRESULT_FROM_WIN32(dwError);
}

_NT_END
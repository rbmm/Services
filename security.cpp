#include "stdafx.h"

_NT_BEGIN

#include <ntlsa.h>
HMODULE GetNtMod();

class WLog
{
	PVOID _BaseAddress;
	ULONG _RegionSize, _Ptr;
	BOOL bShift;

	PWSTR _buf()
	{
		return (PWSTR)((PBYTE)_BaseAddress + _Ptr);
	}

	ULONG _cch()
	{
		return (_RegionSize - _Ptr) / sizeof(WCHAR);
	}

public:

	BOOL IsShift()
	{
		return bShift;
	}

	void operator >> (HWND hwnd)
	{
		PVOID pv = (PVOID)SendMessage(hwnd, EM_GETHANDLE, 0, 0);
		SendMessage(hwnd, EM_SETHANDLE, (WPARAM)_BaseAddress, 0);
		_BaseAddress = 0;
		if (pv)
		{
			LocalFree(pv);
		}
	}

	ULONG Init(SIZE_T RegionSize)
	{
		if (_BaseAddress = LocalAlloc(0, RegionSize))
		{
			_RegionSize = (ULONG)RegionSize, _Ptr = 0;
			return NOERROR;
		}
		return GetLastError();
	}

	~WLog()
	{
		if (_BaseAddress)
		{
			LocalFree(_BaseAddress);
		}
	}

	WLog(WLog&&) = delete;
	WLog(WLog&) = delete;
	WLog(BOOL bShift): _BaseAddress(0), bShift(bShift) {  }

	operator PCWSTR()
	{
		return (PCWSTR)_BaseAddress;
	}

	WLog& operator <<(PCWSTR str)
	{
		if (!wcscpy_s(_buf(), _cch(), str))
		{
			_Ptr += (ULONG)wcslen(_buf()) * sizeof(WCHAR);
		}
		return *this;
	}

	WLog& operator ()(PCWSTR format, ...)
	{
		va_list args;
		va_start(args, format);

		int len = _vsnwprintf_s(_buf(), _cch(), _TRUNCATE, format, args);

		if (0 < len)
		{
			_Ptr += len * sizeof(WCHAR);
		}

		va_end(args);

		return *this;
	}

	WLog& operator[](HRESULT dwError)
	{
		LPCVOID lpSource = 0;
		ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS;

		if (dwError & FACILITY_NT_BIT)
		{
			dwError &= ~FACILITY_NT_BIT;
			dwFlags = FORMAT_MESSAGE_FROM_HMODULE|FORMAT_MESSAGE_IGNORE_INSERTS;
			lpSource = GetNtMod();
		}

		if (dwFlags = FormatMessageW(dwFlags, lpSource, dwError, 0, _buf(), _cch(), 0))
		{
			_Ptr += dwFlags * sizeof(WCHAR);
		}
		return *this;
	}
};

extern volatile const UCHAR guz;
//#pragma warning(disable)
const static UNICODE_STRING emptyUS{};
const static OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };

PCSTR GetSidNameUseName(SID_NAME_USE snu)
{
	switch (snu)
	{
	case SidTypeUser: return "User";
	case SidTypeGroup: return "Group";
	case SidTypeDomain: return "Domain";
	case SidTypeAlias: return "Alias";
	case SidTypeWellKnownGroup: return "WellKnownGroup";
	case SidTypeDeletedAccount: return "DeletedAccount";
	case SidTypeInvalid: return "Invalid";
	case SidTypeUnknown: return "Unknown";
	case SidTypeComputer: return "Computer";
	case SidTypeLabel: return "Label";
	case SidTypeLogonSession: return "LogonSession";
	}
	return "?";
}

class LSA_LOOKUP
{
	LSA_HANDLE PolicyHandle;
public:
	LSA_LOOKUP()
	{
		LSA_OBJECT_ATTRIBUTES ObjectAttributes = { sizeof(ObjectAttributes) };

		if (0 > LsaOpenPolicy(0, &ObjectAttributes, POLICY_LOOKUP_NAMES, &PolicyHandle))
		{
			PolicyHandle = 0;
		}
	}

	~LSA_LOOKUP()
	{
		if (PolicyHandle)
		{
			LsaClose(PolicyHandle);
		}
	}

	LSA_LOOKUP_HANDLE operator()()
	{
		return PolicyHandle;
	}
};

NTSTATUS DumpGroups(WLog& log, LSA_LOOKUP_HANDLE PolicyHandle, PTOKEN_GROUPS ptg)
{
	ULONG GroupCount = ptg->GroupCount;

	if (!GroupCount)
	{
		return STATUS_SUCCESS;
	}

	PSID* Sids = (PSID*)alloca(GroupCount * sizeof(PSID)), *pSid = Sids;

	ULONG n = GroupCount;

	PSID_AND_ATTRIBUTES Groups = ptg->Groups;
	do 
	{
		*pSid++ = Groups++->Sid;
	} while (--n);

	PLSA_TRANSLATED_NAME Names = 0;
	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains = 0;

	ULONG Entries = 0;
	PLSA_TRUST_INFORMATION Domains = 0;

	NTSTATUS status = PolicyHandle ? 
		LsaLookupSids(PolicyHandle, GroupCount, Sids, &ReferencedDomains, &Names) : STATUS_INVALID_HANDLE;

	if (ReferencedDomains)
	{
		Entries = ReferencedDomains->Entries;
		Domains = ReferencedDomains->Domains;
	}

	PVOID bufNames = Names;

	UNICODE_STRING StringSid;
	Groups = ptg->Groups;
	do 
	{
		if (0 > RtlConvertSidToUnicodeString(&StringSid, Groups->Sid, TRUE))
		{
			StringSid.Length = 0;
			StringSid.Buffer = 0;
		}

		PCUNICODE_STRING Name = &emptyUS;
		PCUNICODE_STRING Domain = &emptyUS;
		SID_NAME_USE Use = SidTypeUnknown;

		if (Names)
		{
			ULONG DomainIndex = Names->DomainIndex;

			if (DomainIndex < Entries)
			{
				Domain = &Domains[DomainIndex].Name;
			}

			Name = &Names->Name;
			Use = Names++->Use;
		}

		if (ULONG Attributes = Groups->Attributes)
		{
			char sz[10];

			sz[0] = Attributes & SE_GROUP_MANDATORY ? 'M' : ' ';
			sz[1] = Attributes & SE_GROUP_ENABLED ? 'E' : ' ';
			sz[2] = Attributes & SE_GROUP_ENABLED_BY_DEFAULT ? '+' : ' ';
			sz[3] = Attributes & SE_GROUP_OWNER ? 'O' : ' ';
			sz[4] = Attributes & SE_GROUP_USE_FOR_DENY_ONLY ? 'D' : ' ';
			sz[5] = Attributes & SE_GROUP_INTEGRITY ? 'I' : ' ';
			sz[6] = Attributes & SE_GROUP_INTEGRITY_ENABLED ? '+' : ' ';
			sz[7] = Attributes & SE_GROUP_LOGON_ID ? 'L' : ' ';
			sz[8] = Attributes & SE_GROUP_RESOURCE ? 'R' : ' ';
			sz[9] = 0;

			switch (Use)
			{
			case SidTypeInvalid: 
			case SidTypeUnknown:
				log(L"%08X %S [%wZ] [%S]\r\n", 
					Attributes, sz, &StringSid, GetSidNameUseName(Use));
				break;
			default:
				log(L"%08X %S [%wZ] '%wZ\\%wZ' [%S]\r\n", 
					Attributes, sz, &StringSid, Domain, Name, GetSidNameUseName(Use));
			}
		}
		else
		{
			switch (Use)
			{
			case SidTypeInvalid: 
			case SidTypeUnknown:
				log(L"[%wZ] [%S]\r\n", 
					&StringSid, GetSidNameUseName(Use));
				break;
			default:
				log(L"[%wZ] '%wZ\\%wZ' [%S]\r\n", 
					&StringSid, Domain, Name, GetSidNameUseName(Use));
			}
		}

		RtlFreeUnicodeString(&StringSid);

	} while (Groups++, --GroupCount);

	if (ReferencedDomains) LsaFreeMemory(ReferencedDomains);
	if (bufNames) LsaFreeMemory(bufNames);

	return status;
}

PSID GetSidFromACE(PACE_HEADER ph)
{
	if ((ULONG)ph->AceType - ACCESS_MIN_MS_OBJECT_ACE_TYPE <= 
		ACCESS_MAX_MS_OBJECT_ACE_TYPE - ACCESS_ALLOWED_OBJECT_ACE_TYPE)
	{
		switch (reinterpret_cast<PACCESS_ALLOWED_OBJECT_ACE>(ph)->Flags & (ACE_OBJECT_TYPE_PRESENT|ACE_INHERITED_OBJECT_TYPE_PRESENT))
		{
		case 0:
			return &reinterpret_cast<PACCESS_ALLOWED_OBJECT_ACE>(ph)->ObjectType;
		case ACE_OBJECT_TYPE_PRESENT:
		case ACE_INHERITED_OBJECT_TYPE_PRESENT:
			return &reinterpret_cast<PACCESS_ALLOWED_OBJECT_ACE>(ph)->InheritedObjectType;
			//case ACE_OBJECT_TYPE_PRESENT|ACE_INHERITED_OBJECT_TYPE_PRESENT:
		default:
			return &reinterpret_cast<PACCESS_ALLOWED_OBJECT_ACE>(ph)->SidStart;
		}
	}

	return &reinterpret_cast<PACCESS_ALLOWED_ACE>(ph)->SidStart;
}

NTSTATUS DumpACEList(WLog& log, LSA_LOOKUP_HANDLE PolicyHandle, ULONG AceCount, PVOID FirstAce)
{
	union {
		PVOID pv;
		PBYTE pb;
		PACE_HEADER ph;
		PACCESS_ALLOWED_ACE pah;
	};

	pv = FirstAce;

	PSID* Sids = (PSID*)alloca(AceCount * sizeof(PSID)), *pSid = Sids, Sid;

	ULONG SidCount = 0, n = AceCount;

	do 
	{
		if (RtlValidSid(Sid = GetSidFromACE(ph)))
		{
			*pSid++ = Sid;
			SidCount++;
		}
		pb += ph->AceSize;
	} while (--n);

	pv = FirstAce;

	PLSA_TRANSLATED_NAME Names = 0;
	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains = 0;

	ULONG Entries = 0;
	PLSA_TRUST_INFORMATION Domains = 0;

	NTSTATUS status = PolicyHandle ? 
		LsaLookupSids (PolicyHandle, SidCount, Sids, &ReferencedDomains, &Names) : STATUS_INVALID_HANDLE;

	if (ReferencedDomains)
	{
		Entries = ReferencedDomains->Entries;
		Domains = ReferencedDomains->Domains;
	}
	PVOID bufNames = Names;

	char sz[16], sz2[16];

	UNICODE_STRING StringSid = {};

	do
	{
		if (!RtlValidSid(Sid = GetSidFromACE(ph)))
		{
			continue;
		}

		PCUNICODE_STRING Name = &emptyUS;
		PCUNICODE_STRING Domain = &emptyUS;
		SID_NAME_USE Use = SidTypeUnknown;

		if (Names)
		{
			ULONG DomainIndex = Names->DomainIndex;

			if (DomainIndex < Entries)
			{
				Domain = &Domains[DomainIndex].Name;
			}

			Name = &Names->Name;
			Use = Names++->Use;
		}

		ACCESS_MASK Mask = pah->Mask;
		sprintf_s(sz2, _countof(sz2), "%08X", Mask);

		switch (pah->Header.AceType)
		{
		case ACCESS_ALLOWED_ACE_TYPE:
			sz[0] = 'A', sz[1] = 0;
			break;
		case ACCESS_DENIED_ACE_TYPE:
			sz[0] = 'D', sz[1] = 0;
			break;
		case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
			sz[0] = 'L', sz[1] = 0;
			sz2[0] = Mask & SYSTEM_MANDATORY_LABEL_NO_READ_UP ? 'R' : ' ';
			sz2[1] = Mask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP ? 'W' : ' ';
			sz2[2] = Mask & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP ? 'E' : ' ';
			sz2[3] = 0;
			break;
		default:
			sprintf_s(sz, _countof(sz), "0x%x", pah->Header.AceType);
		}

		if (0 > RtlConvertSidToUnicodeString(&StringSid, Sid, TRUE))
		{
			StringSid.Length = 0;
			StringSid.Buffer = 0;
		}

		switch (Use)
		{
		case SidTypeInvalid: 
		case SidTypeUnknown:
			log(L"%S %02X %S [%wZ] [%S]\r\n", sz, ph->AceFlags, sz2, 
				&StringSid, GetSidNameUseName(Use));
			break;
		default:
			log(L"%S %02X %S [%wZ] '%wZ\\%wZ' [%S]\r\n", sz, ph->AceFlags, sz2, 
				&StringSid, Domain, Name, GetSidNameUseName(Use));
		}

		RtlFreeUnicodeString(&StringSid);

		if (log.IsShift())
		{
			if (Mask & 0x00000001) log << L"\tQUERY_CONFIG\r\n";
			if (Mask & 0x00000002) log << L"\tCHANGE_CONFIG\r\n";
			if (Mask & 0x00000004) log << L"\tQUERY_STATUS\r\n";
			if (Mask & 0x00000008) log << L"\tENUMERATE_DEPENDENTS\r\n";
			if (Mask & 0x00000010) log << L"\tSTART\r\n";
			if (Mask & 0x00000020) log << L"\tSTOP\r\n";
			if (Mask & 0x00000040) log << L"\tPAUSE_CONTINUE\r\n";
			if (Mask & 0x00000080) log << L"\tINTERROGATE\r\n";
			if (Mask & 0x00000100) log << L"\tUSER_DEFINED_CONTROL\r\n";
			if (Mask & 0x00010000) log << L"\tDELETE\r\n";
			if (Mask & 0x00020000) log << L"\tREAD_CONTROL\r\n";
			if (Mask & 0x00040000) log << L"\tWRITE_DAC\r\n";
			if (Mask & 0x00080000) log << L"\tWRITE_OWNER\r\n";
			if (Mask & 0x00100000) log << L"\tSYNCHRONIZE\r\n";
			log << L"\r\n";
		}

	} while (pb += ph->AceSize, --AceCount);

	if (ReferencedDomains) LsaFreeMemory(ReferencedDomains);
	if (bufNames) LsaFreeMemory(bufNames);

	return status;
}

void DumpSid(WLog& log, LSA_LOOKUP_HANDLE PolicyHandle, PCWSTR Prefix, PSID Sid)
{
	log(Prefix);
	TOKEN_GROUPS tg = { 1, { { Sid, 0 }} };
	DumpGroups(log, PolicyHandle, &tg);
}

void DumpAcl(WLog& log, LSA_LOOKUP_HANDLE PolicyHandle, PACL acl, PCWSTR caption)
{
	log(caption);

	if (!acl)
	{
		log(L"NULL\r\n");
		return;
	}

	if (!acl->AceCount)
	{
		log(L"empty\r\n");
		return;
	}

	log(L"T FL AcessMsK Sid\r\n");

	DumpACEList(log, PolicyHandle, acl->AceCount, acl + 1);
}

#undef _NTDDK_
#include <sddl.h>

void DumpObjectSecurity(WLog& log, LSA_LOOKUP_HANDLE PolicyHandle, _In_ SC_HANDLE hService)
{
	ULONG cb = 0, rcb = 512;

	PVOID stack = alloca(guz);

	union {
		PVOID buf;
		PSECURITY_DESCRIPTOR psd;
	};

	NTSTATUS status;
	do 
	{
		if (cb < rcb)
		{
			cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
		}

		if (QueryServiceObjectSecurity(hService, 
			OWNER_SECURITY_INFORMATION|
			DACL_SECURITY_INFORMATION|
			LABEL_SECURITY_INFORMATION,
			psd, cb, &rcb))
		{
			status = 0;

			PWSTR sz;
			if (ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION, 
				OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION, &sz, &rcb))
			{
				log(L"%s\r\n\r\n", sz);
				LocalFree(sz);
			}

			PACL Acl;
			BOOLEAN bPresent, bDefault;

			if (0 <= RtlGetDaclSecurityDescriptor(psd, &bPresent, &Acl, &bDefault))
			{
				DumpAcl(log, PolicyHandle, bPresent ? Acl : 0, L"DACL:\r\n");
			}

			if (0 <= RtlGetSaclSecurityDescriptor(psd, &bPresent, &Acl, &bDefault))
			{
				DumpAcl(log, PolicyHandle, bPresent ? Acl : 0, L"LABEL:\r\n");
			}

			PSID Owner;
			if (0 <= RtlGetOwnerSecurityDescriptor(psd, &Owner, &bDefault) && Owner)
			{
				DumpSid(log, PolicyHandle, L"Owner: ", Owner);
			}
		}
		else
		{
			status = GetLastError();
			log[status];
		}

	} while (status == ERROR_INSUFFICIENT_BUFFER);
}

void ShowSD(_In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName, _In_ HWND hwndParent, _In_ HFONT hFont, _In_ BOOL bShift)
{
	if (HWND hwnd = CreateWindowExW(0, WC_EDIT, lpServiceName, WS_OVERLAPPEDWINDOW|WS_VSCROLL|ES_MULTILINE,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hwndParent, 0, 0, 0))
	{
		SendMessage(hwnd, WM_SETFONT, (WPARAM)hFont, 0);

		WLog log(bShift);

		if (!log.Init(0x10000))
		{
			LSA_LOOKUP ll;
			if (SC_HANDLE hService = OpenServiceW(hSCManager, lpServiceName, READ_CONTROL ))
			{
				DumpObjectSecurity(log, ll(), hService);
				CloseServiceHandle(hService);
			}
			else
			{
				log[GetLastError()];
			}
			log >> hwnd;
		}

		ShowWindow(hwnd, SW_SHOWNORMAL);
	}
}

_NT_END
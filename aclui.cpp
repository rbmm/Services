#include "stdafx.h"
#include <Aclui.h>

_NT_BEGIN

#include "impersonate.h"

#define SERVICE_GENERIC_READ	STANDARD_RIGHTS_READ | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS
#define SERVICE_GENERIC_WRITE	STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG
#define SERVICE_GENERIC_EXECUTE	STANDARD_RIGHTS_EXECUTE | SERVICE_START | SERVICE_STOP |SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL

class CSecurityInformation : public ISecurityInformation
{
	SC_HANDLE _hService;
	PCWSTR _lpServiceName;
	HANDLE _hSystemToken;
	BOOL _bRevert;
	LONG _dwRef = 1;

	~CSecurityInformation()
	{
		if (SC_HANDLE hService = _hService)
		{
			CloseServiceHandle(hService);
		}

		if (_bRevert)
		{
			RtlRevertToSelf();
		}
	}

public:

	HRESULT Init(_In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName, _In_ HANDLE hSystemToken)
	{
		ULONG dwDesiredAccess = READ_CONTROL|WRITE_DAC|WRITE_OWNER;

		if (0 <= SetTokenForService(hSCManager, lpServiceName, hSystemToken, READ_CONTROL|WRITE_DAC|WRITE_OWNER))
		{
			_bRevert = TRUE;
		}
		else
		{
			dwDesiredAccess = READ_CONTROL|WRITE_OWNER;
		}

		if (SC_HANDLE hService = OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess))
		{
			_hService = hService, _lpServiceName = lpServiceName, _hSystemToken = hSystemToken;
			return S_OK;
		}

		return GetLastHr();
	}

	// *** IUnknown methods ***
	virtual HRESULT STDAPICALLTYPE QueryInterface(_In_ REFIID riid, _Outptr_ void **ppvObj)
	{
		if (riid == __uuidof(IUnknown) || riid == __uuidof(ISecurityInformation))
		{
			*ppvObj = static_cast<ISecurityInformation*>(this);
			AddRef();
			return S_OK;
		}

		return E_NOINTERFACE;
	}

	virtual ULONG STDAPICALLTYPE AddRef()
	{
		return InterlockedIncrementNoFence(&_dwRef);
	}

	virtual ULONG STDAPICALLTYPE Release()
	{
		ULONG dwRef = InterlockedDecrement(&_dwRef);
		if (!dwRef)
		{
			delete this;
		}
		return dwRef;
	}

	// *** ISecurityInformation methods ***
	virtual HRESULT STDAPICALLTYPE GetObjectInformation ( PSI_OBJECT_INFO pObjectInfo )
	{
		RtlZeroMemory(pObjectInfo, sizeof(SI_OBJECT_INFO));
		pObjectInfo->dwFlags = SI_ADVANCED|SI_EDIT_OWNER;
		pObjectInfo->pszObjectName = const_cast<PWSTR>(_lpServiceName);
		return S_OK;
	}
	
	virtual HRESULT STDAPICALLTYPE GetSecurity (SECURITY_INFORMATION RequestedInformation,
		PSECURITY_DESCRIPTOR *ppSecurityDescriptor,
		BOOL /*fDefault*/ )
	{
		ULONG dwError, cb = 0x100;
		do 
		{

			if (PSECURITY_DESCRIPTOR pSecurityDescriptor = LocalAlloc(0, cb))
			{
				if (NOERROR == (dwError = BOOL_TO_ERROR(QueryServiceObjectSecurity(_hService, 
					RequestedInformation, pSecurityDescriptor, cb, &cb))))
				{
					*ppSecurityDescriptor = pSecurityDescriptor;
					return S_OK;
				}

				LocalFree(pSecurityDescriptor);
			}
			else
			{
				dwError = GetLastError();
				break;
			}

		} while (dwError == ERROR_INSUFFICIENT_BUFFER);

		return HRESULT_FROM_WIN32(dwError);
	}

	virtual HRESULT STDAPICALLTYPE SetSecurity (SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR pSecurityDescriptor )
	{
		return GetLastHr(SetServiceObjectSecurity(_hService, SecurityInformation, pSecurityDescriptor));
	}

	virtual HRESULT STDAPICALLTYPE GetAccessRights ( const GUID* /*pguidObjectType*/,
		DWORD /*dwFlags*/, // SI_EDIT_AUDITS, SI_EDIT_PROPERTIES
		PSI_ACCESS *ppAccess,
		ULONG *pcAccesses,
		ULONG *piDefaultAccess )
	{
		static const SI_ACCESS sa[] = {
			{ 0, SERVICE_QUERY_CONFIG,			L"Query Config",			SI_ACCESS_GENERAL },
			{ 0, SERVICE_CHANGE_CONFIG,			L"Change Config",			SI_ACCESS_GENERAL },
			{ 0, SERVICE_QUERY_STATUS,			L"Query Status",			SI_ACCESS_GENERAL },
			{ 0, SERVICE_ENUMERATE_DEPENDENTS,	L"Enumerate Dependents",	SI_ACCESS_GENERAL },
			{ 0, SERVICE_START,					L"Start",					SI_ACCESS_GENERAL },
			{ 0, SERVICE_STOP,					L"Stop",					SI_ACCESS_GENERAL },
			{ 0, SERVICE_PAUSE_CONTINUE,		L"Pause/Continue",			SI_ACCESS_GENERAL },
			{ 0, SERVICE_INTERROGATE,			L"Interogate",				SI_ACCESS_GENERAL },
			{ 0, SERVICE_USER_DEFINED_CONTROL,	L"User Defined Control",	SI_ACCESS_GENERAL },
			{ 0, DELETE,						L"Delete",					SI_ACCESS_GENERAL },
			{ 0, READ_CONTROL,					L"Read Control",			SI_ACCESS_GENERAL },
			{ 0, WRITE_DAC,						L"Write DAC",				SI_ACCESS_GENERAL },
			{ 0, WRITE_OWNER,					L"Write Owner",				SI_ACCESS_GENERAL },
		};

		*ppAccess = const_cast<SI_ACCESS*>(sa);
		*pcAccesses = _countof(sa);
		*piDefaultAccess = 0;

		return S_OK;
	}

	virtual HRESULT STDAPICALLTYPE MapGeneric (const GUID * /*pguidObjectType*/, UCHAR * /*pAceFlags*/, ACCESS_MASK *pMask)
	{
		static const GENERIC_MAPPING GenericMapping = {
			SERVICE_GENERIC_READ, SERVICE_GENERIC_WRITE, SERVICE_GENERIC_EXECUTE, SERVICE_ALL_ACCESS
		};
		RtlMapGenericMask(pMask, const_cast<GENERIC_MAPPING*>(&GenericMapping));
		return S_OK;
	}

	virtual HRESULT STDAPICALLTYPE GetInheritTypes ( PSI_INHERIT_TYPE *ppInheritTypes, ULONG *pcInheritTypes )
	{
		*ppInheritTypes = 0;
		*pcInheritTypes = 0;
		return S_OK;
	}

	virtual HRESULT STDAPICALLTYPE PropertySheetPageCallback( HWND /*hwnd*/, UINT /*uMsg*/, SI_PAGE_TYPE /*uPage*/ )
	{
		return S_OK;
	}
};

int ShowErrorBox(HWND hwnd, HRESULT dwError, PCWSTR pzCaption, UINT uType = MB_OK);

EXTERN_C PVOID __imp_EditSecurity = 0;

#ifdef _X86_
#pragma comment(linker, "/alternatename:__imp__EditSecurity@8=___imp_EditSecurity")
#endif

void EditServiceSecurity(_In_ HWND hwnd ,_In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName, _In_ HANDLE hSystemToken)
{
	if (!__imp_EditSecurity)
	{
		if (HMODULE hmod = LoadLibraryW(L"Aclui"))
		{
			__imp_EditSecurity = GetProcAddress(hmod, "EditSecurity");
		}

		if (!__imp_EditSecurity)
		{
			return;
		}
	}

	if (CSecurityInformation * psi = new CSecurityInformation{})
	{
		if (HRESULT hr = psi->Init(hSCManager, lpServiceName, hSystemToken))
		{
			ShowErrorBox(hwnd, hr, lpServiceName, MB_ICONHAND);
		}
		else
		{
			EditSecurity(hwnd, psi);
		}
		psi->Release();
	}
}

HRESULT ChangeServiceStartType(_In_ ULONG dwStartType, _In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName, _In_ HANDLE hSystemToken)
{
	HRESULT hr;
	BOOL SecondTry = FALSE, bRevert = FALSE;
__0:
	if (SC_HANDLE hService = OpenServiceW(hSCManager, lpServiceName, SERVICE_CHANGE_CONFIG ))
	{
		hr = BOOL_TO_ERROR(ChangeServiceConfigW(hService, SERVICE_NO_CHANGE, dwStartType, SERVICE_NO_CHANGE, 0, 0, 0, 0, 0, 0, 0));

		CloseServiceHandle(hService);
	}
	else
	{
		hr = GetLastError();
	}

	if (ERROR_ACCESS_DENIED == hr && !SecondTry)
	{
		SecondTry = TRUE;

		if (0 <= (hr = SetTokenForService(hSCManager, lpServiceName, hSystemToken, SERVICE_CHANGE_CONFIG)))
		{
			bRevert = TRUE;
			goto __0;
		}
	}
	if (bRevert) RtlRevertToSelf();
	return HRESULT_FROM_WIN32(hr);
}

HRESULT TryStartService(_In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName, _In_ HANDLE hSystemToken)
{
	HRESULT hr;
	BOOL SecondTry = FALSE, bRevert = FALSE;
__0:
	if (SC_HANDLE hService = OpenServiceW(hSCManager, lpServiceName, SERVICE_START ))
	{
		hr = BOOL_TO_ERROR(StartServiceW(hService, 0, 0));

		CloseServiceHandle(hService);
	}
	else
	{
		hr = GetLastError();
	}

	if (ERROR_ACCESS_DENIED == hr && !SecondTry)
	{
		SecondTry = TRUE;

		if (0 <= (hr = SetTokenForService(hSCManager, lpServiceName, hSystemToken, SERVICE_START)))
		{
			bRevert = TRUE;
			goto __0;
		}
	}

	if (bRevert) RtlRevertToSelf();
	return HRESULT_FROM_WIN32(hr);
}

HRESULT TryControlService(_In_ SC_HANDLE hSCManager, 
						  _In_ PCWSTR lpServiceName, 
						  _In_ DWORD dwControl, 
						  _In_ DWORD dwAccess,
						  _In_ HANDLE hSystemToken)
{
	HRESULT hr;
	BOOL SecondTry = FALSE, bRevert = FALSE;
__0:
	if (SC_HANDLE hService = OpenServiceW(hSCManager, lpServiceName, dwAccess ))
	{
		SERVICE_STATUS ServiceStatus;

		hr = BOOL_TO_ERROR(ControlService(hService, dwControl, &ServiceStatus));

		CloseServiceHandle(hService);
	}
	else
	{
		hr = GetLastError();
	}

	if (ERROR_ACCESS_DENIED == hr && !SecondTry)
	{
		SecondTry = TRUE;

		if (0 <= (hr = SetTokenForService(hSCManager, lpServiceName, hSystemToken, dwAccess)))
		{
			bRevert = TRUE;
			goto __0;
		}
	}

	if (bRevert) RtlRevertToSelf();
	return HRESULT_FROM_WIN32(hr);
}

_NT_END
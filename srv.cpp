#include "stdafx.h"
#include "../NtVer/nt_ver.h"

#include "resource.h"
_NT_BEGIN

#include "../winz/app.h"
#include "../winz/wic.h"
#include "../winz/Frame.h"
#include "..\inc\initterm.h"
#include "impersonate.h"

extern const volatile UCHAR guz = 0;

BEGIN_PRIVILEGES(tp_ctp, 3)
	LAA(SE_CREATE_TOKEN_PRIVILEGE),
	LAA(SE_SECURITY_PRIVILEGE),
	LAA(SE_IMPERSONATE_PRIVILEGE),
END_PRIVILEGES

enum Colum { 
	CID_NAME, CID_START, CID_STATE, CID_TYPE, CID_ID, CID_DNAME, CID_MAX 
};

static const int align[] = { 
	LVCFMT_LEFT, LVCFMT_CENTER, LVCFMT_CENTER, LVCFMT_CENTER, LVCFMT_RIGHT, LVCFMT_LEFT
};

enum { AFX_IDW_STATUS_BAR, ID_LV, ID_COMBO, ID_APPLY };

HMODULE GetNtMod()
{
	static HMODULE s_hntmod;
	if (!s_hntmod)
	{
		s_hntmod = GetModuleHandle(L"ntdll");
	}

	return s_hntmod;
}

int ShowErrorBox(HWND hwnd, HRESULT dwError, PCWSTR pzCaption, UINT uType = MB_OK)
{
	PWSTR psz;
	ULONG dwFlags, errType = uType & MB_ICONMASK;
	HMODULE hmod;	

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
__nt:
		hmod = GetNtMod();
		dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE;

		if (!errType)
		{
			static const UINT s_errType[] = { MB_ICONINFORMATION, MB_ICONINFORMATION, MB_ICONWARNING, MB_ICONERROR };
			uType |= s_errType[(ULONG)dwError >> 30];
		}
	}
	else
	{
		hmod = 0;
		dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM;
		if (!errType)
		{
			uType |= dwError ? MB_ICONERROR : MB_ICONINFORMATION;
		}
	}

	int r = IDCANCEL;
	if (FormatMessageW(dwFlags, hmod, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (PWSTR)&psz, 0, 0))
	{
		r = MessageBoxW(hwnd, psz, pzCaption, uType);
		LocalFree(psz);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}

	return r;
}

void EditServiceSecurity(_In_ HWND hwnd ,_In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName, _In_ HANDLE hSystemToken);
void ShowSD(_In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName, _In_ HANDLE hSystemToken, _In_ HWND hwndParent, _In_ HFONT hFont, _In_ BOOL bShift);
HRESULT ChangeServiceStartType(_In_ ULONG dwStartType, _In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName, _In_ HANDLE hSystemToken);
HRESULT TryStartService(_In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName, _In_ HANDLE hSystemToken);
HRESULT TryControlService(_In_ SC_HANDLE hSCManager, 
						  _In_ PCWSTR lpServiceName, 
						  _In_ DWORD dwControl, 
						  _In_ DWORD dwAccess,
						  _In_ HANDLE hSystemToken);

//////////////////////////////////////////////////////////////////////////
//
struct __declspec(novtable) ServiceData : SERVICE_NOTIFY
{
	SC_HANDLE hService;

	ServiceData() { 
		dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
		pfnNotifyCallback = ScNotifyCallback;
		pContext = 0;
	}

	void Close() { 
		if (hService) CloseServiceHandle(hService), hService = 0; 
	}

	void NotifyStatusChange()
	{
		if (hService) NotifyServiceStatusChange(hService, 
			SERVICE_NOTIFY_CONTINUE_PENDING|
			SERVICE_NOTIFY_DELETE_PENDING|
			SERVICE_NOTIFY_PAUSE_PENDING|
			SERVICE_NOTIFY_PAUSED|
			SERVICE_NOTIFY_RUNNING|
			SERVICE_NOTIFY_START_PENDING|
			SERVICE_NOTIFY_STOP_PENDING|
			SERVICE_NOTIFY_STOPPED, this);
	}

	virtual void OnScNotify() = 0;

	static VOID CALLBACK ScNotifyCallback (_In_ PVOID pParameter)
	{
		static_cast<ServiceData*>(reinterpret_cast<SERVICE_NOTIFY*>(pParameter))->OnScNotify();
	}

	virtual ~ServiceData()
	{
		Close();
	}

	void Set(_In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName)
	{
		if (hService = OpenServiceW(hSCManager, lpServiceName, SERVICE_QUERY_STATUS))
		{
			NotifyStatusChange();
		}
	}
};

//////////////////////////////////////////////////////////////////////////

struct ENUM_SERVICES 
{
	ENUM_SERVICES* next;
	ULONG n;
	ENUM_SERVICE_STATUS_PROCESSW Services[];

	void* operator new(size_t s, ULONG cb)
	{
		return ::operator new(s + cb);
	}

	void operator delete(void* p)
	{
		::operator delete(p);
	}
};

ENUM_SERVICE_STATUS_PROCESSW* GetService(ENUM_SERVICES* next, ULONG i)
{
	do 
	{
		ULONG n = next->n;
		if (i < n)
		{
			return next->Services + i;
		}
		i -= n;
	} while (next = next->next);

	return 0;
}

void destroy(ENUM_SERVICES* next)
{
	if (next)
	{
		do 
		{
			ENUM_SERVICES* buf = next;
			next = next->next;
			delete buf;
		} while (next);
	}
}

struct Sort 
{
	int s;
	union {
		ULONG iSubItem;
		Colum c;
	};

	ENUM_SERVICES* lpServices;

	static int CompareU(ULONG a, ULONG b)
	{
		if (a < b) return -1;
		if (a > b) return +1;
		return 0;
	}

	int Compare(ENUM_SERVICE_STATUS_PROCESSW* i, ENUM_SERVICE_STATUS_PROCESSW* j)
	{
		switch (c)
		{
		case CID_NAME:
			return _wcsicmp(i->lpServiceName, j->lpServiceName);
		case CID_DNAME:
			return _wcsicmp(i->lpDisplayName, j->lpDisplayName);
		case CID_START:
			return CompareU(i->ServiceStatusProcess.dwServiceSpecificExitCode, j->ServiceStatusProcess.dwServiceSpecificExitCode);
		case CID_ID:
			return CompareU(i->ServiceStatusProcess.dwProcessId, j->ServiceStatusProcess.dwProcessId);
		case CID_TYPE:
			return CompareU(i->ServiceStatusProcess.dwServiceType, j->ServiceStatusProcess.dwServiceType);
		case CID_STATE:
			return CompareU(i->ServiceStatusProcess.dwCurrentState, j->ServiceStatusProcess.dwCurrentState);
		}

		return 0;
	}

	static int __cdecl FuncCompare(void * This, const void * p, const void * q)
	{
		ENUM_SERVICES* lpServices = reinterpret_cast<Sort*>(This)->lpServices;
		return reinterpret_cast<Sort*>(This)->s * reinterpret_cast<Sort*>(This)->Compare(
			GetService(lpServices, *(ULONG*)p), GetService(lpServices, *(ULONG*)q));
	}
};

class ZMainWnd : public ZSDIFrameWnd, ServiceData
{
	SC_HANDLE _hSCManager;
	ENUM_SERVICES* _lpServices;
	PULONG _pi2i;
	HANDLE _hSysToken, _hKey;

	HFONT _hFont, _hStatusFont;
	HWND _hwndLV, _hwndCB, _hwndApply;
	HIMAGELIST _himl;
	ULONG _iItem = MAXULONG;
	ULONG _iSubItem = CID_NAME;
	ULONG _ItemCount;
	LONG _sortbits = ~0;
	ULONG _dwStartType = MAXULONG;
	BOOL _bTimerActive;

	//////////////////////////////////////////////////////////////////////////
	//ULONG _iTop = MINLONG, _iCount = 0;
	//////////////////////////////////////////////////////////////////////////

	enum { nTimerID = 1 };

	virtual PCUNICODE_STRING getPosName()
	{
		STATIC_UNICODE_STRING_(MainWnd);
		return &MainWnd;
	}

	BOOL CreateImageList();

	virtual BOOL CreateClient(HWND hwnd, int x, int y, int nWidth, int nHeight);
	virtual BOOL CreateTB(HWND hwnd);
	virtual BOOL CreateSB(HWND hwnd);

	void OnDispInfo(LVITEMW* item);
	void OnItemChanged(HWND hwnd, NMLISTVIEW* pnm);
	void OnStartTypeChanged(ULONG dwStartType);

	void OnRClk(HWND hwnd, NMITEMACTIVATE* lpnmitem );
	void OnDblClk(HWND hwnd, NMITEMACTIVATE* lpnmitem );
	void SortColum(HWND hwndLV, ULONG iSubItem);

	void Refresh(HWND hwnd);

	void UpdateItem(ULONG i)
	{
		RECT rc {LVIR_BOUNDS};
		if (SendMessageW(_hwndLV, LVM_GETITEMRECT, i, (LPARAM)&rc))
		{
			InvalidateRect(_hwndLV, &rc, 0);
		}
	}

	BOOL OnApply(HWND hwnd);
	void OnStart(HWND hwnd);
	void OnStop(HWND hwnd);
	void OnPause(HWND hwnd);

	ENUM_SERVICE_STATUS_PROCESSW* GetServiceI(ULONG iItem)
	{
		return iItem < _ItemCount ? GetService(_lpServices, _pi2i[iItem]) : 0;
	}

	void OnSD(HWND hwnd);

	void OnTimer();

	void SetStatus(ULONG iItem);
	void GetInfoTip(NMLVGETINFOTIP* pit);

	virtual void OnScNotify();

	void UpdateStartStop(ENUM_SERVICE_STATUS_PROCESSW* lpService);

	HRESULT Init(SC_HANDLE hSCManager);

	LRESULT WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
public:
	~ZMainWnd();

	HRESULT Init();
};

void ZMainWnd::OnScNotify()
{
	//DbgPrint("OnScNotify(%x %08x {%x %x %x}])\n", dwNotificationStatus, dwNotificationTriggered, 
	//	ServiceStatus.dwCurrentState, ServiceStatus.dwControlsAccepted, ServiceStatus.dwWin32ExitCode);

	if (0 <= dwNotificationStatus)
	{
		ULONG iItem = _iItem;

		if (ENUM_SERVICE_STATUS_PROCESSW* lpService = GetServiceI(iItem))
		{
			if (ServiceStatus.dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR)
			{
				ServiceStatus.dwWin32ExitCode = ServiceStatus.dwServiceSpecificExitCode;
			}

			ServiceStatus.dwServiceSpecificExitCode = lpService->ServiceStatusProcess.dwServiceSpecificExitCode;

			int i = memcmp(&ServiceStatus, &lpService->ServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS));
			
			lpService->ServiceStatusProcess = ServiceStatus;
			
			if (i)
			{
				UpdateStartStop(lpService);
				UpdateItem(iItem);
				SetStatus(iItem);
			}

			if (dwNotificationTriggered) NotifyStatusChange();
		}
	}
}

void ZMainWnd::SortColum(HWND hwndLV, ULONG iSubItem)
{
	if (iSubItem < CID_MAX)
	{
		Sort s { _bittestandcomplement(&_sortbits, iSubItem) ? +1 : -1, iSubItem, _lpServices }; 
		qsort_s(_pi2i, _ItemCount, sizeof(ULONG), Sort::FuncCompare, &s);

		LVCOLUMN lc = { LVCF_FMT, LVCFMT_LEFT };
		if (_iSubItem != iSubItem)
		{
			ListView_SetColumn(hwndLV, _iSubItem, &lc);
			_iSubItem = iSubItem;
		}

		lc.fmt = align[iSubItem] | (0 < s.s ? HDF_SORTUP : HDF_SORTDOWN);

		ListView_SetColumn(hwndLV, iSubItem, &lc);
		InvalidateRect(hwndLV, 0, FALSE);
	}
}

ZMainWnd::~ZMainWnd()
{
	destroy(_lpServices), _lpServices = 0;

	union {
		SC_HANDLE hSCManager;
		HANDLE h;
	};

	if (hSCManager = _hSCManager)
	{
		CloseServiceHandle(hSCManager);
	}

	if (h = _hKey)
	{
		NtClose(h);
	}

	if (h = _hSysToken)
	{
		NtClose(h);
	}
}

#define _TEST_
#ifdef _TEST_

EXTERN_C PVOID __imp_RtlGetPersistedStateLocation = 0;

void QuerySD(LPWSTR lpServiceName, PSECURITY_DESCRIPTOR lpSecurityDescriptor)
{
	BOOLEAN bpresent, bDefaulted;
	PACL Dacl;

	if (0 <= RtlGetDaclSecurityDescriptor(lpSecurityDescriptor, &bpresent, &Dacl, &bDefaulted) && bpresent && Dacl)
	{
		BOOL b = FALSE;
		PACCESS_ALLOWED_ACE pBestAce = 0;

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
					if ((pAce->Mask & (SERVICE_CHANGE_CONFIG|SERVICE_STOP|SERVICE_START)) == 
						(SERVICE_CHANGE_CONFIG|SERVICE_STOP|SERVICE_START))
					{
						b = TRUE;
					}
					
					if (!pBestAce || !(~pAce->Mask & pBestAce->Mask))
					{
						pBestAce = pAce;
					}
				}

			} while (pb += pHead->AceSize, --AceCount);
		}

		if (!b || !pBestAce)
		{
			DbgPrint("!!!!!");
		}

		if (pBestAce)
		{
			UNICODE_STRING us;
			if (0 <= RtlConvertSidToUnicodeString(&us, &pBestAce->SidStart, TRUE))
			{
				DbgPrint("%08x %wZ | %S\n", pBestAce->Mask, &us, lpServiceName);
				RtlFreeUnicodeString(&us);
			}
		}
	}
	else
	{
		__nop();
	}
}
#endif//_TEST_

#undef _NTDDK_
#include <sddl.h>

void InitS(HANDLE hKey, PUNICODE_STRING Id, ULONG n, ENUM_SERVICE_STATUS_PROCESSW Services[])
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), hKey, &ObjectName, OBJ_CASE_INSENSITIVE };
	STATIC_UNICODE_STRING_(StartOverride);
	OBJECT_ATTRIBUTES oa2 = { sizeof(oa2), 0, const_cast<PUNICODE_STRING>(&StartOverride), OBJ_CASE_INSENSITIVE };
	
#ifdef _TEST_
	STATIC_UNICODE_STRING_(Security);
	OBJECT_ATTRIBUTES oa3 = { sizeof(oa3), 0, const_cast<PUNICODE_STRING>(&Security), OBJ_CASE_INSENSITIVE };
#endif

	do 
	{
		if (Services->ServiceStatusProcess.dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR)
		{
			Services->ServiceStatusProcess.dwWin32ExitCode = Services->ServiceStatusProcess.dwServiceSpecificExitCode;
		}

		Services->ServiceStatusProcess.dwServiceSpecificExitCode = MAXULONG;

		RtlInitUnicodeString(&ObjectName, Services->lpServiceName);

		if (0 <= ZwOpenKey(&oa2.RootDirectory, KEY_QUERY_VALUE, &oa))
		{
			union {
				KEY_VALUE_PARTIAL_INFORMATION kvpi;
				UCHAR buf [0x200];
			};
			STATIC_UNICODE_STRING_(Start);

			if (0 <= ZwQueryValueKey(oa2.RootDirectory, &Start, KeyValuePartialInformation, &kvpi, sizeof(kvpi), &kvpi.TitleIndex) &&
				kvpi.Type == REG_DWORD)
			{
				Services->ServiceStatusProcess.dwServiceSpecificExitCode = (ULONG&)kvpi.Data;

				if (Id && (ULONG&)kvpi.Data == BootLoad)
				{
					if (0 <= ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa2))
					{
						if (0 <= ZwQueryValueKey(hKey, Id, KeyValuePartialInformation, &kvpi, sizeof(kvpi), &kvpi.TitleIndex) &&
							kvpi.Type == REG_DWORD)
						{
							Services->ServiceStatusProcess.dwServiceSpecificExitCode = (ULONG&)kvpi.Data;
						}
						NtClose(hKey);
					}
				}

#ifdef _TEST_
				oa3.RootDirectory = oa2.RootDirectory;
				if (0 <= ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa3))
				{
					if (0 <= ZwQueryValueKey(hKey, &Security, KeyValuePartialInformation, &kvpi, sizeof(buf), &kvpi.TitleIndex) &&
						kvpi.Type == REG_BINARY)
					{
						if (RtlValidSecurityDescriptor(kvpi.Data))
						{
							PWSTR psz;
							if (ConvertSecurityDescriptorToStringSecurityDescriptorW(kvpi.Data, 
								SDDL_REVISION, DACL_SECURITY_INFORMATION, &psz, 0))
							{
								DbgPrint("%S: %S\n", Services->lpServiceName, psz);
								LocalFree(psz);
							}
							//QuerySD(Services->lpServiceName, kvpi.Data);
						}
					}
					NtClose(hKey);
				}
#endif
			}

			NtClose(oa2.RootDirectory);
		}

	} while (Services++, --n);
}

NTSTATUS HwCfgGetCurrentConfiguration(PULONG pId)
{
	NTSTATUS status = STATUS_SUCCESS;
	STATIC_OBJECT_ATTRIBUTES(oa, "\\Registry\\MACHINE\\SYSTEM\\HardwareConfig\\Current");

	HANDLE hKey;
	if (0 <= ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa))
	{
		KEY_VALUE_PARTIAL_INFORMATION kvpi;
		STATIC_UNICODE_STRING_(Id);
		if (0 <= ZwQueryValueKey(hKey, &Id, KeyValuePartialInformation, &kvpi, sizeof(kvpi), &kvpi.TitleIndex) &&
			kvpi.Type == REG_DWORD)
		{
			*pId = (ULONG&)kvpi.Data;
		}
		NtClose(hKey);
	}

	return status;
}

HRESULT ZMainWnd::Init(SC_HANDLE hSCManager)
{
	union {
		ULONG Id;
		WCHAR sz[16];
	};
	UNICODE_STRING uID, *puID = 0;
	if (0 <= HwCfgGetCurrentConfiguration(&Id))
	{
		if (0 < swprintf_s(sz, _countof(sz), L"%d", Id))
		{
			RtlInitUnicodeString(puID = &uID, sz);
		}
	}

	ULONG dwError;

	ULONG cbBytesNeeded = 0x40000 - FIELD_OFFSET(ENUM_SERVICES, Services), ResumeHandle = 0, ItemCount = 0, n;

	ENUM_SERVICES* lpServices = 0;
	do 
	{
		dwError = ERROR_OUTOFMEMORY;

		DWORD dwServiceType = g_nt_ver.Version < _WIN32_WINNT_WIN10 ? 
			SERVICE_WIN32|SERVICE_ADAPTER |SERVICE_DRIVER|SERVICE_INTERACTIVE_PROCESS: SERVICE_TYPE_ALL;

		if (ENUM_SERVICES* next = new(cbBytesNeeded) ENUM_SERVICES)
		{
			switch (dwError = BOOL_TO_ERROR(EnumServicesStatusEx(hSCManager, 
				SC_ENUM_PROCESS_INFO, dwServiceType, SERVICE_STATE_ALL, 
				(PBYTE)next->Services, cbBytesNeeded, &cbBytesNeeded, &n, &ResumeHandle, 0)))
			{
			case NOERROR:
			case ERROR_MORE_DATA:
				InitS(_hKey, puID, n, next->Services);
				next->next = lpServices, lpServices = next, ItemCount += n, next->n = n;
				break;
			default:
				delete [] next;
			}
		}

	} while (dwError == ERROR_MORE_DATA);

	if (dwError == NOERROR)
	{
		if (PULONG pi2i = new ULONG[ItemCount])
		{
			_pi2i = pi2i;
			_lpServices = lpServices, _ItemCount = ItemCount;
			do 
			{
				*pi2i++ = --ItemCount;
			} while (ItemCount);

			return S_OK;
		}
	}

	destroy(lpServices);

	return HRESULT_FROM_WIN32(dwError);
}

HRESULT ZMainWnd::Init()
{
	HRESULT hr = AdjustPrivileges();
	
	STATIC_OBJECT_ATTRIBUTES(oa, "\\Registry\\MACHINE\\SYSTEM\\CurrentControlSet\\Services");
	if (hr || 0 > (hr = GetToken(&tp_ctp, &_hSysToken)) || 0 > (hr = ZwOpenKey(&_hKey, KEY_READ, &oa)))
	{
		return HRESULT_FROM_NT(hr);
	}

	if (SC_HANDLE hSCManager = OpenSCManagerW(0, 0, SC_MANAGER_ENUMERATE_SERVICE ))
	{
		if (0 <= (hr = Init(hSCManager)))
		{
			_hSCManager = hSCManager;
			return S_OK;
		}

		CloseServiceHandle(hSCManager);
	}

	return GetLastHr();
}

void ZMainWnd::UpdateStartStop(ENUM_SERVICE_STATUS_PROCESSW* lpService)
{
	LONG m = 0;
	DWORD dwControlsAccepted = lpService->ServiceStatusProcess.dwControlsAccepted;

	if (dwControlsAccepted & SERVICE_ACCEPT_STOP)
	{
		_bittestandset(&m, 2);
	}

	switch (lpService->ServiceStatusProcess.dwCurrentState)
	{
	case SERVICE_STOPPED:
		switch (lpService->ServiceStatusProcess.dwServiceSpecificExitCode)
		{
		case SystemLoad:
		case AutoLoad:
		case DemandLoad:
			m = 1;
			break;
		}
		break;

	case SERVICE_PAUSED:
		if (dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE)
		{
			_bittestandset(&m, 0);
		}
		break;

	case SERVICE_RUNNING: 
		if (dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE)
		{
			_bittestandset(&m, 1);
		}
		break;
	}

	EnableCmd(ID_START, _bittest(&m, 0));
	EnableCmd(ID_PAUSE, _bittest(&m, 1));
	EnableCmd(ID_STOP, _bittest(&m, 2));
}

void ZMainWnd::OnItemChanged(HWND hwnd, NMLISTVIEW* pnm)
{
	if (LVIF_STATE & pnm->uChanged)
	{
		UINT uNewState = pnm->uNewState & LVIS_SELECTED;
		UINT uOldState = pnm->uOldState & LVIS_SELECTED;

		if (uNewState != uOldState)
		{
			ServiceData::Close();

			BOOL bNeedTimer = FALSE;

			ULONG iItem = pnm->iItem;
			_iItem = iItem;
			_dwStartType = MAXULONG;

			ULONG dwStartType = MAXULONG;
			BOOL bNewItemSelected = FALSE;
			if (uNewState)
			{
				if (ENUM_SERVICE_STATUS_PROCESSW* lpService = GetServiceI(iItem))
				{
					bNewItemSelected = TRUE;

					ServiceData::Set(_hSCManager, lpService->lpServiceName);

					UpdateStartStop(lpService);

					dwStartType = lpService->ServiceStatusProcess.dwServiceSpecificExitCode;

					bNeedTimer = lpService->ServiceStatusProcess.dwServiceType & SERVICE_DRIVER;
				}
			}

			EnableCmd(ID_SD, bNewItemSelected);

			EnableWindow(_hwndCB, dwStartType != MAXULONG && 0 <= ComboBox_SetCurSel(_hwndCB, dwStartType));
			EnableWindow(_hwndApply, FALSE);

			if (ZStatusBar::getHWND())
			{
				SetStatus(iItem);
			}

			if (_bTimerActive != bNeedTimer)
			{
				if (bNeedTimer)
				{
					_bTimerActive = SetTimer(hwnd, nTimerID, 1000, 0) != 0;
				}
				else
				{
					KillTimer(hwnd, nTimerID);
					_bTimerActive = FALSE;
				}
			}
		}
	}
}

BOOL IsValidNewStartType(ULONG dwStartType, ENUM_SERVICE_STATUS_PROCESSW* lpService)
{
	return dwStartType <= SERVICE_DISABLED &&
	(dwStartType != lpService->ServiceStatusProcess.dwServiceSpecificExitCode) &&
		(dwStartType > SERVICE_SYSTEM_START || lpService->ServiceStatusProcess.dwServiceType < SERVICE_WIN32_OWN_PROCESS);
}

void ZMainWnd::OnStartTypeChanged(ULONG dwStartType)
{
	if (ENUM_SERVICE_STATUS_PROCESSW* lpService = GetServiceI(_iItem))
	{
		_dwStartType = dwStartType;
		EnableWindow(_hwndApply, IsValidNewStartType(dwStartType, lpService));
	}
}

BOOL ZMainWnd::OnApply(HWND hwnd)
{
	if (ENUM_SERVICE_STATUS_PROCESSW* lpService = GetServiceI(_iItem))
	{
		ULONG dwStartType = _dwStartType;
		if (IsValidNewStartType(dwStartType, lpService))
		{
			if (HRESULT hr = ChangeServiceStartType(dwStartType, _hSCManager, lpService->lpServiceName, _hSysToken))
			{
				ShowErrorBox(hwnd, hr, 0, MB_ICONHAND);
			}
			else
			{
				lpService->ServiceStatusProcess.dwServiceSpecificExitCode = dwStartType;
				UpdateItem(_iItem);
				UpdateStartStop(lpService);
				return TRUE;
			}
		}
	}

	return FALSE;
}

void ZMainWnd::OnStart(HWND hwnd)
{
	if (ENUM_SERVICE_STATUS_PROCESSW* lpService = GetServiceI(_iItem))
	{
		HRESULT hr;
		switch (lpService->ServiceStatusProcess.dwCurrentState)
		{
		case SERVICE_STOPPED:
			hr = TryStartService(_hSCManager, lpService->lpServiceName, _hSysToken);
			break;
		case SERVICE_PAUSED:
			hr = TryControlService(_hSCManager, lpService->lpServiceName, 
				SERVICE_CONTROL_CONTINUE, SERVICE_PAUSE_CONTINUE, _hSysToken);
			break;
		default: return;
		}

		if (hr)
		{
			ShowErrorBox(hwnd, hr, 0, MB_ICONHAND);
		}
	}
}

void ZMainWnd::OnStop(HWND hwnd)
{
	if (ENUM_SERVICE_STATUS_PROCESSW* lpService = GetServiceI(_iItem))
	{
		if (HRESULT hr = TryControlService(_hSCManager, lpService->lpServiceName, 
			SERVICE_CONTROL_STOP, SERVICE_STOP, _hSysToken))
		{
			ShowErrorBox(hwnd, hr, 0, MB_ICONHAND);
		}
	}
}

void ZMainWnd::OnPause(HWND hwnd)
{
	if (ENUM_SERVICE_STATUS_PROCESSW* lpService = GetServiceI(_iItem))
	{
		if (HRESULT hr = TryControlService(_hSCManager, lpService->lpServiceName, 
			SERVICE_CONTROL_PAUSE, SERVICE_PAUSE_CONTINUE, _hSysToken))
		{
			ShowErrorBox(hwnd, hr, 0, MB_ICONHAND);
		}
	}
}

void ZMainWnd::OnSD(HWND hwnd)
{
	if (ENUM_SERVICE_STATUS_PROCESSW* lpService = GetServiceI(_iItem))
	{
		0 > GetKeyState(VK_LSHIFT) ? 
			EditServiceSecurity(hwnd, _hSCManager, lpService->lpServiceName, _hSysToken) :
			ShowSD(_hSCManager, lpService->lpServiceName, _hSysToken, hwnd, _hFont, 0 > GetKeyState(VK_RSHIFT));
	}
}

void ZMainWnd::OnTimer()
{
	if (ENUM_SERVICE_STATUS_PROCESSW* lpService = GetServiceI(_iItem))
	{
		if (lpService->ServiceStatusProcess.dwServiceType & SERVICE_DRIVER)
		{
			if (hService && QueryServiceStatus(hService, (SERVICE_STATUS*)&ServiceStatus ))
			{
				dwNotificationStatus = 0;
				dwNotificationTriggered = 0;
				OnScNotify();
			}
		}
	}
}

void SetStringToClipboard(HWND hwnd, PCWSTR lpsz)
{
	if (OpenClipboard(hwnd))
	{
		EmptyClipboard();
		size_t cb = (wcslen(lpsz) + 1) * sizeof(WCHAR);
		if (HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, cb))
		{
			memcpy(GlobalLock(hg), lpsz, cb);
			GlobalUnlock(hg);
			if (!SetClipboardData(CF_UNICODETEXT, hg)) GlobalFree(hg);
		}
		CloseClipboard();
	}
}

void ZMainWnd::OnRClk(HWND hwnd, NMITEMACTIVATE* lpnmitem )
{
	if (ENUM_SERVICE_STATUS_PROCESSW* lpService = GetServiceI(lpnmitem->iItem))
	{
		if (HMENU hmenu = LoadMenuW((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDR_MENU1)))
		{
			ClientToScreen(_hwndLV, &lpnmitem->ptAction);
			
			ULONG cmd = TrackPopupMenu(GetSubMenu(hmenu, 0), TPM_NONOTIFY|TPM_RETURNCMD, 
				lpnmitem->ptAction.x, lpnmitem->ptAction.y, 0, hwnd, 0);
			
			DestroyMenu(hmenu);

			switch (cmd)
			{
			case ID_0_EDITSECURITY:
				EditServiceSecurity(hwnd, _hSCManager, lpService->lpServiceName, _hSysToken);
				break;
			case ID_0_VIEWSECURITY:
				ShowSD(_hSCManager, lpService->lpServiceName, _hSysToken, hwnd, _hFont, FALSE);
				break;
			case ID_0_VIEWSECURITY40004:
				ShowSD(_hSCManager, lpService->lpServiceName, _hSysToken, hwnd, _hFont, TRUE);
				break;
			case ID_0_COPYNAME:
				SetStringToClipboard(hwnd, lpService->lpDisplayName);
				break;
			}
		}
	}
}

LRESULT ZMainWnd::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_DESTROY:
		if (_himl) ImageList_Destroy(_himl);
		if (_hFont) DeleteObject(_hFont);
		if (_bTimerActive) KillTimer(hwnd, nTimerID);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case MAKEWPARAM(ID_COMBO, CBN_SELCHANGE):
			OnStartTypeChanged(ComboBox_GetCurSel((HWND)lParam));
			return 0;
		
		case ID_SD:
			OnSD(hwnd);
			return 0;

		case ID_RELOAD:
			destroy(_lpServices), _lpServices = 0;
			Init(_hSCManager);
			ListView_SetItemCountEx(_hwndLV, _ItemCount, 0);
			_sortbits = ~0;
			SortColum(_hwndLV, CID_NAME);
			return 0;

		case ID_APPLY:
			if (OnApply(hwnd))
			{
				EnableWindow((HWND)lParam, FALSE);
			}
			return 0;
		
		case ID_START:
			OnStart(hwnd);
			return 0;
		
		case ID_STOP:
			OnStop(hwnd);
			return 0;

		case ID_PAUSE:
			OnPause(hwnd);
			return 0;
		}
		break;

	case WM_TIMER:
		OnTimer();
		break;

	case WM_NOTIFY:
		switch (((NMHDR*)lParam)->idFrom)
		{
		case ID_LV:
			switch (((NMHDR*)lParam)->code)
			{
			case LVN_GETDISPINFO:
				OnDispInfo(&reinterpret_cast<NMLVDISPINFO*>(lParam)->item);
				break;

			case LVN_GETINFOTIP:
				GetInfoTip(reinterpret_cast<NMLVGETINFOTIP*>(lParam));
				break;

			case LVN_COLUMNCLICK:
				SortColum(reinterpret_cast<NMLISTVIEW*>(lParam)->hdr.hwndFrom, reinterpret_cast<NMLISTVIEW*>(lParam)->iSubItem);
				break;

			case NM_RCLICK:
				OnRClk(hwnd, reinterpret_cast<NMITEMACTIVATE*>(lParam));
				break;
			case NM_DBLCLK:
				//OnDblClk(hwnd, reinterpret_cast<NMITEMACTIVATE*>(lParam));
				break;

			case LVN_ITEMCHANGED:
				OnItemChanged(hwnd, reinterpret_cast<NMLISTVIEW*>(lParam));
				break;

			//case LVN_ODCACHEHINT:
			//	reinterpret_cast<NMLVCACHEHINT*>(lParam)->iTo -= reinterpret_cast<NMLVCACHEHINT*>(lParam)->iFrom - 1;
			//	if (_iCount < (ULONG)reinterpret_cast<NMLVCACHEHINT*>(lParam)->iTo)
			//	{
			//		_iCount = reinterpret_cast<NMLVCACHEHINT*>(lParam)->iTo;
			//	}

			//	if ((ULONG)(reinterpret_cast<NMLVCACHEHINT*>(lParam)->iFrom - _iTop) >= _iCount)
			//	{
			//		_iTop = reinterpret_cast<NMLVCACHEHINT*>(lParam)->iFrom;

			//		DbgPrint("====%u, %u\n", 
			//			reinterpret_cast<NMLVCACHEHINT*>(lParam)->iFrom,reinterpret_cast<NMLVCACHEHINT*>(lParam)->iTo);
			//	}
			//	break;

			//case NM_CUSTOMDRAW:
			//	DbgPrint("************\n");
			//	break;

			//default:
			//	ULONG i = LVN_FIRST - ((NMHDR*)lParam)->code;
			//	if (i < (LVN_FIRST - LVN_LAST))
			//	{
			//		switch (i)
			//		{
			//		case LVN_FIRST - LVN_HOTTRACK:
			//			__nop();
			//			break;
			//		default:
			//			DbgPrint(":: %u\n", i);
			//		}
			//	}
			//	break;
			}
			break;
		}
		break;
	}
	return ZSDIFrameWnd::WindowProc(hwnd, uMsg, wParam, lParam);
}

BOOL IsSz(PKEY_VALUE_PARTIAL_INFORMATION pkvpi)
{
	switch (pkvpi->Type)
	{
	case REG_SZ:
	case REG_EXPAND_SZ:
		ULONG Length = pkvpi->DataLength;
		return Length && !(Length & (sizeof(WCHAR) - 1)) && !*(PWSTR)(pkvpi->Data + Length - sizeof(WCHAR));
	}

	return FALSE;
}

void ZMainWnd::GetInfoTip(NMLVGETINFOTIP* pit)
{
	if (ENUM_SERVICE_STATUS_PROCESSW* lpService = GetServiceI(pit->iItem))
	{
		UNICODE_STRING ObjectName;
		STATIC_UNICODE_STRING_(ImagePath);
		STATIC_UNICODE_STRING_(Parameters);
		STATIC_UNICODE_STRING_(ServiceDll);
		OBJECT_ATTRIBUTES oa = { sizeof(oa), _hKey, &ObjectName, OBJ_CASE_INSENSITIVE };
		OBJECT_ATTRIBUTES oa2 = { sizeof(oa2), 0, const_cast<PUNICODE_STRING>(&Parameters), OBJ_CASE_INSENSITIVE };
		RtlInitUnicodeString(&ObjectName, lpService->lpServiceName);
		
		BOOL b = FALSE;
		PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)pit->pszText;

		if (0 <= ZwOpenKey(&oa2.RootDirectory, KEY_QUERY_VALUE, &oa))
		{
			ULONG cb = pit->cchTextMax * sizeof(WCHAR);

			HANDLE hKey;
			if (0 <= ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa2))
			{
				if (0 <= ZwQueryValueKey(hKey, &ServiceDll, KeyValuePartialInformation, kvpi, cb, &kvpi->TitleIndex))
				{
					b = IsSz(kvpi);
				}
				NtClose(hKey);
			}

			if (!b && 0 <= ZwQueryValueKey(oa2.RootDirectory, &ImagePath, KeyValuePartialInformation, kvpi, cb, &kvpi->TitleIndex))
			{
				b = IsSz(kvpi);
			}
			NtClose(oa2.RootDirectory);
		}
		
		if (b)
		{
			wcscpy(pit->pszText, (PCWSTR)kvpi->Data);
			return;
		}
		
		if (lpService->ServiceStatusProcess.dwServiceType & SERVICE_DRIVER)
		{
			swprintf_s(pit->pszText, pit->cchTextMax, L"%s.sys", lpService->lpServiceName);
			return;
		}
	}
	swprintf_s(pit->pszText, pit->cchTextMax, L"??");
}

void ZMainWnd::SetStatus(ULONG iItem)
{
	WCHAR txt[256], *psz = txt;
	*txt = 0;

	if (ENUM_SERVICE_STATUS_PROCESSW* lpService = GetServiceI(iItem))
	{
		int len = 0;
		ULONG cch = _countof(txt);

		DWORD dwServiceType = lpService->ServiceStatusProcess.dwServiceType;

		static const PCWSTR ssz[] = {
			L"KERNEL_DRIVER",
			L"FILE_SYSTEM_DRIVER",
			L"ADAPTER",
			L"RECOGNIZER_DRIVER",
			L"OWN_PROCESS",
			L"SHARE_PROCESS",
			L"USER_SERVICE",
			L"USERSERVICE_INSTANCE",
			L"INTERACTIVE_PROCESS",
			L"PKG_SERVICE",
		};

		static const ULONG stt[] {
			SERVICE_KERNEL_DRIVER,
			SERVICE_FILE_SYSTEM_DRIVER,
			SERVICE_ADAPTER,
			SERVICE_RECOGNIZER_DRIVER,
			SERVICE_WIN32_OWN_PROCESS,
			SERVICE_WIN32_SHARE_PROCESS,
			SERVICE_USER_SERVICE,
			SERVICE_USERSERVICE_INSTANCE,
			SERVICE_INTERACTIVE_PROCESS,
			SERVICE_PKG_SERVICE,
		};

		ULONG n = _countof(stt);

		do 
		{
			if (dwServiceType & stt[--n])
			{
				if (0 > (len = swprintf_s(psz, cch, L"%s | ", ssz[n])))
				{
					break;
				}
				psz += len, cch -= len;
			}

		} while (n);

		if (0 <= len && lpService->ServiceStatusProcess.dwCurrentState == SERVICE_STOPPED)
		{
			HRESULT dwExitCode = lpService->ServiceStatusProcess.dwWin32ExitCode;
			ULONG dwFlags;
			HMODULE hmod;	

			if ((dwExitCode & FACILITY_NT_BIT) || (0 > dwExitCode && HRESULT_FACILITY(dwExitCode) == FACILITY_NULL))
			{
				dwExitCode &= ~FACILITY_NT_BIT;
__nt:
				hmod = GetNtMod();
				dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE;
			}
			else
			{
				hmod = 0;
				dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM;
			}

			if (FormatMessageW(dwFlags, hmod, dwExitCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), psz, cch, 0))
			{
			}
			else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
			{
				goto __nt;
			}
			else
			{
				swprintf_s(psz, cch, L"[%x]", lpService->ServiceStatusProcess.dwWin32ExitCode);
			}
		}
	}

	SetStatusText(SB_SIMPLEID, txt);
}

PCWSTR GetStartTypeName(ULONG dwStartType)
{
	switch (dwStartType)
	{
	case BootLoad: return L"Boot";
	case SystemLoad: return L"System";
	case AutoLoad: return L"Automatic";
	case DemandLoad: return L"Manual";
	case DisableLoad: return L"Disabled";
	default: return L"?";
	}
}

PCWSTR GetStateName(ULONG dwCurrentState)
{
	switch (dwCurrentState)
	{
	case SERVICE_STOPPED: return L"Stoped";
	case SERVICE_START_PENDING: return L"Starting ...";
	case SERVICE_STOP_PENDING: return L"Stoping ...";
	case SERVICE_RUNNING: return L"Running";
	case SERVICE_CONTINUE_PENDING: return L"Continuing ...";
	case SERVICE_PAUSE_PENDING: return L"Pausing ...";
	case SERVICE_PAUSED: return L"Paused";
	default: return L"?";
	}
}

void ZMainWnd::OnDispInfo(LVITEMW* item)
{
	if (ENUM_SERVICE_STATUS_PROCESSW* lpService = GetServiceI(item->iItem))
	{
		if (item->mask & LVIF_TEXT)
		{
			PWSTR pszText = item->pszText;
			ULONG cchTextMax = item->cchTextMax;

			if (cchTextMax)
			{
				*pszText = 0;
			}

			switch (item->iSubItem)
			{
			case CID_NAME:
				swprintf_s(pszText, cchTextMax, L"%s", lpService->lpServiceName);
				break;
			case CID_START:
				swprintf_s(pszText, cchTextMax, L"%s", GetStartTypeName(lpService->ServiceStatusProcess.dwServiceSpecificExitCode));
				break;
			case CID_TYPE:
				swprintf_s(pszText, cchTextMax, L"%s", lpService->ServiceStatusProcess.dwServiceType & SERVICE_DRIVER ? L"K" : L"U");
				break;
			case CID_STATE:
				swprintf_s(pszText, cchTextMax, L"%s", GetStateName(lpService->ServiceStatusProcess.dwCurrentState));
				break;
			case CID_ID:
				swprintf_s(pszText, cchTextMax, L"%x", lpService->ServiceStatusProcess.dwProcessId);
				break;
			case CID_DNAME:
				swprintf_s(pszText, cchTextMax, L"%s", lpService->lpDisplayName);
				break;
			}
		}

		if (item->mask & LVIF_IMAGE)
		{
			//ID_A(7), ID_B(6), ID_E(5), ID_G(4), ID_M(3), ID_P(2), ID_R(1), ID_Y(0),
			ULONG i = lpService->ServiceStatusProcess.dwServiceSpecificExitCode;

			item->iImage = i > SERVICE_DISABLED ? I_IMAGENONE : i;
		}
	}
}

BOOL ZMainWnd::CreateImageList()
{
	LIC c {0, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON) };

	static const UINT cc[] = { 
		ID_K, ID_G, ID_R, ID_Y, ID_B,
	};

	if (HIMAGELIST himl = ImageList_Create(c._cx, c._cy, ILC_COLOR32, _countof(cc), 0))
	{

		ULONG n = _countof(cc);
		int i;
		do 
		{
			i = -1;
			if (0 <= c.CreateBMPFromPNG(MAKEINTRESOURCE(cc[--n])))
			{
				i = ImageList_Add(himl, c._hbmp, 0);
				DeleteObject(c._hbmp), c._hbmp = 0;
			}

		} while (0 <= i && n);

		if (0 <= i)
		{
			_himl = himl;
			return TRUE;
		}

		ImageList_Destroy(himl);
	}

	return FALSE;
}

BOOL ZMainWnd::CreateSB(HWND hwnd)
{
	if (hwnd = ZStatusBar::Create(hwnd))
	{
		_hStatusFont = (HFONT)SendMessage(hwnd, WM_GETFONT, 0, 0);
		SendMessage(hwnd, SB_SIMPLE, TRUE, 0);
		return TRUE;
	}
	return FALSE;
}

BOOL ZMainWnd::CreateTB(HWND hwnd)
{
	int cc = 32 < GetSystemMetrics(SM_CYICON) ? 48 : 32;

	static const TBBUTTON g_btns[] = {
		{IMAGE_ENHMETAFILE, ID_RELOAD, TBSTATE_ENABLED, BTNS_AUTOSIZE, {}, (DWORD_PTR)L" Refresh ", -1},
		{IMAGE_ENHMETAFILE, ID_SD, 0, BTNS_AUTOSIZE, {}, (DWORD_PTR)L" Security Descriptor (hold left shift for edit) ", -1},
		{IMAGE_ENHMETAFILE, ID_START, 0, BTNS_AUTOSIZE, {}, (DWORD_PTR)L" start ", -1},
		{IMAGE_ENHMETAFILE, ID_PAUSE, 0, BTNS_AUTOSIZE, {}, (DWORD_PTR)L" pause ", -1},
		{IMAGE_ENHMETAFILE, ID_STOP, 0, BTNS_AUTOSIZE, {}, (DWORD_PTR)L" stop ", -1},
	};

	if (HWND hwndTB = ZToolBar::Create(hwnd, (HINSTANCE)&__ImageBase, 0, 0, cc, cc, g_btns, _countof(g_btns), TRUE))
	{
		RECT rc, rc2;
		SendMessage(hwndTB, TB_GETITEMRECT, _countof(g_btns) - 1, (LPARAM)&rc);

		if (HWND hwndCB = CreateWindowExW(0, WC_COMBOBOX, 0, 
			WS_VSCROLL|CBS_DROPDOWNLIST|WS_CHILD|WS_VISIBLE|WS_DISABLED, 
			rc.right += (3*cc>>3), 0, 4*cc, 0, hwndTB, (HMENU)ID_COMBO, 0, 0))
		{
			SendMessage(hwndCB, WM_SETFONT, (WPARAM)_hStatusFont, 0);

			ULONG H, y;
			GetWindowRect(hwndCB, &rc2);
			SetWindowPos(hwndCB, 0, rc.right, y = ((rc.bottom - rc.top) - (H = rc2.bottom - rc2.top)) >> 1, 0, 0, 
				SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE);

			_hwndCB = hwndCB;

			static PCWSTR mods[] = {
				L"Boot",
				L"System",
				L"Automatic",
				L"Manual",
				L"Disabled",
			};

			ULONG n = _countof(mods);
			PCWSTR* pcsz = mods;
			do 
			{
				ComboBox_AddString(hwndCB, *pcsz++);
			} while (--n);

			rc.right += 4*cc + (3*cc>>3);

			if (hwndCB = CreateWindowExW(0, WC_BUTTONW, L"Apply", 
				WS_CHILD|WS_VISIBLE|WS_DISABLED, rc.right, y, 3*H, H, hwndTB, (HMENU)ID_APPLY, 0, 0))
			{
				SendMessage(hwndCB, WM_SETFONT, (WPARAM)_hStatusFont, 0);

				_hwndApply = hwndCB;

				return TRUE;
			}
		}
	}

	return FALSE;
}

BOOL ZMainWnd::CreateClient(HWND hwnd, int x, int y, int nWidth, int nHeight)
{
	_hFont = 0;

	if (!(hwnd = CreateWindowExW(0, WC_LISTVIEWW, 0, 
		WS_VISIBLE|WS_CHILD|LVS_EDITLABELS|LVS_REPORT|LVS_OWNERDATA|
		LVS_SHOWSELALWAYS|LVS_SHAREIMAGELISTS|LVS_SINGLESEL|WS_HSCROLL|WS_VSCROLL, 
		x, y, nWidth, nHeight, hwnd, (HMENU)ID_LV, 0, 0))) return FALSE;

	_hwndLV = hwnd;

	NONCLIENTMETRICS ncm = { sizeof(NONCLIENTMETRICS) };
	if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
	{
		ncm.lfCaptionFont.lfHeight = -ncm.iMenuHeight;
		ncm.lfCaptionFont.lfWeight = FW_NORMAL;
		ncm.lfCaptionFont.lfQuality = CLEARTYPE_QUALITY;
		ncm.lfCaptionFont.lfPitchAndFamily = FIXED_PITCH|FF_MODERN;
		wcscpy(ncm.lfCaptionFont.lfFaceName, L"Courier New");

		if (_hFont = CreateFontIndirect(&ncm.lfCaptionFont))
		{
			SendMessage(hwnd, WM_SETFONT, (WPARAM)_hFont, 0);
		}
	}

	SetWindowTheme(hwnd, L"Explorer", 0);

	if (CreateImageList())
	{
		ListView_SetImageList(hwnd, _himl, LVSIL_SMALL);
	}

	LV_COLUMN lvclmn = { 
		LVCF_TEXT | LVCF_WIDTH | LVCF_FMT | LVCF_SUBITEM, LVCFMT_LEFT 
	};

	static const PCWSTR headers[] = {
		L" Name ", L" Start ", L" State ", L"Type", L" Id ", L" Display Name "
	};

	static const ULONG lens[] = { 20, 6, 7, 4, 4, 32 };

	C_ASSERT(_countof(headers) == _countof(lens));

	do
	{
		lvclmn.pszText = const_cast<PWSTR>(headers[lvclmn.iSubItem]);
		lvclmn.cx = lens[lvclmn.iSubItem] * ncm.iMenuHeight;
		lvclmn.fmt = align[lvclmn.iSubItem];

		ListView_InsertColumn(hwnd, lvclmn.iSubItem, &lvclmn);
	} while (++lvclmn.iSubItem < _countof(headers));

	ListView_SetExtendedListViewStyle(hwnd, 
		LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_LABELTIP|LVS_EX_DOUBLEBUFFER|LVS_EX_INFOTIP);

	ListView_SetItemCountEx(hwnd, _ItemCount, 0);
	SortColum(hwnd, CID_NAME);

	return TRUE;
}

void zmain()
{
	ZGLOBALS globals;
	ZApp app;
	ZRegistry reg;
	ZMainWnd wnd{};

	HRESULT status = wnd.Init();

	if (0 > status)
	{
		ShowErrorBox(0, status, 0);
	}
	else if (0 <= reg.Create(L"Software\\{0B62FC2A-9F2D-4c33-AE2F-65E0CF80C63B}"))
	{
		if (wnd.Create(L"Services", (HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(ID_MAIN), TRUE))
		{
			app.Run();
		}
	}
}

void CALLBACK ep(void*)
{
	initterm();

	if (0 <= CoInitializeEx(0, COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE))
	{
		zmain();
		CoUninitialize();
	}
	destroyterm();
	ExitProcess(0);
}

_NT_END
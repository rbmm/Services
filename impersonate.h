#pragma once

NTSTATUS GetToken(_In_ const TOKEN_PRIVILEGES* RequiredSet, _Out_ PHANDLE phToken);

NTSTATUS AdjustPrivileges();

NTSTATUS SetToken(HANDLE hToken = 0);

HRESULT SetTokenForService(_In_ SC_HANDLE hService, _In_ HANDLE hSystemToken, _In_ ULONG Mask);

HRESULT SetTokenForService(_In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName, _In_ HANDLE hSystemToken, _In_ ULONG Mask);

extern const SECURITY_QUALITY_OF_SERVICE sqos;
extern const OBJECT_ATTRIBUTES oa_sqos;


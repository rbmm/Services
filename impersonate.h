#pragma once

NTSTATUS WINAPI GetToken(_In_ const TOKEN_PRIVILEGES* RequiredSet, _Out_ PHANDLE phToken);
NTSTATUS WINAPI AdjustPrivileges();

NTSTATUS WINAPI RtlRevertToSelf();

HRESULT SetTokenForService(_In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName, _In_ HANDLE hSystemToken, _In_ ULONG Mask);

NTSTATUS SetTrustedInstallerToken(_In_ HANDLE hSystemToken);

extern const SECURITY_QUALITY_OF_SERVICE sqos;
extern const OBJECT_ATTRIBUTES oa_sqos;


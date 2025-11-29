#pragma once

#ifndef TH32CS_SNAPPROCESS
#define TH32CS_SNAPPROCESS 0x00000002
#endif

// Additional function declarations not in _include/bofdefs.h
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegGetValueA(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$GetFileSecurityA(LPCSTR lpFileName, SECURITY_INFORMATION RequestedInformation, PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD nLength, LPDWORD lpnLengthNeeded);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$DuplicateToken(HANDLE ExistingTokenHandle, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, PHANDLE DuplicateTokenHandle);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$AccessCheck(PSECURITY_DESCRIPTOR pSecurityDescriptor, HANDLE ClientToken, DWORD DesiredAccess, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, LPDWORD PrivilegeSetLength, LPDWORD GrantedAccess, LPBOOL AccessStatus);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI IPHLPAPI$GetExtendedTcpTable(PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, TCP_TABLE_CLASS TableClass, ULONG Reserved);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI IPHLPAPI$GetExtendedUdpTable(PVOID pUdpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, UDP_TABLE_CLASS TableClass, ULONG Reserved);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$QueryFullProcessImageNameA(HANDLE hProcess, DWORD dwFlags, LPSTR lpExeName, PDWORD lpdwSize);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI GetFileAttributesA(LPCSTR lpFileName);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

// Windows Event Log API (advapi32.dll) - legacy API for reading event logs
DECLSPEC_IMPORT HANDLE WINAPI ADVAPI32$OpenEventLogA(LPCSTR lpUNCServerName, LPCSTR lpSourceName);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ReadEventLogA(HANDLE hEventLog, DWORD dwReadFlags, DWORD dwRecordOffset, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, PDWORD pnBytesRead, PDWORD pnMinNumberOfBytesNeeded);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CloseEventLog(HANDLE hEventLog);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetNumberOfEventLogRecords(HANDLE hEventLog, PDWORD NumberOfRecords);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetOldestEventLogRecord(HANDLE hEventLog, PDWORD OldestRecord);

// Event Log constants
#define EVENTLOG_SEQUENTIAL_READ 0x0001
#define EVENTLOG_SEEK_READ 0x0002
#define EVENTLOG_FORWARDS_READ 0x0004
#define EVENTLOG_BACKWARDS_READ 0x0008
#define EVENTLOG_SUCCESS 0x0000
#define EVENTLOG_ERROR_TYPE 0x0001
#define EVENTLOG_WARNING_TYPE 0x0002
#define EVENTLOG_INFORMATION_TYPE 0x0004
#define EVENTLOG_AUDIT_SUCCESS 0x0008
#define EVENTLOG_AUDIT_FAILURE 0x0010

// KERNEL32 functions added for winpeas
WINBASEAPI DWORD WINAPI KERNEL32$GetLogicalDrives(VOID);
WINBASEAPI UINT WINAPI KERNEL32$GetDriveTypeA(LPCSTR lpRootPathName);

// MPR functions added for winpeas
WINBASEAPI DWORD WINAPI MPR$WNetGetConnectionA(LPCSTR lpLocalName, LPSTR lpRemoteName, LPDWORD lpnLength);

// Additional KERNEL32 function declarations
DECLSPEC_IMPORT WINBASEAPI VOID WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME lpSystemTime);

// Additional type definitions and constants
#define WTS_CURRENT_SERVER_HANDLE ((HANDLE)NULL)
#define WTS_USERNAME 5
#define KEY_WRITE 0x20006

typedef struct _SHARE_INFO_502 {
    LMSTR shi502_netname;
    DWORD shi502_type;
    LMSTR shi502_remark;
    DWORD shi502_permissions;
    DWORD shi502_max_uses;
    DWORD shi502_current_uses;
    LMSTR shi502_path;
    LMSTR shi502_passwd;
    DWORD shi502_reserved;
    PSECURITY_DESCRIPTOR shi502_security_descriptor;
} SHARE_INFO_502, *PSHARE_INFO_502, *LPSHARE_INFO_502;

#define MAX_PREFERRED_LENGTH ((DWORD) -1)
#define NERR_Success 0
#define ERROR_MORE_DATA 234

// Token constants
#ifndef TOKEN_QUERY
#define TOKEN_QUERY 0x0008
#endif
#ifndef TokenUser
#define TokenUser 1
#endif
#ifndef TokenGroups
#define TokenGroups 2
#endif

// LDAP constants
#ifndef LDAP_PORT
#define LDAP_PORT 389
#endif
#ifndef LDAP_VERSION3
#define LDAP_VERSION3 3
#endif
#ifndef LDAP_AUTH_NEGOTIATE
#define LDAP_AUTH_NEGOTIATE 0x0480
#endif
#ifndef LDAP_SCOPE_BASE
#define LDAP_SCOPE_BASE 0
#endif
#ifndef LDAP_SCOPE_ONELEVEL
#define LDAP_SCOPE_ONELEVEL 1
#endif
#ifndef LDAP_SCOPE_SUBTREE
#define LDAP_SCOPE_SUBTREE 2
#endif
#ifndef LDAP_SUCCESS
#define LDAP_SUCCESS 0
#endif

// SID list structure for AD checks
typedef struct _SID_LIST {
    char sid[256];
    struct _SID_LIST* next;
} SID_LIST, *PSID_LIST;

// Helper functions for AD checks (declared in utils.c)
PSID_LIST GetCurrentSids(void);
void FreeSidList(PSID_LIST sidList);
BOOL IsSidInList(PSID_LIST sidList, const char* sid);
char* GetRootDseProp(LDAP* ld, const char* prop);


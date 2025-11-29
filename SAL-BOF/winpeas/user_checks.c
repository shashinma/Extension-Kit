// ============================================================================
// USER INFORMATION CHECKS
// ============================================================================

#include "winpeas.h"

void CheckTokenPrivileges(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] TOKEN PRIVILEGES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HANDLE tokenHandle;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &tokenHandle)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[TOKEN_PRIV] Failed to open process token. Error: %lu\n", KERNEL32$GetLastError());
        return;
    }

    DWORD tokenInfoSize = 0;
    ADVAPI32$GetTokenInformation(tokenHandle, TokenPrivileges, NULL, 0, &tokenInfoSize);
    if (tokenInfoSize == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[TOKEN_PRIV] Failed to get token information size. Error: %lu\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    PTOKEN_PRIVILEGES tokenPrivileges = (PTOKEN_PRIVILEGES)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, tokenInfoSize);
    if (!tokenPrivileges) {
        BeaconPrintf(CALLBACK_OUTPUT, "[TOKEN_PRIV] Memory allocation failed.\n");
        goto cleanup;
    }
    if (!ADVAPI32$GetTokenInformation(tokenHandle, TokenPrivileges, tokenPrivileges, tokenInfoSize, &tokenInfoSize)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[TOKEN_PRIV] Failed to get token privileges. Error: %lu\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    static const char * KnownVulnerable[] = {
        "SeAssignPrimaryToken",
        "SeBackupPrivilege",
        "SeCreateTokenPrivilege",
        "SeRestorePrivilege",
        "SeDebugPrivilege",
        "SeImpersonatePrivilege",
        "SeLoadDriverPrivilege",
        "SeManageVolumePrivilege",
        "SeTcbPrivilege",
        "SeTakeOwnershipPrivilege",
        NULL
    };

    for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; ++i) {
        LUID privilegeLuid = tokenPrivileges->Privileges[i].Luid;
        char privilegeNameBuffer[256];
        DWORD bufferSize = sizeof(privilegeNameBuffer);
        if (ADVAPI32$LookupPrivilegeNameA(NULL, &privilegeLuid, privilegeNameBuffer, &bufferSize)) {
            BOOL isEnabled = (tokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED;
            BOOL isVulnerable = FALSE;
            
            int j = 0;
            while (KnownVulnerable[j]) {
                if (MSVCRT$_stricmp(KnownVulnerable[j], privilegeNameBuffer) == 0) {
                    isVulnerable = TRUE;
                    break;
                }
                j++;
            }
            
            BeaconPrintf(CALLBACK_OUTPUT, "[TOKEN_PRIV] %s: %s %s\n", 
                privilegeNameBuffer, 
                isEnabled ? "Enabled" : "Disabled", 
                isVulnerable ? "- VULNERABLE" : "");
        }
    }

cleanup:
    if (tokenPrivileges) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, tokenPrivileges);
    }
    if (tokenHandle) {
        KERNEL32$CloseHandle(tokenHandle);
    }
}

void CheckLoggedUsers(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] LOGGED USERS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Use WTS API to enumerate sessions
    PWTS_SESSION_INFOA pSessionInfo = NULL;
    DWORD dwCount = 0;
    
    if (WTSAPI32$WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &dwCount)) {
        for (DWORD i = 0; i < dwCount; i++) {
            if (pSessionInfo[i].State == WTSActive || pSessionInfo[i].State == WTSConnected) {
                LPSTR pBuffer = NULL;
                DWORD dwBytesReturned = 0;
                
                if (WTSAPI32$WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, pSessionInfo[i].SessionId, WTSUserName, &pBuffer, &dwBytesReturned)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[LOGGED_USERS] Session %lu: User: %s, State: %lu\n", 
                        pSessionInfo[i].SessionId, pBuffer, pSessionInfo[i].State);
                    WTSAPI32$WTSFreeMemory(pBuffer);
                }
            }
        }
        WTSAPI32$WTSFreeMemory(pSessionInfo);
    }
}

void CheckAutologin(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] AUTOLOGIN CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char valueData[1024];
    DWORD valueSize = sizeof(valueData);
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(valueData);
        if (ADVAPI32$RegQueryValueExA(hKey, "AutoAdminLogon", NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
            if (MSVCRT$strcmp(valueData, "1") == 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGIN] AutoAdminLogon is ENABLED\n");
                
                valueSize = sizeof(valueData);
                if (ADVAPI32$RegQueryValueExA(hKey, "DefaultUserName", NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGIN] DefaultUserName: %s\n", valueData);
                }
                
                valueSize = sizeof(valueData);
                if (ADVAPI32$RegQueryValueExA(hKey, "DefaultPassword", NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGIN] DefaultPassword: %s\n", valueData);
                }
                
                valueSize = sizeof(valueData);
                if (ADVAPI32$RegQueryValueExA(hKey, "DefaultDomainName", NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGIN] DefaultDomainName: %s\n", valueData);
                }
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGIN] AutoAdminLogon is disabled\n");
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGIN] AutoAdminLogon not configured\n");
        }
        ADVAPI32$RegCloseKey(hKey);
    }
}

void CheckPasswordPolicy(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] PASSWORD POLICY CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    DWORD valueData = 0;
    DWORD valueSize = sizeof(DWORD);
    
    // Check account policies in SAM
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "MinPasswordLen", NULL, NULL, (LPBYTE)&valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[PASSWORD_POLICY] MinPasswordLen: %d\n", valueData);
        }
        
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "PasswordHistoryLen", NULL, NULL, (LPBYTE)&valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[PASSWORD_POLICY] PasswordHistoryLen: %d\n", valueData);
        }
        
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check Netlogon settings
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "RequireStrongKey", NULL, NULL, (LPBYTE)&valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[PASSWORD_POLICY] RequireStrongKey: %d\n", valueData);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check account lockout policy
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "LockoutBadCount", NULL, NULL, (LPBYTE)&valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[PASSWORD_POLICY] LockoutBadCount: %d\n", valueData);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[PASSWORD_POLICY] Note: Run 'net accounts' for detailed password policy\n");
}

void CheckDateTime(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] DATE AND TIME CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    SYSTEMTIME st;
    GetSystemTime(&st);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[DATETIME] System Time: %04d-%02d-%02d %02d:%02d:%02d UTC\n", 
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    KERNEL32$GetLocalTime(&st);
    BeaconPrintf(CALLBACK_OUTPUT, "[DATETIME] Local Time: %04d-%02d-%02d %02d:%02d:%02d\n", 
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    // Check timezone from registry
    HKEY hKey;
    char timezoneName[256] = {0};
    DWORD valueSize = sizeof(timezoneName);
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "TimeZoneKeyName", NULL, NULL, (LPBYTE)timezoneName, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[DATETIME] TimeZone: %s\n", timezoneName);
        }
        
        DWORD bias = 0;
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "Bias", NULL, NULL, (LPBYTE)&bias, &valueSize) == ERROR_SUCCESS) {
            int hours = -(int)(bias / 60);
            int minutes = -(int)(bias % 60);
            BeaconPrintf(CALLBACK_OUTPUT, "[DATETIME] UTC Bias: %d minutes (UTC%+03d:%02d)\n", bias, hours, minutes < 0 ? -minutes : minutes);
        }
        
        ADVAPI32$RegCloseKey(hKey);
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[DATETIME] Note: You may need to adjust local date/time to exploit some vulnerability\n");
}

void CheckEverLoggedUsers(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] EVER LOGGED USERS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char usersPath[] = "C:\\Users";
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\*", usersPath);
    int userCount = 0;
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && 
                    MSVCRT$strcmp(findData.cFileName, "..") != 0 &&
                    MSVCRT$strcmp(findData.cFileName, "Public") != 0 &&
                    MSVCRT$strcmp(findData.cFileName, "Default") != 0 &&
                    MSVCRT$strcmp(findData.cFileName, "Default User") != 0) {
                    
                    char userProfilePath[MAX_PATH * 2];
                    MSVCRT$sprintf(userProfilePath, "%s\\%s", usersPath, findData.cFileName);
                    
                    // Check if it's a real user profile (has NTUSER.DAT)
                    char ntuserPath[MAX_PATH * 2];
                    MSVCRT$sprintf(ntuserPath, "%s\\NTUSER.DAT", userProfilePath);
                    
                    HANDLE hFile = CreateFileA(ntuserPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[EVER_LOGGED] %s\n", findData.cFileName);
                        userCount++;
                        KERNEL32$CloseHandle(hFile);
                    }
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData));
        KERNEL32$FindClose(hFind);
    }
    
    if (userCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[EVER_LOGGED] No user profiles found\n");
    }
}

void CheckHomeFolders(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] HOME FOLDERS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char usersPath[] = "C:\\Users";
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\*", usersPath);
    int folderCount = 0;
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && 
                    MSVCRT$strcmp(findData.cFileName, "..") != 0 &&
                    MSVCRT$strcmp(findData.cFileName, "Public") != 0) {
                    
                    char userPath[MAX_PATH * 2];
                    MSVCRT$sprintf(userPath, "%s\\%s", usersPath, findData.cFileName);
                    
                    ULARGE_INTEGER freeBytes, totalBytes;
                    if (KERNEL32$GetDiskFreeSpaceExA(userPath, &freeBytes, &totalBytes, NULL)) {
                        double totalGB = (double)totalBytes.QuadPart / (1024 * 1024 * 1024);
                        BeaconPrintf(CALLBACK_OUTPUT, "[HOME_FOLDERS] %s (Size: %.2f GB)\n", findData.cFileName, totalGB);
                        folderCount++;
                    } else {
                        BeaconPrintf(CALLBACK_OUTPUT, "[HOME_FOLDERS] %s\n", findData.cFileName);
                        folderCount++;
                    }
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData));
        KERNEL32$FindClose(hFind);
    }
    
    if (folderCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[HOME_FOLDERS] No home folders found\n");
    }
}

void CheckLocalUsers(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] LOCAL USERS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char userName[256];
    DWORD userNameSize = sizeof(userName);
    int userCount = 0;
    
    // Check local users in SAM
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users\\Names", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, userName, &userNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            if (MSVCRT$strcmp(userName, ".") != 0 && MSVCRT$strcmp(userName, "..") != 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[LOCAL_USERS] %s\n", userName);
                userCount++;
            }
            userNameSize = sizeof(userName);
        }
        ADVAPI32$RegCloseKey(hKey);
    } else {
        // Fallback: check users directory
        char usersPath[] = "C:\\Users";
        WIN32_FIND_DATA findData;
        char searchPath[MAX_PATH * 2];
        MSVCRT$sprintf(searchPath, "%s\\*", usersPath);
        
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && 
                        MSVCRT$strcmp(findData.cFileName, "..") != 0 &&
                        MSVCRT$strcmp(findData.cFileName, "Public") != 0 &&
                        MSVCRT$strcmp(findData.cFileName, "Default") != 0 &&
                        MSVCRT$strcmp(findData.cFileName, "Default User") != 0) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[LOCAL_USERS] %s\n", findData.cFileName);
                        userCount++;
                    }
                }
            } while (KERNEL32$FindNextFileA(hFind, &findData));
            KERNEL32$FindClose(hFind);
        }
    }
    
    if (userCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[LOCAL_USERS] No local users found\n");
    }
}

void CheckRDPSessions(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] RDP SESSIONS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    PWTS_SESSION_INFOA pSessionInfo = NULL;
    DWORD dwCount = 0;
    DWORD dwRet = 0;
    
    dwRet = WTSAPI32$WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &dwCount);
    if (dwRet != 0 && pSessionInfo != NULL) {
        int sessionCount = 0;
        for (DWORD i = 0; i < dwCount; i++) {
            LPSTR pUserName = NULL;
            DWORD userNameLen = 0;
            
            // Query username for each session
            if (WTSAPI32$WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, pSessionInfo[i].SessionId, WTS_USERNAME, &pUserName, &userNameLen) != 0) {
                if (pUserName != NULL && MSVCRT$strlen(pUserName) > 0) {
                    char* stateStr = "Unknown";
                    switch (pSessionInfo[i].State) {
                        case 0: stateStr = "Active"; break;
                        case 1: stateStr = "Connected"; break;
                        case 2: stateStr = "ConnectQuery"; break;
                        case 3: stateStr = "Shadow"; break;
                        case 4: stateStr = "Disconnected"; break;
                        case 5: stateStr = "Idle"; break;
                        case 6: stateStr = "Listen"; break;
                        case 7: stateStr = "Reset"; break;
                        case 8: stateStr = "Down"; break;
                        case 9: stateStr = "Init"; break;
                    }
                    
                    BeaconPrintf(CALLBACK_OUTPUT, "[RDP_SESSIONS] SessionID: %d, User: %s, State: %s\n", 
                        pSessionInfo[i].SessionId, pUserName, stateStr);
                    sessionCount++;
                }
                if (pUserName) {
                    WTSAPI32$WTSFreeMemory(pUserName);
                }
            }
        }
        WTSAPI32$WTSFreeMemory(pSessionInfo);
        
        if (sessionCount == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[RDP_SESSIONS] No active RDP sessions found\n");
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[RDP_SESSIONS] Failed to enumerate sessions\n");
    }
}

void CheckClipboardText(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] CLIPBOARD TEXT CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Note: Clipboard access requires USER32 APIs which may not be available in BOF context
    // This is a simplified check - full implementation would require OpenClipboard/GetClipboardData
    BeaconPrintf(CALLBACK_OUTPUT, "[CLIPBOARD] Note: Clipboard access may be limited in BOF context\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[CLIPBOARD] Use 'powershell Get-Clipboard' for full clipboard content\n");
}

void CheckLogonSessions(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] LOGON SESSIONS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Note: Full logon sessions enumeration requires LSA API (LsaEnumerateLogonSessions)
    // This is a simplified check using WTSAPI and registry
    
    // Use WTSEnumerateSessionsA which we already have
    PWTS_SESSION_INFOA sessionInfo = NULL;
    DWORD sessionCount = 0;
    
    if (WTSAPI32$WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessionInfo, &sessionCount)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[LOGON_SESSIONS] Found %lu active sessions\n", sessionCount);
        
        for (DWORD i = 0; i < sessionCount && i < 20; i++) {
            char* username = NULL;
            char* domain = NULL;
            DWORD bytesReturned = 0;
            
            // Get username
            if (WTSAPI32$WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, sessionInfo[i].SessionId, WTSUserName, &username, &bytesReturned)) {
                if (username && MSVCRT$strlen(username) > 0) {
                    // Get domain
                    char* domainName = NULL;
                    if (WTSAPI32$WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, sessionInfo[i].SessionId, WTSDomainName, &domainName, &bytesReturned)) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[LOGON_SESSIONS] Session %lu: %s\\%s (State: %d)\n", 
                            sessionInfo[i].SessionId, domainName ? domainName : "", username, sessionInfo[i].State);
                        WTSAPI32$WTSFreeMemory(domainName);
                    } else {
                        BeaconPrintf(CALLBACK_OUTPUT, "[LOGON_SESSIONS] Session %lu: %s (State: %d)\n", 
                            sessionInfo[i].SessionId, username, sessionInfo[i].State);
                    }
                }
                WTSAPI32$WTSFreeMemory(username);
            }
        }
        
        WTSAPI32$WTSFreeMemory(sessionInfo);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[LOGON_SESSIONS] Failed to enumerate sessions (or access denied)\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[LOGON_SESSIONS] Note: Full enumeration requires LSA API (LsaEnumerateLogonSessions)\n");
    }
    
    // Also check registry for logon information
    HKEY hKey;
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char sid[256];
        DWORD sidSize = sizeof(sid);
        int profileCount = 0;
        DWORD subkeyIndex = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, sid, &sidSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && profileCount < 10) {
            HKEY profileKey;
            char profilePath[512];
            MSVCRT$sprintf(profilePath, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%s", sid);
            
            if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, profilePath, 0, KEY_READ, &profileKey) == ERROR_SUCCESS) {
                char profileImagePath[512] = {0};
                DWORD valueSize = sizeof(profileImagePath);
                
                if (ADVAPI32$RegQueryValueExA(profileKey, "ProfileImagePath", NULL, NULL, (LPBYTE)profileImagePath, &valueSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[LOGON_SESSIONS] Profile: %s (SID: %s)\n", profileImagePath, sid);
                    profileCount++;
                }
                ADVAPI32$RegCloseKey(profileKey);
            }
            sidSize = sizeof(sid);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
}


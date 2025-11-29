// ============================================================================
// INTERESTING FILES CHECKS
// ============================================================================

#include "winpeas.h"

void CheckUnattendFiles(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] UNATTEND FILES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char szWinDir[MAX_PATH * 2];
    int NumOfFoundFiles = 0;
    HANDLE hFile;

    if (GetWindowsDirectoryA(szWinDir, sizeof(szWinDir)) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UNATTEND_FILES] Failed to resolve Windows directory\n");
        return;
    }

    static const char * UnattendFiles[] = {
        "\\sysprep\\sysprep.xml",
        "\\sysprep\\sysprep.inf",
        "\\sysprep.inf",
        "\\Panther\\Unattended.xml",
        "\\Panther\\Unattend.xml",
        "\\Panther\\Unattend\\Unattend.xml",
        "\\Panther\\Unattend\\Unattended.xml",
        "\\System32\\Sysprep\\unattend.xml",
        "\\System32\\Sysprep\\Panther\\unattend.xml",
        "\\unattend.txt",
        "\\unattend.inf",
        NULL
    };

    for (int i = 0; UnattendFiles[i] != NULL; i++) {
        char FullPath[MAX_PATH * 2];
        MSVCRT$sprintf(FullPath, "%s%s", szWinDir, UnattendFiles[i]);

        hFile = CreateFileA(FullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_OUTPUT, "[UNATTEND_FILES] Found: %s\n", FullPath);
            NumOfFoundFiles++;
            KERNEL32$CloseHandle(hFile);
        }
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[UNATTEND_FILES] Found a total of %d unattend files\n", NumOfFoundFiles);
}

void CheckSAMBackups(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SAM & SYSTEM BACKUPS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char szWinDir[MAX_PATH * 2];
    if (GetWindowsDirectoryA(szWinDir, sizeof(szWinDir)) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[SAM_BACKUPS] Failed to resolve Windows directory\n");
        return;
    }

    static const char * SAMBackupFiles[] = {
        "\\repair\\SAM",
        "\\System32\\config\\RegBack\\SAM",
        "\\System32\\config\\SAM",
        "\\repair\\SYSTEM",
        "\\System32\\config\\SYSTEM",
        "\\System32\\config\\RegBack\\SYSTEM",
        "\\repair\\SECURITY",
        "\\System32\\config\\SECURITY",
        NULL
    };

    int foundCount = 0;
    for (int i = 0; SAMBackupFiles[i] != NULL; i++) {
        char FullPath[MAX_PATH * 2];
        MSVCRT$sprintf(FullPath, "%s%s", szWinDir, SAMBackupFiles[i]);
        
        HANDLE hFile = CreateFileA(FullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_OUTPUT, "[SAM_BACKUPS] Found: %s\n", FullPath);
            foundCount++;
            KERNEL32$CloseHandle(hFile);
        }
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[SAM_BACKUPS] No SAM/SYSTEM backup files found\n");
    }
}

void CheckGPPPasswords(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] GPP PASSWORD CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    static const char * GPPFiles[] = {
        "C:\\Microsoft\\Group Policy\\history\\Groups.xml",
        "C:\\Microsoft\\Group Policy\\history\\Services.xml",
        "C:\\Microsoft\\Group Policy\\history\\Scheduledtasks.xml",
        "C:\\Microsoft\\Group Policy\\history\\DataSources.xml",
        "C:\\Microsoft\\Group Policy\\history\\Printers.xml",
        "C:\\Microsoft\\Group Policy\\history\\Drives.xml",
        NULL
    };

    int foundCount = 0;
    for (int i = 0; GPPFiles[i] != NULL; i++) {
        HANDLE hFile = CreateFileA(GPPFiles[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_OUTPUT, "[GPP] Found: %s\n", GPPFiles[i]);
            BeaconPrintf(CALLBACK_OUTPUT, "[GPP] Note: Check this file for cpassword (encrypted password)\n");
            foundCount++;
            KERNEL32$CloseHandle(hFile);
        }
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[GPP] No GPP password files found\n");
    }
}

void CheckGroupPolicyHistory(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] GROUP POLICY HISTORY CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char gpoPaths[][MAX_PATH] = {
        "C:\\ProgramData\\Microsoft\\Group Policy\\History",
        "C:\\Documents and Settings\\All Users\\Application Data\\Microsoft\\Group Policy\\History"
    };
    
    char* gpoFiles[] = {
        "Groups.xml",
        "Services.xml",
        "Scheduledtasks.xml",
        "DataSources.xml",
        "Printers.xml",
        "Drives.xml"
    };
    
    int foundCount = 0;
    
    for (int i = 0; i < 2; i++) {
        WIN32_FIND_DATA findData;
        char searchPath[MAX_PATH * 2];
        MSVCRT$sprintf(searchPath, "%s\\*", gpoPaths[i]);
        
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && 
                        MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                        
                        for (int j = 0; j < 6; j++) {
                            char filePath[MAX_PATH * 2];
                            MSVCRT$sprintf(filePath, "%s\\%s\\%s", gpoPaths[i], findData.cFileName, gpoFiles[j]);
                            
                            HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                            if (hFile != INVALID_HANDLE_VALUE) {
                                BeaconPrintf(CALLBACK_OUTPUT, "[GPO_HISTORY] %s\n", filePath);
                                foundCount++;
                                KERNEL32$CloseHandle(hFile);
                            }
                        }
                    }
                }
            } while (KERNEL32$FindNextFileA(hFind, &findData));
            KERNEL32$FindClose(hFind);
        }
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[GPO_HISTORY] No Group Policy history files found\n");
    }
}

void CheckMcAfeeSiteList(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] MCAFEE SITELIST.XML CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    static const char * SiteListPaths[] = {
        "C:\\Program Files\\McAfee\\SiteList.xml",
        "C:\\Program Files (x86)\\McAfee\\SiteList.xml",
        NULL
    };
    
    int foundCount = 0;
    for (int i = 0; SiteListPaths[i] != NULL; i++) {
        HANDLE hFile = CreateFileA(SiteListPaths[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_OUTPUT, "[MCAFEE] Found: %s\n", SiteListPaths[i]);
            BeaconPrintf(CALLBACK_OUTPUT, "[MCAFEE] Note: Check this file for credentials\n");
            foundCount++;
            KERNEL32$CloseHandle(hFile);
        }
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[MCAFEE] No SiteList.xml files found\n");
    }
}

void CheckPuttySessions(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] PUTTY SESSIONS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\SimonTatham\\PuTTY\\Sessions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char sessionName[256];
        DWORD subkeyIndex = 0;
        DWORD subkeyNameSize = sizeof(sessionName);
        int sessionCount = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, sessionName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY sessionKey;
            if (ADVAPI32$RegOpenKeyExA(hKey, sessionName, 0, KEY_READ, &sessionKey) == ERROR_SUCCESS) {
                char hostName[1024] = {0};
                DWORD valueSize = sizeof(hostName);
                if (ADVAPI32$RegQueryValueExA(sessionKey, "HostName", NULL, NULL, (LPBYTE)hostName, &valueSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[PUTTY] Session: %s, Host: %s\n", sessionName, hostName);
                    sessionCount++;
                }
                ADVAPI32$RegCloseKey(sessionKey);
            }
            subkeyNameSize = sizeof(sessionName);
        }
        ADVAPI32$RegCloseKey(hKey);
        
        if (sessionCount == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[PUTTY] No PuTTY sessions found\n");
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[PUTTY] PuTTY not installed or no sessions configured\n");
    }
}

void CheckSuperPutty(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SUPERPUTTY CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for SuperPutty configuration files
    char superPuttyPath[] = "C:\\Users\\%USERNAME%\\Documents\\SuperPuTTY";
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\sessions*.xml", superPuttyPath);
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        int fileCount = 0;
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                char fullPath[MAX_PATH * 2];
                MSVCRT$sprintf(fullPath, "%s\\%s", superPuttyPath, findData.cFileName);
                BeaconPrintf(CALLBACK_OUTPUT, "[SUPERPUTTY] Found config file: %s\n", fullPath);
                fileCount++;
                if (fileCount >= 10) break;
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData) && fileCount < 10);
        KERNEL32$FindClose(hFind);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[SUPERPUTTY] No SuperPutty configuration files found\n");
    }
}

void CheckSSHKeys(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SSH KEYS IN REGISTRY CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char valueName[256];
    char valueData[4096];
    DWORD valueNameSize = sizeof(valueName);
    DWORD valueSize = sizeof(valueData);
    int keyCount = 0;
    
    // Check for SSH keys in registry
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\SimonTatham\\PuTTY\\SshHostKeys", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD valueIndex = 0;
        
        while (ADVAPI32$RegEnumValueA(hKey, valueIndex++, valueName, &valueNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            valueSize = sizeof(valueData);
            if (ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT, "[SSH_KEYS] Host: %s, Key: %s\n", valueName, valueData);
                keyCount++;
            }
            valueNameSize = sizeof(valueName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (keyCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[SSH_KEYS] No SSH host keys found in registry\n");
    }
}

void CheckOfficeRecentFiles(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] OFFICE RECENT FILES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char valueName[256];
    char valueData[1024];
    DWORD valueNameSize = sizeof(valueName);
    DWORD valueSize = sizeof(valueData);
    int fileCount = 0;
    
    // Check Word recent files
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Office\\16.0\\Word\\File MRU", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD valueIndex = 0;
        while (ADVAPI32$RegEnumValueA(hKey, valueIndex++, valueName, &valueNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && fileCount < 10) {
            if (MSVCRT$strcmp(valueName, "MaxDisplay") != 0) {
                valueSize = sizeof(valueData);
                if (ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[OFFICE] Word: %s\n", valueData);
                    fileCount++;
                }
            }
            valueNameSize = sizeof(valueName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check Excel recent files
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Office\\16.0\\Excel\\File MRU", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD valueIndex = 0;
        valueNameSize = sizeof(valueName);
        while (ADVAPI32$RegEnumValueA(hKey, valueIndex++, valueName, &valueNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && fileCount < 20) {
            if (MSVCRT$strcmp(valueName, "MaxDisplay") != 0) {
                valueSize = sizeof(valueData);
                if (ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[OFFICE] Excel: %s\n", valueData);
                    fileCount++;
                }
            }
            valueNameSize = sizeof(valueName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (fileCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[OFFICE] No recent Office files found\n");
    }
}

void CheckOneDriveEndpoints(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] ONEDRIVE OFFICE365 ENDPOINTS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char sid[256];
    DWORD sidSize = sizeof(sid);
    int endpointCount = 0;
    
    // Check for OneDrive sync providers in registry
    if (ADVAPI32$RegOpenKeyExA(HKEY_USERS, NULL, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // This is a simplified check - full implementation would enumerate all SIDs
        BeaconPrintf(CALLBACK_OUTPUT, "[ONEDRIVE] Note: OneDrive endpoints are stored in HKU\\<SID>\\Software\\SyncEngines\\Providers\\OneDrive\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[ONEDRIVE] Note: Check for Office365 endpoints synced by OneDrive\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[ONEDRIVE] Note: Use 'reg query HKU\\<SID>\\Software\\Microsoft\\OneDrive\\Accounts' for detailed info\n");
    } else {
        // Try current user
        if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\OneDrive\\Accounts", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char accountName[256];
            DWORD accountNameSize = sizeof(accountName);
            DWORD subkeyIndex = 0;
            while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, accountName, &accountNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && endpointCount < 5) {
                BeaconPrintf(CALLBACK_OUTPUT, "[ONEDRIVE] Account found: %s\n", accountName);
                endpointCount++;
                accountNameSize = sizeof(accountName);
            }
            ADVAPI32$RegCloseKey(hKey);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[ONEDRIVE] No OneDrive accounts found (or access denied)\n");
        }
    }
}

void CheckWSL(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] WSL CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for WSL executables
    static const char* wslPaths[] = {
        "C:\\Windows\\System32\\wsl.exe",
        "C:\\Windows\\System32\\bash.exe",
        "C:\\Windows\\System32\\lxss\\bash.exe",
        NULL
    };
    
    int foundCount = 0;
    for (int i = 0; wslPaths[i] != NULL; i++) {
        HANDLE hFile = CreateFileA(wslPaths[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_OUTPUT, "[WSL] Found: %s\n", wslPaths[i]);
            foundCount++;
            KERNEL32$CloseHandle(hFile);
        }
    }
    
    // Check for WSL distributions
    char wslPath[] = "C:\\Users";
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\*\\AppData\\Local\\Packages", wslPath);
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                    if (SHLWAPI$StrStrIA(findData.cFileName, "CanonicalGroup") != NULL || 
                        SHLWAPI$StrStrIA(findData.cFileName, "WSL") != NULL) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[WSL] WSL distribution found: %s\n", findData.cFileName);
                        foundCount++;
                    }
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData));
        KERNEL32$FindClose(hFind);
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[WSL] WSL not detected\n");
    }
}

void CheckOracleSQLDeveloper(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] ORACLE SQL DEVELOPER CONFIG FILES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char usersPath[] = "C:\\Users";
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\*", usersPath);
    int foundCount = 0;
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && 
                    MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                    
                    char sqlDevPath[MAX_PATH * 2];
                    MSVCRT$sprintf(sqlDevPath, "%s\\%s\\AppData\\Roaming\\SQL Developer", usersPath, findData.cFileName);
                    
                    char connectionsPath[MAX_PATH * 2];
                    MSVCRT$sprintf(connectionsPath, "%s\\connections*.xml", sqlDevPath);
                    
                    WIN32_FIND_DATA fileData;
                    HANDLE hFileFind = KERNEL32$FindFirstFileA(connectionsPath, &fileData);
                    if (hFileFind != INVALID_HANDLE_VALUE) {
                        do {
                            char fullPath[MAX_PATH * 2];
                            MSVCRT$sprintf(fullPath, "%s\\%s", sqlDevPath, fileData.cFileName);
                            BeaconPrintf(CALLBACK_OUTPUT, "[ORACLE_SQL] %s\n", fullPath);
                            foundCount++;
                        } while (KERNEL32$FindNextFileA(hFileFind, &fileData));
                        KERNEL32$FindClose(hFileFind);
                    }
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData));
        KERNEL32$FindClose(hFind);
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[ORACLE_SQL] No Oracle SQL Developer config files found\n");
    }
}

void CheckSlackFiles(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SLACK FILES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char usersPath[] = "C:\\Users";
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\*", usersPath);
    int foundCount = 0;
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && 
                    MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                    
                    char slackPath[MAX_PATH * 2];
                    MSVCRT$sprintf(slackPath, "%s\\%s\\AppData\\Roaming\\Slack", usersPath, findData.cFileName);
                    
                    HANDLE hDir = CreateFileA(slackPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
                    if (hDir != INVALID_HANDLE_VALUE) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[SLACK] Directory: %s\n", slackPath);
                        foundCount++;
                        KERNEL32$CloseHandle(hDir);
                        
                        // Check for Cookies file
                        char cookiesPath[MAX_PATH * 2];
                        MSVCRT$sprintf(cookiesPath, "%s\\Cookies", slackPath);
                        if (GetFileAttributesA(cookiesPath) != INVALID_FILE_ATTRIBUTES) {
                            BeaconPrintf(CALLBACK_OUTPUT, "[SLACK] File: %s\n", cookiesPath);
                        }
                        
                        // Check for workspaces
                        char workspacesPath[MAX_PATH * 2];
                        MSVCRT$sprintf(workspacesPath, "%s\\storage\\slack-workspaces", slackPath);
                        if (GetFileAttributesA(workspacesPath) != INVALID_FILE_ATTRIBUTES) {
                            BeaconPrintf(CALLBACK_OUTPUT, "[SLACK] File: %s\n", workspacesPath);
                        }
                        
                        // Check for downloads
                        char downloadsPath[MAX_PATH * 2];
                        MSVCRT$sprintf(downloadsPath, "%s\\storage\\slack-downloads", slackPath);
                        if (GetFileAttributesA(downloadsPath) != INVALID_FILE_ATTRIBUTES) {
                            BeaconPrintf(CALLBACK_OUTPUT, "[SLACK] File: %s\n", downloadsPath);
                        }
                    }
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData));
        KERNEL32$FindClose(hFind);
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[SLACK] No Slack files found\n");
    }
}

void CheckOutlookDownloads(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] OUTLOOK DOWNLOADS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char usersPath[] = "C:\\Users";
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\*", usersPath);
    int foundCount = 0;
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && 
                    MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                    
                    char outlookPath[MAX_PATH * 2];
                    MSVCRT$sprintf(outlookPath, "%s\\%s\\AppData\\Local\\Microsoft\\Outlook", usersPath, findData.cFileName);
                    
                    HANDLE hDir = CreateFileA(outlookPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
                    if (hDir != INVALID_HANDLE_VALUE) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[OUTLOOK] Directory: %s\n", outlookPath);
                        foundCount++;
                        KERNEL32$CloseHandle(hDir);
                    }
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData));
        KERNEL32$FindClose(hFind);
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[OUTLOOK] No Outlook directories found\n");
    }
}

void CheckHiddenFiles(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] HIDDEN FILES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char searchPaths[][MAX_PATH] = {
        "C:\\Users",
        "C:\\ProgramData",
        "C:\\Windows\\Temp"
    };
    
    int foundCount = 0;
    
    for (int i = 0; i < 3; i++) {
        WIN32_FIND_DATA findData;
        char searchPath[MAX_PATH * 2];
        MSVCRT$sprintf(searchPath, "%s\\*", searchPaths[i]);
        
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) {
                    char fullPath[MAX_PATH * 2];
                    MSVCRT$sprintf(fullPath, "%s\\%s", searchPaths[i], findData.cFileName);
                    
                    // Only show interesting hidden files
                    if (SHLWAPI$StrStrIA(findData.cFileName, ".config") != NULL ||
                        SHLWAPI$StrStrIA(findData.cFileName, "credential") != NULL ||
                        SHLWAPI$StrStrIA(findData.cFileName, "password") != NULL ||
                        SHLWAPI$StrStrIA(findData.cFileName, ".key") != NULL ||
                        SHLWAPI$StrStrIA(findData.cFileName, ".pem") != NULL) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[HIDDEN] %s\n", fullPath);
                        foundCount++;
                        if (foundCount >= 20) { // Limit output
                            BeaconPrintf(CALLBACK_OUTPUT, "[HIDDEN] ... (showing first 20)\n");
                            break;
                        }
                    }
                }
            } while (KERNEL32$FindNextFileA(hFind, &findData) && foundCount < 20);
            KERNEL32$FindClose(hFind);
        }
        if (foundCount >= 20) break;
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[HIDDEN] No interesting hidden files found\n");
    }
}

void CheckUserCredsFiles(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] USER CREDENTIALS FILES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char usersPath[] = "C:\\Users";
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\*", usersPath);
    int foundCount = 0;
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && 
                    MSVCRT$strcmp(findData.cFileName, "..") != 0 &&
                    MSVCRT$strcmp(findData.cFileName, "Public") != 0) {
                    
                    char userPath[MAX_PATH * 2];
                    MSVCRT$sprintf(userPath, "%s\\%s", usersPath, findData.cFileName);
                    
                    // Search for credential/password files
                    char searchPattern[MAX_PATH * 2];
                    MSVCRT$sprintf(searchPattern, "%s\\*credential*", userPath);
                    
                    WIN32_FIND_DATA fileData;
                    HANDLE hFileFind = KERNEL32$FindFirstFileA(searchPattern, &fileData);
                    if (hFileFind != INVALID_HANDLE_VALUE) {
                        do {
                            if (!(fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                                char fullPath[MAX_PATH * 2];
                                MSVCRT$sprintf(fullPath, "%s\\%s", userPath, fileData.cFileName);
                                BeaconPrintf(CALLBACK_OUTPUT, "[USER_CREDS] %s\n", fullPath);
                                foundCount++;
                                if (foundCount >= 20) break;
                            }
                        } while (KERNEL32$FindNextFileA(hFileFind, &fileData) && foundCount < 20);
                        KERNEL32$FindClose(hFileFind);
                    }
                    
                    if (foundCount < 20) {
                        MSVCRT$sprintf(searchPattern, "%s\\*password*", userPath);
                        hFileFind = KERNEL32$FindFirstFileA(searchPattern, &fileData);
                        if (hFileFind != INVALID_HANDLE_VALUE) {
                            do {
                                if (!(fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                                    char fullPath[MAX_PATH * 2];
                                    MSVCRT$sprintf(fullPath, "%s\\%s", userPath, fileData.cFileName);
                                    BeaconPrintf(CALLBACK_OUTPUT, "[USER_CREDS] %s\n", fullPath);
                                    foundCount++;
                                    if (foundCount >= 20) break;
                                }
                            } while (KERNEL32$FindNextFileA(hFileFind, &fileData) && foundCount < 20);
                            KERNEL32$FindClose(hFileFind);
                        }
                    }
                }
            }
            if (foundCount >= 20) break;
        } while (KERNEL32$FindNextFileA(hFind, &findData));
        KERNEL32$FindClose(hFind);
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[USER_CREDS] No credential/password files found\n");
    } else if (foundCount >= 20) {
        BeaconPrintf(CALLBACK_OUTPUT, "[USER_CREDS] ... (showing first 20)\n");
    }
}

void CheckUserDocuments(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] USER DOCUMENTS CHECK (Limit 100)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for user documents in common locations
    char docPaths[][MAX_PATH] = {
        "C:\\Users\\%USERNAME%\\Documents",
        "C:\\Users\\%USERNAME%\\Desktop",
        "C:\\Users\\%USERNAME%\\Downloads"
    };
    
    int docCount = 0;
    for (int i = 0; i < 3 && docCount < 100; i++) {
        WIN32_FIND_DATA findData;
        char searchPath[MAX_PATH * 2];
        MSVCRT$sprintf(searchPath, "%s\\*", docPaths[i]);
        
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    // Check for interesting file extensions
                    char* ext = NULL;
                    char* p = findData.cFileName;
                    while (*p) {
                        if (*p == '.') ext = p;
                        p++;
                    }
                    if (ext != NULL) {
                        if (SHLWAPI$StrStrIA(ext, ".txt") != NULL ||
                            SHLWAPI$StrStrIA(ext, ".doc") != NULL ||
                            SHLWAPI$StrStrIA(ext, ".xls") != NULL ||
                            SHLWAPI$StrStrIA(ext, ".pdf") != NULL ||
                            SHLWAPI$StrStrIA(ext, ".xml") != NULL ||
                            SHLWAPI$StrStrIA(ext, ".json") != NULL) {
                            char fullPath[MAX_PATH * 2];
                            MSVCRT$sprintf(fullPath, "%s\\%s", docPaths[i], findData.cFileName);
                            BeaconPrintf(CALLBACK_OUTPUT, "[USER_DOCS] %s\n", fullPath);
                            docCount++;
                            if (docCount >= 100) break;
                        }
                    }
                }
            } while (KERNEL32$FindNextFileA(hFind, &findData) && docCount < 100);
            KERNEL32$FindClose(hFind);
        }
    }
    
    if (docCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[USER_DOCS] No documents found (or access denied)\n");
    } else if (docCount >= 100) {
        BeaconPrintf(CALLBACK_OUTPUT, "[USER_DOCS] ... (showing first 100)\n");
    }
}

void CheckRecentFiles(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] RECENT FILES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for recent files shortcuts
    char recentPath[] = "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Recent";
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\*.lnk", recentPath);
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        int fileCount = 0;
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                char fullPath[MAX_PATH * 2];
                MSVCRT$sprintf(fullPath, "%s\\%s", recentPath, findData.cFileName);
                BeaconPrintf(CALLBACK_OUTPUT, "[RECENT_FILES] %s\n", fullPath);
                fileCount++;
                if (fileCount >= 70) break;
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData) && fileCount < 70);
        KERNEL32$FindClose(hFind);
        
        if (fileCount >= 70) {
            BeaconPrintf(CALLBACK_OUTPUT, "[RECENT_FILES] ... (showing first 70)\n");
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[RECENT_FILES] No recent files found (or access denied)\n");
    }
}

void CheckRecycleBin(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] RECYCLE BIN CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check Recycle Bin paths for each drive
    char drives[] = "C:\\";
    char recyclePath[MAX_PATH * 2];
    MSVCRT$sprintf(recyclePath, "%s$Recycle.Bin", drives);
    
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\*", recyclePath);
    int foundCount = 0;
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && 
                    MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                    
                    // Check for interesting files in recycle bin
                    char userRecyclePath[MAX_PATH * 2];
                    MSVCRT$sprintf(userRecyclePath, "%s\\%s", recyclePath, findData.cFileName);
                    
                    char fileSearchPath[MAX_PATH * 2];
                    MSVCRT$sprintf(fileSearchPath, "%s\\*", userRecyclePath);
                    
                    WIN32_FIND_DATA fileData;
                    HANDLE hFileFind = KERNEL32$FindFirstFileA(fileSearchPath, &fileData);
                    if (hFileFind != INVALID_HANDLE_VALUE) {
                        do {
                            if (!(fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                                // Check for interesting file names
                                if (SHLWAPI$StrStrIA(fileData.cFileName, "password") != NULL ||
                                    SHLWAPI$StrStrIA(fileData.cFileName, "credential") != NULL ||
                                    SHLWAPI$StrStrIA(fileData.cFileName, ".kdbx") != NULL ||
                                    SHLWAPI$StrStrIA(fileData.cFileName, ".key") != NULL ||
                                    SHLWAPI$StrStrIA(fileData.cFileName, ".pem") != NULL) {
                                    char fullPath[MAX_PATH * 2];
                                    MSVCRT$sprintf(fullPath, "%s\\%s", userRecyclePath, fileData.cFileName);
                                    BeaconPrintf(CALLBACK_OUTPUT, "[RECYCLE_BIN] %s\n", fullPath);
                                    foundCount++;
                                    if (foundCount >= 10) break;
                                }
                            }
                        } while (KERNEL32$FindNextFileA(hFileFind, &fileData) && foundCount < 10);
                        KERNEL32$FindClose(hFileFind);
                    }
                }
            }
            if (foundCount >= 10) break;
        } while (KERNEL32$FindNextFileA(hFind, &findData));
        KERNEL32$FindClose(hFind);
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[RECYCLE_BIN] No interesting files found in Recycle Bin\n");
    } else if (foundCount >= 10) {
        BeaconPrintf(CALLBACK_OUTPUT, "[RECYCLE_BIN] ... (showing first 10)\n");
    }
}

void CheckExecutablesWithWritePerms(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] EXECUTABLES WITH WRITE PERMISSIONS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char searchPaths[][MAX_PATH] = {
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\ProgramData"
    };
    
    int foundCount = 0;
    
    for (int i = 0; i < 3 && foundCount < 10; i++) {
        WIN32_FIND_DATA findData;
        char searchPath[MAX_PATH * 2];
        MSVCRT$sprintf(searchPath, "%s\\*.exe", searchPaths[i]);
        
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    char fullPath[MAX_PATH * 2];
                    MSVCRT$sprintf(fullPath, "%s\\%s", searchPaths[i], findData.cFileName);
                    
                    // Try to open file for write (simple check)
                    HANDLE hFile = CreateFileA(fullPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[EXEC_WRITE] %s (writable)\n", fullPath);
                        foundCount++;
                        KERNEL32$CloseHandle(hFile);
                    }
                }
            } while (KERNEL32$FindNextFileA(hFind, &findData) && foundCount < 10);
            KERNEL32$FindClose(hFind);
        }
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[EXEC_WRITE] No writable executables found in common directories\n");
    } else if (foundCount >= 10) {
        BeaconPrintf(CALLBACK_OUTPUT, "[EXEC_WRITE] ... (showing first 10)\n");
    }
}

void CheckCloudCredsFiles(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] CLOUD CREDENTIALS FILES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char usersPath[] = "C:\\Users";
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\*", usersPath);
    int foundCount = 0;
    
    char* cloudFiles[] = {
        "accessTokens.json",
        "azureProfile.json",
        "credentials",
        ".aws\\credentials",
        ".azure\\accessTokens.json"
    };
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && 
                    MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                    
                    for (int i = 0; i < 5; i++) {
                        char cloudPath[MAX_PATH * 2];
                        MSVCRT$sprintf(cloudPath, "%s\\%s\\%s", usersPath, findData.cFileName, cloudFiles[i]);
                        
                        HANDLE hFile = CreateFileA(cloudPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                        if (hFile != INVALID_HANDLE_VALUE) {
                            BeaconPrintf(CALLBACK_OUTPUT, "[CLOUD_CREDS] %s\n", cloudPath);
                            foundCount++;
                            KERNEL32$CloseHandle(hFile);
                        }
                    }
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData));
        KERNEL32$FindClose(hFind);
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[CLOUD_CREDS] No cloud credentials files found\n");
    }
}

void CheckCertificates(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] CERTIFICATES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check certificate stores in registry
    HKEY hKey;
    char storeName[256];
    DWORD storeNameSize = sizeof(storeName);
    int certCount = 0;
    
    // Check Current User certificates
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\SystemCertificates", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, storeName, &storeNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && certCount < 10) {
            BeaconPrintf(CALLBACK_OUTPUT, "[CERTIFICATES] CurrentUser Store: %s\n", storeName);
            certCount++;
            storeNameSize = sizeof(storeName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check Local Machine certificates
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\SystemCertificates", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, storeName, &storeNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && certCount < 20) {
            BeaconPrintf(CALLBACK_OUTPUT, "[CERTIFICATES] LocalMachine Store: %s\n", storeName);
            certCount++;
            storeNameSize = sizeof(storeName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (certCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[CERTIFICATES] No certificate stores found\n");
    } else if (certCount >= 20) {
        BeaconPrintf(CALLBACK_OUTPUT, "[CERTIFICATES] ... (showing first 20 stores)\n");
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[CERTIFICATES] Note: Use 'certutil -store' for detailed certificate information\n");
}

void CheckCloudMetadata(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] CLOUD METADATA ENUMERATION\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check AWS
    char awsPath[] = "C:\\Program Files\\Amazon\\";
    DWORD awsAttrib = GetFileAttributesA(awsPath);
    if (awsAttrib != INVALID_FILE_ATTRIBUTES && (awsAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[CLOUD] AWS EC2 detected: %s exists\n", awsPath);
        BeaconPrintf(CALLBACK_OUTPUT, "[CLOUD] Note: Try accessing http://169.254.169.254/latest/meta-data/\n");
    }
    
    // Check Azure
    char azurePath[] = "C:\\WindowsAzure";
    DWORD azureAttrib = GetFileAttributesA(azurePath);
    if (azureAttrib != INVALID_FILE_ATTRIBUTES && (azureAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[CLOUD] Azure VM detected: %s exists\n", azurePath);
        BeaconPrintf(CALLBACK_OUTPUT, "[CLOUD] Note: Try accessing http://169.254.169.254/metadata/instance\n");
    }
    
    // Check GCP
    char gcpPath[] = "C:\\Program Files\\Google\\Compute Engine\\";
    DWORD gcpAttrib = GetFileAttributesA(gcpPath);
    if (gcpAttrib != INVALID_FILE_ATTRIBUTES && (gcpAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[CLOUD] Google Cloud Platform detected: %s exists\n", gcpPath);
        BeaconPrintf(CALLBACK_OUTPUT, "[CLOUD] Note: Try accessing http://metadata.google.internal/computeMetadata/v1/\n");
    }
    
    if (awsAttrib == INVALID_FILE_ATTRIBUTES && azureAttrib == INVALID_FILE_ATTRIBUTES && gcpAttrib == INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[CLOUD] No cloud provider indicators found\n");
    }
}


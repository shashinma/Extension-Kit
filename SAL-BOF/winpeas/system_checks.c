// ============================================================================
// SYSTEM INFORMATION CHECKS
// ============================================================================

#include "winpeas.h"

void CheckBasicSystemInfo(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] BASIC SYSTEM INFORMATION\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    OSVERSIONINFOA osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
    if (GetVersionExA((LPOSVERSIONINFOA)&osvi)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[SYS_INFO] OS Version: %d.%d Build %d\n", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
        BeaconPrintf(CALLBACK_OUTPUT, "[SYS_INFO] OS Platform: %d\n", osvi.dwPlatformId);
        if (osvi.szCSDVersion[0]) {
            BeaconPrintf(CALLBACK_OUTPUT, "[SYS_INFO] Service Pack: %s\n", osvi.szCSDVersion);
        }
    }
    
    SYSTEM_INFO si = {0};
    GetNativeSystemInfo(&si);
    BeaconPrintf(CALLBACK_OUTPUT, "[SYS_INFO] Processor Architecture: %d\n", si.wProcessorArchitecture);
    BeaconPrintf(CALLBACK_OUTPUT, "[SYS_INFO] Number of Processors: %d\n", si.dwNumberOfProcessors);
}

void CheckUACSettings(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] UAC SETTINGS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    DWORD uacValue = 0;
    DWORD bufferSize = sizeof(DWORD);
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "EnableLUA", NULL, NULL, (LPBYTE)&uacValue, &bufferSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[UAC] EnableLUA: %d\n", uacValue);
        }
        bufferSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "ConsentPromptBehaviorAdmin", NULL, NULL, (LPBYTE)&uacValue, &bufferSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[UAC] ConsentPromptBehaviorAdmin: %d\n", uacValue);
        }
        bufferSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "ConsentPromptBehaviorUser", NULL, NULL, (LPBYTE)&uacValue, &bufferSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[UAC] ConsentPromptBehaviorUser: %d\n", uacValue);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
}

void CheckLSAProtection(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] LSA PROTECTION CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    DWORD runAsPPL = 0;
    DWORD bufferSize = sizeof(DWORD);
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "RunAsPPL", NULL, NULL, (LPBYTE)&runAsPPL, &bufferSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[LSA] RunAsPPL: %d %s\n", runAsPPL, runAsPPL ? "- PROTECTED" : "- NOT PROTECTED");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[LSA] RunAsPPL not set (default: disabled)\n");
        }
        ADVAPI32$RegCloseKey(hKey);
    }
}

void CheckCredentialGuard(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] CREDENTIAL GUARD CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    DWORD lsaCfgFlags = 0;
    DWORD bufferSize = sizeof(DWORD);
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "LsaCfgFlags", NULL, NULL, (LPBYTE)&lsaCfgFlags, &bufferSize) == ERROR_SUCCESS) {
            if (lsaCfgFlags == 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[CRED_GUARD] LsaCfgFlags: 0 - Credential Guard is DISABLED\n");
            } else if (lsaCfgFlags == 1) {
                BeaconPrintf(CALLBACK_OUTPUT, "[CRED_GUARD] LsaCfgFlags: 1 - Credential Guard is ENABLED with UEFI lock\n");
            } else if (lsaCfgFlags == 2) {
                BeaconPrintf(CALLBACK_OUTPUT, "[CRED_GUARD] LsaCfgFlags: 2 - Credential Guard is ENABLED without lock\n");
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[CRED_GUARD] LsaCfgFlags: %d\n", lsaCfgFlags);
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[CRED_GUARD] LsaCfgFlags not set (default: disabled)\n");
        }
        ADVAPI32$RegCloseKey(hKey);
    }
}

void CheckLAPS(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] LAPS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft Services\\AdmPwd", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[LAPS] LAPS is installed\n");
        ADVAPI32$RegCloseKey(hKey);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[LAPS] LAPS not installed or not configured\n");
    }
}

void CheckWDigest(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] WDIGEST CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    DWORD useLogonCredential = 0;
    DWORD bufferSize = sizeof(DWORD);
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "UseLogonCredential", NULL, NULL, (LPBYTE)&useLogonCredential, &bufferSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[WDIGEST] UseLogonCredential: %d %s\n", useLogonCredential, useLogonCredential ? "- VULNERABLE (passwords in memory)" : "- Secure");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[WDIGEST] UseLogonCredential not set (default: disabled on Win8.1+)\n");
        }
        ADVAPI32$RegCloseKey(hKey);
    }
}

void CheckCachedCredentials(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] CACHED CREDENTIALS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    DWORD cachedLogonsCount = 0;
    DWORD bufferSize = sizeof(DWORD);
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "CachedLogonsCount", NULL, NULL, (LPBYTE)&cachedLogonsCount, &bufferSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[CACHED_CREDS] CachedLogonsCount: %d\n", cachedLogonsCount);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[CACHED_CREDS] CachedLogonsCount not set (default: 10)\n");
        }
        ADVAPI32$RegCloseKey(hKey);
    }
}

void CheckEnvironmentVariables(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] ENVIRONMENT VARIABLES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    LPWCH lpvEnv = KERNEL32$GetEnvironmentStringsW();
    if (lpvEnv) {
        LPWSTR lpszVariable = (LPWSTR)lpvEnv;
        int count = 0;
        while (*lpszVariable && count < 50) { // Limit output
            SIZE_T envLength = KERNEL32$lstrlenW(lpszVariable);
            char* convertedEnv = (char*)intAlloc(envLength + 1);
            KERNEL32$WideCharToMultiByte(CP_ACP, 0, lpszVariable, (int)envLength, convertedEnv, (int)(envLength + 1), NULL, NULL);
            convertedEnv[envLength] = '\0';
            
            // Check for interesting variables
            if (MSVCRT$strstr(convertedEnv, "PASSWORD") || 
                MSVCRT$strstr(convertedEnv, "SECRET") ||
                MSVCRT$strstr(convertedEnv, "KEY") ||
                MSVCRT$strstr(convertedEnv, "TOKEN") ||
                MSVCRT$strstr(convertedEnv, "API")) {
                BeaconPrintf(CALLBACK_OUTPUT, "[ENV] %s\n", convertedEnv);
            }
            lpszVariable += envLength + 1;
            intFree(convertedEnv);
            count++;
        }
        KERNEL32$FreeEnvironmentStringsA((LPSTR)lpvEnv);
    }
}

void CheckInternetSettings(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] INTERNET SETTINGS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char valueData[1024];
    DWORD valueSize = sizeof(valueData);
    
    // Check HKCU Internet Settings
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[INTERNET_SETTINGS] HKCU Settings:\n");
        
        valueSize = sizeof(valueData);
        if (ADVAPI32$RegQueryValueExA(hKey, "ProxyServer", NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[INTERNET_SETTINGS] ProxyServer: %s\n", valueData);
        }
        
        valueSize = sizeof(valueData);
        if (ADVAPI32$RegQueryValueExA(hKey, "ProxyEnable", NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[INTERNET_SETTINGS] ProxyEnable: %d\n", *(DWORD*)valueData);
        }
        
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check HKLM Internet Settings
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[INTERNET_SETTINGS] HKLM Settings:\n");
        
        valueSize = sizeof(valueData);
        if (ADVAPI32$RegQueryValueExA(hKey, "ProxyServer", NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[INTERNET_SETTINGS] ProxyServer: %s\n", valueData);
        }
        
        ADVAPI32$RegCloseKey(hKey);
    }
}

void CheckWindowsDefender(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] WINDOWS DEFENDER CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    DWORD valueData = 0;
    DWORD valueSize = sizeof(DWORD);
    
    // Check if Windows Defender is enabled
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[DEFENDER] Windows Defender registry key exists\n");
        
        // Check exclusions
        HKEY exclusionsKey;
        if (ADVAPI32$RegOpenKeyExA(hKey, "Exclusions\\Paths", 0, KEY_READ, &exclusionsKey) == ERROR_SUCCESS) {
            char valueName[256];
            DWORD valueNameSize = sizeof(valueName);
            DWORD valueIndex = 0;
            int exclusionCount = 0;
            
            while (ADVAPI32$RegEnumValueA(exclusionsKey, valueIndex++, valueName, &valueNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT, "[DEFENDER] Path Exclusion: %s\n", valueName);
                exclusionCount++;
                valueNameSize = sizeof(valueName);
            }
            
            if (exclusionCount == 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[DEFENDER] No path exclusions found\n");
            }
            ADVAPI32$RegCloseKey(exclusionsKey);
        }
        
        ADVAPI32$RegCloseKey(hKey);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[DEFENDER] Windows Defender registry key not found\n");
    }
}

void CheckNTLMSettings(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] NTLM SETTINGS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    DWORD valueData = 0;
    DWORD valueSize = sizeof(DWORD);
    
    // Check LanmanCompatibilityLevel
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "LmCompatibilityLevel", NULL, NULL, (LPBYTE)&valueData, &valueSize) == ERROR_SUCCESS) {
            const char* levelDesc[] = {
                "Send LM & NTLM responses",
                "Send LM & NTLM - Use NTLMv2 session security if negotiated",
                "Send NTLM response only",
                "Send NTLMv2 response only (Win7+ default)",
                "Send NTLMv2 response only. DC: Refuse LM",
                "Send NTLMv2 response only. DC: Refuse LM & NTLM"
            };
            const char* desc = (valueData < 6) ? levelDesc[valueData] : "Unknown";
            BeaconPrintf(CALLBACK_OUTPUT, "[NTLM] LmCompatibilityLevel: %d (%s)\n", valueData, desc);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check NTLM signing settings
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "RequireSecuritySignature", NULL, NULL, (LPBYTE)&valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[NTLM] Client RequireSecuritySignature: %d\n", valueData);
        }
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "EnableSecuritySignature", NULL, NULL, (LPBYTE)&valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[NTLM] Client EnableSecuritySignature: %d\n", valueData);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check NTLM restrictions
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "RestrictReceivingNTLMTraffic", NULL, NULL, (LPBYTE)&valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[NTLM] RestrictReceivingNTLMTraffic: %d\n", valueData);
        }
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "RestrictSendingNTLMTraffic", NULL, NULL, (LPBYTE)&valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[NTLM] RestrictSendingNTLMTraffic: %d\n", valueData);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
}

void CheckDrives(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] DRIVES INFORMATION CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    DWORD drives = KERNEL32$GetLogicalDrives();
    if (drives == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[DRIVES] Failed to get logical drives\n");
        return;
    }
    
    char driveLetter[] = "A:\\";
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            driveLetter[0] = 'A' + i;
            DWORD driveType = KERNEL32$GetDriveTypeA(driveLetter);
            
            const char* typeStr[] = {
                "Unknown",
                "Invalid",
                "Removable",
                "Fixed",
                "Remote",
                "CD-ROM",
                "RAM Disk"
            };
            const char* type = (driveType < 7) ? typeStr[driveType] : "Unknown";
            
            ULARGE_INTEGER freeBytes, totalBytes;
            if (KERNEL32$GetDiskFreeSpaceExA(driveLetter, &freeBytes, &totalBytes, NULL)) {
                double freeGB = (double)freeBytes.QuadPart / (1024 * 1024 * 1024);
                double totalGB = (double)totalBytes.QuadPart / (1024 * 1024 * 1024);
                BeaconPrintf(CALLBACK_OUTPUT, "[DRIVES] %s - Type: %s, Free: %.2f GB / Total: %.2f GB\n", 
                    driveLetter, type, freeGB, totalGB);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[DRIVES] %s - Type: %s\n", driveLetter, type);
            }
        }
    }
}

void CheckPrinters(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] PRINTERS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char subkeyName[256];
    DWORD subkeyNameSize = sizeof(subkeyName);
    int printerCount = 0;
    
    // Check printers in registry
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY printerKey;
            if (ADVAPI32$RegOpenKeyExA(hKey, subkeyName, 0, KEY_READ, &printerKey) == ERROR_SUCCESS) {
                char portName[256] = {0};
                DWORD valueSize = sizeof(portName);
                
                if (ADVAPI32$RegQueryValueExA(printerKey, "Port", NULL, NULL, (LPBYTE)portName, &valueSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[PRINTERS] %s (Port: %s)\n", subkeyName, portName);
                    printerCount++;
                }
                ADVAPI32$RegCloseKey(printerKey);
            }
            subkeyNameSize = sizeof(subkeyName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (printerCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PRINTERS] No printers found\n");
    }
}

void CheckNamedPipes(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] NAMED PIPES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    WIN32_FIND_DATA findData;
    char searchPath[] = "\\\\.\\pipe\\*";
    int pipeCount = 0;
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[NAMED_PIPES] %s\n", findData.cFileName);
                pipeCount++;
                if (pipeCount >= 50) { // Limit output
                    BeaconPrintf(CALLBACK_OUTPUT, "[NAMED_PIPES] ... (showing first 50)\n");
                    break;
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData));
        KERNEL32$FindClose(hFind);
    }
    
    if (pipeCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[NAMED_PIPES] No named pipes found\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[NAMED_PIPES] Found %d named pipes\n", pipeCount);
    }
}

void CheckAMSIProviders(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] AMSI PROVIDERS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char subkeyName[256];
    DWORD subkeyNameSize = sizeof(subkeyName);
    int providerCount = 0;
    
    // Check AMSI providers
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\AMSI\\Providers", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY providerKey;
            char providerPath[1024] = {0};
            DWORD valueSize = sizeof(providerPath);
            
            // Check InprocServer32 path
            char clsidPath[512];
            MSVCRT$sprintf(clsidPath, "SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", subkeyName);
            
            if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, clsidPath, 0, KEY_READ, &providerKey) == ERROR_SUCCESS) {
                if (ADVAPI32$RegQueryValueExA(providerKey, "", NULL, NULL, (LPBYTE)providerPath, &valueSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[AMSI] Provider: %s\n", subkeyName);
                    BeaconPrintf(CALLBACK_OUTPUT, "[AMSI]   Path: %s\n", providerPath);
                    providerCount++;
                }
                ADVAPI32$RegCloseKey(providerKey);
            }
            subkeyNameSize = sizeof(subkeyName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (providerCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AMSI] No AMSI providers found\n");
    }
}

void CheckDotNetVersions(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] .NET VERSIONS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char version[256] = {0};
    DWORD valueSize = sizeof(version);
    
    // Check .NET Framework 3.5
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v3.5", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "Version", NULL, NULL, (LPBYTE)version, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[.NET] Framework 3.5: %s\n", version);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check .NET Framework 4.x
    valueSize = sizeof(version);
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "Version", NULL, NULL, (LPBYTE)version, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[.NET] Framework 4.x: %s\n", version);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check CLR versions in Framework folder
    char frameworkPath[] = "C:\\Windows\\Microsoft.NET\\Framework";
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\*", frameworkPath);
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                    if (findData.cFileName[0] == 'v') {
                        char systemDllPath[MAX_PATH * 2];
                        MSVCRT$sprintf(systemDllPath, "%s\\%s\\System.dll", frameworkPath, findData.cFileName);
                        
                        HANDLE hFile = CreateFileA(systemDllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                        if (hFile != INVALID_HANDLE_VALUE) {
                            BeaconPrintf(CALLBACK_OUTPUT, "[.NET] CLR Version: %s\n", findData.cFileName);
                            KERNEL32$CloseHandle(hFile);
                        }
                    }
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData));
        KERNEL32$FindClose(hFind);
    }
}

void CheckMicrosoftUpdates(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] MICROSOFT UPDATES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for installed hotfixes in registry
    HKEY hKey;
    char hotfixId[256];
    DWORD hotfixIdSize = sizeof(hotfixId);
    int updateCount = 0;
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, hotfixId, &hotfixIdSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && updateCount < 20) {
            BeaconPrintf(CALLBACK_OUTPUT, "[UPDATES] Hotfix: %s\n", hotfixId);
            updateCount++;
            hotfixIdSize = sizeof(hotfixId);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (updateCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPDATES] No hotfixes found in registry (or access denied)\n");
    } else if (updateCount >= 20) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPDATES] ... (showing first 20)\n");
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[UPDATES] Note: Use 'wmic qfe list' or 'Get-HotFix' for full list\n");
}

void CheckSysMon(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SYSMON CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char valueName[256];
    DWORD valueType = 0;
    DWORD valueSize = 0;
    
    // Check if SysMon is installed
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[SYSMON] SysMon driver is installed\n");
        
        // Check HashingAlgorithm
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "HashingAlgorithm", NULL, &valueType, NULL, &valueSize) == ERROR_SUCCESS) {
            DWORD hashAlg = 0;
            ADVAPI32$RegQueryValueExA(hKey, "HashingAlgorithm", NULL, &valueType, (LPBYTE)&hashAlg, &valueSize);
            BeaconPrintf(CALLBACK_OUTPUT, "[SYSMON] HashingAlgorithm: %d\n", hashAlg);
        }
        
        // Check Options
        valueSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "Options", NULL, &valueType, NULL, &valueSize) == ERROR_SUCCESS) {
            DWORD options = 0;
            ADVAPI32$RegQueryValueExA(hKey, "Options", NULL, &valueType, (LPBYTE)&options, &valueSize);
            BeaconPrintf(CALLBACK_OUTPUT, "[SYSMON] Options: 0x%x\n", options);
        }
        
        // Check if Rules exist
        valueSize = 0;
        if (ADVAPI32$RegQueryValueExA(hKey, "Rules", NULL, &valueType, NULL, &valueSize) == ERROR_SUCCESS && valueSize > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[SYSMON] Rules configured: Yes (%d bytes)\n", valueSize);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[SYSMON] Rules configured: No\n");
        }
        
        ADVAPI32$RegCloseKey(hKey);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[SYSMON] SysMon driver not installed (or access denied)\n");
    }
}

void CheckAppLocker(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] APPLOCKER CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char ruleType[256];
    DWORD ruleTypeSize = sizeof(ruleType);
    int ruleCount = 0;
    
    // Check AppLocker policy in registry
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[APPLOCKER] AppLocker policy found\n");
        
        DWORD subkeyIndex = 0;
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, ruleType, &ruleTypeSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && ruleCount < 10) {
            BeaconPrintf(CALLBACK_OUTPUT, "[APPLOCKER] Rule Type: %s\n", ruleType);
            ruleCount++;
            ruleTypeSize = sizeof(ruleType);
        }
        ADVAPI32$RegCloseKey(hKey);
    } else {
        // Check alternative location
        if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\AppLocker", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[APPLOCKER] AppLocker configuration found (alternative location)\n");
            ADVAPI32$RegCloseKey(hKey);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[APPLOCKER] No AppLocker policy found (or access denied)\n");
        }
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[APPLOCKER] Note: Use 'Get-AppLockerPolicy' for detailed policy information\n");
}

void CheckAuditSettings(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] AUDIT SETTINGS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char valueName[256];
    DWORD valueType = 0;
    DWORD valueSize = 0;
    int settingCount = 0;
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUDIT] Audit settings found\n");
        
        DWORD valueIndex = 0;
        while (ADVAPI32$RegEnumValueA(hKey, valueIndex++, valueName, &valueSize, NULL, &valueType, NULL, NULL) == ERROR_SUCCESS && settingCount < 20) {
            valueSize = sizeof(valueName);
            valueSize = 0;
            ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, &valueType, NULL, &valueSize);
            
            if (valueType == REG_DWORD && valueSize == sizeof(DWORD)) {
                DWORD value = 0;
                ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, &valueType, (LPBYTE)&value, &valueSize);
                BeaconPrintf(CALLBACK_OUTPUT, "[AUDIT] %s: %d\n", valueName, value);
            } else if (valueType == REG_SZ || valueType == REG_MULTI_SZ) {
                char* buffer = (char*)MSVCRT$calloc(valueSize + 1, 1);
                if (buffer) {
                    ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, &valueType, (LPBYTE)buffer, &valueSize);
                    BeaconPrintf(CALLBACK_OUTPUT, "[AUDIT] %s: %s\n", valueName, buffer);
                    MSVCRT$free(buffer);
                }
            }
            settingCount++;
            valueSize = sizeof(valueName);
        }
        ADVAPI32$RegCloseKey(hKey);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUDIT] No audit settings found (or access denied)\n");
    }
}

void CheckWEFSettings(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] WEF (WINDOWS EVENT FORWARDING) SETTINGS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char valueName[256];
    DWORD valueType = 0;
    DWORD valueSize = 0;
    int settingCount = 0;
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding\\SubscriptionManager", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[WEF] WEF settings found\n");
        
        DWORD valueIndex = 0;
        while (ADVAPI32$RegEnumValueA(hKey, valueIndex++, valueName, &valueSize, NULL, &valueType, NULL, NULL) == ERROR_SUCCESS && settingCount < 10) {
            valueSize = sizeof(valueName);
            valueSize = 0;
            ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, &valueType, NULL, &valueSize);
            
            if (valueType == REG_SZ || valueType == REG_MULTI_SZ) {
                char* buffer = (char*)MSVCRT$calloc(valueSize + 1, 1);
                if (buffer) {
                    ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, &valueType, (LPBYTE)buffer, &valueSize);
                    BeaconPrintf(CALLBACK_OUTPUT, "[WEF] %s: %s\n", valueName, buffer);
                    MSVCRT$free(buffer);
                }
            }
            settingCount++;
            valueSize = sizeof(valueName);
        }
        ADVAPI32$RegCloseKey(hKey);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[WEF] No WEF settings found (logs are not being forwarded)\n");
    }
}

void CheckSecurityPackages(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SECURITY PACKAGES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char valueName[256];
    DWORD valueType = 0;
    DWORD valueSize = 0;
    
    // Check Security Packages in LSA registry
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(valueName);
        if (ADVAPI32$RegQueryValueExA(hKey, "Security Packages", NULL, &valueType, NULL, &valueSize) == ERROR_SUCCESS) {
            if (valueType == REG_MULTI_SZ && valueSize > 0) {
                char* buffer = (char*)MSVCRT$calloc(valueSize + 1, 1);
                if (buffer) {
                    ADVAPI32$RegQueryValueExA(hKey, "Security Packages", NULL, &valueType, (LPBYTE)buffer, &valueSize);
                    char* p = buffer;
                    while (*p && (p - buffer) < valueSize) {
                        if (MSVCRT$strlen(p) > 0) {
                            BeaconPrintf(CALLBACK_OUTPUT, "[SECURITY_PACKAGES] %s\n", p);
                            if (SHLWAPI$StrStrIA(p, "wdigest") != NULL) {
                                BeaconPrintf(CALLBACK_OUTPUT, "[SECURITY_PACKAGES] [!] WDigest is enabled - plaintext password extraction is possible!\n");
                            }
                        }
                        p += MSVCRT$strlen(p) + 1;
                    }
                    MSVCRT$free(buffer);
                }
            }
        }
        ADVAPI32$RegCloseKey(hKey);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[SECURITY_PACKAGES] Failed to read security packages (or access denied)\n");
    }
}

void CheckAVDetection(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] ANTIVIRUS DETECTION CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for AV in registry
    HKEY hKey;
    char avName[256];
    DWORD avNameSize = sizeof(avName);
    int avCount = 0;
    
    // Check Security Center registry
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Security Center\\Provider\\Av", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, avName, &avNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && avCount < 10) {
            HKEY avKey;
            char avPath[512];
            MSVCRT$sprintf(avPath, "SOFTWARE\\Microsoft\\Security Center\\Provider\\Av\\%s", avName);
            
            if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, avPath, 0, KEY_READ, &avKey) == ERROR_SUCCESS) {
                char displayName[256];
                DWORD nameSize = sizeof(displayName);
                if (ADVAPI32$RegQueryValueExA(avKey, "displayName", NULL, NULL, (LPBYTE)displayName, &nameSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[AV] %s\n", displayName);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[AV] Provider: %s\n", avName);
                }
                avCount++;
                ADVAPI32$RegCloseKey(avKey);
            }
            avNameSize = sizeof(avName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (avCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AV] No antivirus products found in Security Center (or access denied)\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[AV] Note: Use 'WMIC /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName' for full detection\n");
    }
}

void CheckPowerShellSettings(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] POWERSHELL SETTINGS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    DWORD valueType;
    char valueData[256];
    DWORD valueSize = sizeof(valueData);
    
    // Check PowerShell v2 version
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "PowerShellVersion", NULL, &valueType, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[PS_SETTINGS] PowerShell v2 Version: %s\n", valueData);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check PowerShell v5 version
    valueSize = sizeof(valueData);
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "PowerShellVersion", NULL, &valueType, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[PS_SETTINGS] PowerShell v5 Version: %s\n", valueData);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check Transcription Settings (HKLM)
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_SETTINGS] Transcription policy found in HKLM\n");
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check Transcription Settings (HKCU)
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_SETTINGS] Transcription policy found in HKCU\n");
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check Module Logging Settings (HKLM)
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_SETTINGS] Module Logging policy found in HKLM\n");
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check Module Logging Settings (HKCU)
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_SETTINGS] Module Logging policy found in HKCU\n");
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check Scriptblock Logging Settings (HKLM)
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_SETTINGS] ScriptBlock Logging policy found in HKLM\n");
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check Scriptblock Logging Settings (HKCU)
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_SETTINGS] ScriptBlock Logging policy found in HKCU\n");
        ADVAPI32$RegCloseKey(hKey);
    }
}

void CheckWindowsErrorReporting(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] WINDOWS ERROR REPORTING (WER) CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    DWORD valueType;
    DWORD valueData;
    DWORD valueSize = sizeof(valueData);
    
    // Check WER settings
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // Check Disabled value
        valueSize = sizeof(valueData);
        if (ADVAPI32$RegQueryValueExA(hKey, "Disabled", NULL, &valueType, (LPBYTE)&valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[WER] Disabled: %d (0=Enabled, 1=Disabled)\n", valueData);
        }
        
        // Check DontShowUI value
        valueSize = sizeof(valueData);
        if (ADVAPI32$RegQueryValueExA(hKey, "DontShowUI", NULL, &valueType, (LPBYTE)&valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[WER] DontShowUI: %d\n", valueData);
        }
        
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check for crash dump settings
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\CrashControl", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char dumpPath[MAX_PATH];
        DWORD dumpPathSize = sizeof(dumpPath);
        if (ADVAPI32$RegQueryValueExA(hKey, "CrashDumpEnabled", NULL, &valueType, (LPBYTE)&valueData, &valueSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[WER] CrashDumpEnabled: %d (0=None, 1=Complete, 2=Kernel, 3=Small)\n", valueData);
        }
        
        dumpPathSize = sizeof(dumpPath);
        if (ADVAPI32$RegQueryValueExA(hKey, "DumpFile", NULL, &valueType, (LPBYTE)dumpPath, &dumpPathSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[WER] DumpFile: %s\n", dumpPath);
        }
        
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check for minidump directory
    char minidumpPath[] = "C:\\Windows\\Minidump";
    if (GetFileAttributesA(minidumpPath) != INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[WER] Minidump directory exists: %s\n", minidumpPath);
        BeaconPrintf(CALLBACK_OUTPUT, "[WER] Note: May contain crash dumps with sensitive information\n");
    }
}

void CheckSystemLastShutdownTime(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SYSTEM LAST SHUTDOWN TIME CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    FILETIME shutdownTime;
    DWORD valueSize = sizeof(FILETIME);
    
    // Check ControlSet001
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\Windows", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "ShutdownTime", NULL, NULL, (LPBYTE)&shutdownTime, &valueSize) == ERROR_SUCCESS) {
            SYSTEMTIME st;
            if (KERNEL32$FileTimeToSystemTime(&shutdownTime, &st)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[SHUTDOWN_TIME] Last Shutdown: %04d-%02d-%02d %02d:%02d:%02d\n", 
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            }
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check CurrentControlSet
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Windows", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        valueSize = sizeof(FILETIME);
        if (ADVAPI32$RegQueryValueExA(hKey, "ShutdownTime", NULL, NULL, (LPBYTE)&shutdownTime, &valueSize) == ERROR_SUCCESS) {
            SYSTEMTIME st;
            if (KERNEL32$FileTimeToSystemTime(&shutdownTime, &st)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[SHUTDOWN_TIME] Last Shutdown (Current): %04d-%02d-%02d %02d:%02d:%02d\n", 
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            }
        }
        ADVAPI32$RegCloseKey(hKey);
    }
}

void CheckLocalGroupPolicy(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] LOCAL GROUP POLICY CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char gpoId[256];
    DWORD gpoIdSize = sizeof(gpoId);
    int gpoCount = 0;
    
    // Check Machine GPOs
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\DataStore\\Machine\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, gpoId, &gpoIdSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && gpoCount < 10) {
            HKEY gpoKey;
            char gpoPath[512];
            MSVCRT$sprintf(gpoPath, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\DataStore\\Machine\\0\\%s", gpoId);
            
            if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, gpoPath, 0, KEY_READ, &gpoKey) == ERROR_SUCCESS) {
                char gpoName[256] = {0};
                char displayName[256] = {0};
                char fileSysPath[512] = {0};
                DWORD valueSize = sizeof(gpoName);
                
                if (ADVAPI32$RegQueryValueExA(gpoKey, "GPOName", NULL, NULL, (LPBYTE)gpoName, &valueSize) == ERROR_SUCCESS) {
                    valueSize = sizeof(displayName);
                    ADVAPI32$RegQueryValueExA(gpoKey, "DisplayName", NULL, NULL, (LPBYTE)displayName, &valueSize);
                    valueSize = sizeof(fileSysPath);
                    ADVAPI32$RegQueryValueExA(gpoKey, "FileSysPath", NULL, NULL, (LPBYTE)fileSysPath, &valueSize);
                    
                    BeaconPrintf(CALLBACK_OUTPUT, "[LOCAL_GPO] Machine GPO:\n");
                    BeaconPrintf(CALLBACK_OUTPUT, "[LOCAL_GPO]   Name: %s\n", gpoName);
                    if (MSVCRT$strlen(displayName) > 0) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[LOCAL_GPO]   Display Name: %s\n", displayName);
                    }
                    if (MSVCRT$strlen(fileSysPath) > 0) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[LOCAL_GPO]   File System Path: %s\n", fileSysPath);
                    }
                    gpoCount++;
                }
                ADVAPI32$RegCloseKey(gpoKey);
            }
            gpoIdSize = sizeof(gpoId);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check User GPOs (simplified - check current user)
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\DataStore\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        gpoIdSize = sizeof(gpoId);
        DWORD subkeyIndex = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, gpoId, &gpoIdSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && gpoCount < 20) {
            HKEY gpoKey;
            char gpoPath[512];
            MSVCRT$sprintf(gpoPath, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\DataStore\\0\\%s", gpoId);
            
            if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, gpoPath, 0, KEY_READ, &gpoKey) == ERROR_SUCCESS) {
                char gpoName[256] = {0};
                char displayName[256] = {0};
                DWORD valueSize = sizeof(gpoName);
                
                if (ADVAPI32$RegQueryValueExA(gpoKey, "GPOName", NULL, NULL, (LPBYTE)gpoName, &valueSize) == ERROR_SUCCESS) {
                    valueSize = sizeof(displayName);
                    ADVAPI32$RegQueryValueExA(gpoKey, "DisplayName", NULL, NULL, (LPBYTE)displayName, &valueSize);
                    
                    BeaconPrintf(CALLBACK_OUTPUT, "[LOCAL_GPO] User GPO:\n");
                    BeaconPrintf(CALLBACK_OUTPUT, "[LOCAL_GPO]   Name: %s\n", gpoName);
                    if (MSVCRT$strlen(displayName) > 0) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[LOCAL_GPO]   Display Name: %s\n", displayName);
                    }
                    gpoCount++;
                }
                ADVAPI32$RegCloseKey(gpoKey);
            }
            gpoIdSize = sizeof(gpoId);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (gpoCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[LOCAL_GPO] No local Group Policy objects found\n");
    }
}


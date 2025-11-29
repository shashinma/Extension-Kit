// ============================================================================
// APPLICATIONS INFORMATION CHECKS
// ============================================================================

#include "winpeas.h"

void CheckInstalledSoftware(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] INSTALLED SOFTWARE CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char subkeyName[256];
    DWORD subkeyNameSize = sizeof(subkeyName);
    int appCount = 0;
    
    // Check HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY appKey;
            if (ADVAPI32$RegOpenKeyExA(hKey, subkeyName, 0, KEY_READ, &appKey) == ERROR_SUCCESS) {
                char displayName[512] = {0};
                DWORD valueSize = sizeof(displayName);
                
                if (ADVAPI32$RegQueryValueExA(appKey, "DisplayName", NULL, NULL, (LPBYTE)displayName, &valueSize) == ERROR_SUCCESS) {
                    // Skip Microsoft entries
                    if (SHLWAPI$StrStrIA(displayName, "Microsoft") == NULL && 
                        SHLWAPI$StrStrIA(displayName, "Windows") == NULL) {
                        char version[256] = {0};
                        char publisher[256] = {0};
                        valueSize = sizeof(version);
                        ADVAPI32$RegQueryValueExA(appKey, "DisplayVersion", NULL, NULL, (LPBYTE)version, &valueSize);
                        valueSize = sizeof(publisher);
                        ADVAPI32$RegQueryValueExA(appKey, "Publisher", NULL, NULL, (LPBYTE)publisher, &valueSize);
                        
                        BeaconPrintf(CALLBACK_OUTPUT, "[INSTALLED_SOFTWARE] %s", displayName);
                        if (MSVCRT$strlen(version) > 0) {
                            BeaconPrintf(CALLBACK_OUTPUT, " (v%s)", version);
                        }
                        if (MSVCRT$strlen(publisher) > 0) {
                            BeaconPrintf(CALLBACK_OUTPUT, " - %s", publisher);
                        }
                        BeaconPrintf(CALLBACK_OUTPUT, "\n");
                        appCount++;
                    }
                }
                ADVAPI32$RegCloseKey(appKey);
            }
            subkeyNameSize = sizeof(subkeyName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check WOW6432Node for 32-bit apps on 64-bit systems
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        subkeyNameSize = sizeof(subkeyName);
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY appKey;
            if (ADVAPI32$RegOpenKeyExA(hKey, subkeyName, 0, KEY_READ, &appKey) == ERROR_SUCCESS) {
                char displayName[512] = {0};
                DWORD valueSize = sizeof(displayName);
                
                if (ADVAPI32$RegQueryValueExA(appKey, "DisplayName", NULL, NULL, (LPBYTE)displayName, &valueSize) == ERROR_SUCCESS) {
                    if (SHLWAPI$StrStrIA(displayName, "Microsoft") == NULL && 
                        SHLWAPI$StrStrIA(displayName, "Windows") == NULL) {
                        char version[256] = {0};
                        valueSize = sizeof(version);
                        ADVAPI32$RegQueryValueExA(appKey, "DisplayVersion", NULL, NULL, (LPBYTE)version, &valueSize);
                        
                        BeaconPrintf(CALLBACK_OUTPUT, "[INSTALLED_SOFTWARE] %s", displayName);
                        if (MSVCRT$strlen(version) > 0) {
                            BeaconPrintf(CALLBACK_OUTPUT, " (v%s) [x86]", version);
                        } else {
                            BeaconPrintf(CALLBACK_OUTPUT, " [x86]");
                        }
                        BeaconPrintf(CALLBACK_OUTPUT, "\n");
                        appCount++;
                    }
                }
                ADVAPI32$RegCloseKey(appKey);
            }
            subkeyNameSize = sizeof(subkeyName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (appCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[INSTALLED_SOFTWARE] No non-Microsoft software found\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[INSTALLED_SOFTWARE] Found %d non-Microsoft applications\n", appCount);
    }
}

void CheckAutoRuns(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] AUTORUNS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char valueName[256];
    char valueData[1024];
    DWORD valueNameSize = sizeof(valueName);
    DWORD valueSize = sizeof(valueData);
    int autorunCount = 0;
    
    // Check HKLM Run
    const char* autorunKeys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        NULL
    };
    
    for (int k = 0; k < 2; k++) {
        if (ADVAPI32$RegOpenKeyExA((k == 0) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER, autorunKeys[k], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD valueIndex = 0;
            valueNameSize = sizeof(valueName);
            
            while (ADVAPI32$RegEnumValueA(hKey, valueIndex++, valueName, &valueNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                valueSize = sizeof(valueData);
                if (ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[AUTORUN] %s\\%s: %s\n", 
                        (k == 0) ? "HKLM" : "HKCU", autorunKeys[k], valueData);
                    autorunCount++;
                }
                valueNameSize = sizeof(valueName);
            }
            ADVAPI32$RegCloseKey(hKey);
        }
    }
    
    if (autorunCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTORUN] No autorun entries found\n");
    }
}

void CheckScheduledTasks(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SCHEDULED TASKS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check access to tasks folder
    char tasksPath[MAX_PATH];
    MSVCRT$sprintf(tasksPath, "C:\\Windows\\System32\\Tasks");
    
    DWORD attributes = GetFileAttributesA(tasksPath);
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[SCHEDULED_TASKS] Tasks folder accessible: %s\n", tasksPath);
        BeaconPrintf(CALLBACK_OUTPUT, "[SCHEDULED_TASKS] Note: Check folder contents for writable task files\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[SCHEDULED_TASKS] Tasks folder not accessible (requires admin)\n");
    }
    
    // Check Task Scheduler registry
    HKEY hKey;
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char subkeyName[256];
        DWORD subkeyNameSize = sizeof(subkeyName);
        DWORD subkeyIndex = 0;
        int taskCount = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && taskCount < 20) {
            HKEY taskKey;
            if (ADVAPI32$RegOpenKeyExA(hKey, subkeyName, 0, KEY_READ, &taskKey) == ERROR_SUCCESS) {
                char taskName[512] = {0};
                DWORD valueSize = sizeof(taskName);
                
                if (ADVAPI32$RegQueryValueExA(taskKey, "Path", NULL, NULL, (LPBYTE)taskName, &valueSize) == ERROR_SUCCESS) {
                    // Skip Microsoft tasks
                    if (SHLWAPI$StrStrIA(taskName, "Microsoft") == NULL && 
                        SHLWAPI$StrStrIA(taskName, "\\Microsoft\\") == NULL) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[SCHEDULED_TASKS] Task: %s\n", taskName);
                        taskCount++;
                    }
                }
                ADVAPI32$RegCloseKey(taskKey);
            }
            subkeyNameSize = sizeof(subkeyName);
        }
        ADVAPI32$RegCloseKey(hKey);
        
        if (taskCount == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[SCHEDULED_TASKS] No non-Microsoft scheduled tasks found\n");
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[SCHEDULED_TASKS] Failed to access Task Scheduler registry\n");
    }
}

void CheckDeviceDrivers(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] DEVICE DRIVERS CHECK (Non-Microsoft)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for non-Microsoft drivers in system32\drivers
    char driversPath[] = "C:\\Windows\\System32\\drivers";
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\*.sys", driversPath);
    int driverCount = 0;
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                char fullPath[MAX_PATH * 2];
                MSVCRT$sprintf(fullPath, "%s\\%s", driversPath, findData.cFileName);
                
                // Skip Microsoft drivers (common patterns)
                if (SHLWAPI$StrStrIA(findData.cFileName, "dump_") == NULL &&
                    SHLWAPI$StrStrIA(findData.cFileName, "ntoskrnl") == NULL &&
                    SHLWAPI$StrStrIA(findData.cFileName, "hal") == NULL) {
                    
                    // Try to get file version info (simplified - just check if file exists and is readable)
                    HANDLE hFile = CreateFileA(fullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[DEVICE_DRIVERS] %s\n", fullPath);
                        driverCount++;
                        KERNEL32$CloseHandle(hFile);
                        if (driverCount >= 20) break;
                    }
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData) && driverCount < 20);
        KERNEL32$FindClose(hFind);
    }
    
    if (driverCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[DEVICE_DRIVERS] No non-Microsoft drivers found (or access denied)\n");
    } else if (driverCount >= 20) {
        BeaconPrintf(CALLBACK_OUTPUT, "[DEVICE_DRIVERS] ... (showing first 20)\n");
    }
}

void CheckActiveWindow(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] CURRENT ACTIVE WINDOW CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Note: Active window check requires USER32 APIs (GetForegroundWindow, GetWindowText)
    // which may not be available in BOF context
    BeaconPrintf(CALLBACK_OUTPUT, "[ACTIVE_WINDOW] Note: Active window detection requires USER32 APIs\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[ACTIVE_WINDOW] Note: Use 'powershell (Get-Process -Id (Get-WindowProcess)).MainWindowTitle' for active window\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[ACTIVE_WINDOW] Note: Check active window executable for writable permissions (DLL hijacking)\n");
}


// ============================================================================
// SERVICES INFORMATION CHECKS
// ============================================================================

#include "winpeas.h"

void CheckUnquotedServicePaths(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] UNQUOTED SERVICE PATHS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY servicesKey;
    BOOL foundVulnerablePath = FALSE;
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\", 0, KEY_READ, &servicesKey) == ERROR_SUCCESS) {
        char serviceSubkeyName[256];
        DWORD subkeyIndex = 0;
        DWORD subkeyNameSize = sizeof(serviceSubkeyName);
        while (TRUE) {
            subkeyNameSize = sizeof(serviceSubkeyName);
            if (ADVAPI32$RegEnumKeyExA(servicesKey, subkeyIndex++, serviceSubkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                break;
            }
            HKEY imagePathKey;
            if (ADVAPI32$RegOpenKeyExA(servicesKey, serviceSubkeyName, 0, KEY_READ, &imagePathKey) == ERROR_SUCCESS) {
                char imagePathValue[1024] = { 0 };
                DWORD valueSize = sizeof(imagePathValue);
                if (ADVAPI32$RegGetValueA(imagePathKey, NULL, "ImagePath", RRF_RT_REG_SZ, NULL, &imagePathValue, &valueSize) != ERROR_SUCCESS) {
                    ADVAPI32$RegCloseKey(imagePathKey);
                    continue;
                }

                if (SHLWAPI$StrStrIA(imagePathValue, " ") == NULL || SHLWAPI$StrStrIA(imagePathValue, "\"") != NULL) {
                    ADVAPI32$RegCloseKey(imagePathKey);
                    continue;
                }

                if (SHLWAPI$StrStrIA(imagePathValue, "System32") != NULL ||
                    SHLWAPI$StrStrIA(imagePathValue, "SysWow64") != NULL ||
                    SHLWAPI$StrStrIA(imagePathValue, ".sys") != NULL)
                {
                    ADVAPI32$RegCloseKey(imagePathKey);
                    continue;
                }

                BeaconPrintf(CALLBACK_OUTPUT, "[UNQUOTED_SVC] Service '%s' has an unquoted executable path: %s\n", serviceSubkeyName, imagePathValue);
                foundVulnerablePath = TRUE;
                ADVAPI32$RegCloseKey(imagePathKey);
            }
        }
        ADVAPI32$RegCloseKey(servicesKey);
    }

    if (!foundVulnerablePath) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UNQUOTED_SVC] No unquoted service paths found\n");
    }
}

void CheckInterestingServices(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] INTERESTING SERVICES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char subkeyName[256];
    DWORD subkeyNameSize = sizeof(subkeyName);
    int serviceCount = 0;
    
    // Check services in registry
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && serviceCount < 50) {
            HKEY serviceKey;
            if (ADVAPI32$RegOpenKeyExA(hKey, subkeyName, 0, KEY_READ, &serviceKey) == ERROR_SUCCESS) {
                char imagePath[1024] = {0};
                char displayName[512] = {0};
                DWORD valueSize = sizeof(imagePath);
                
                // Get ImagePath
                if (ADVAPI32$RegQueryValueExA(serviceKey, "ImagePath", NULL, NULL, (LPBYTE)imagePath, &valueSize) == ERROR_SUCCESS) {
                    // Skip Microsoft services
                    if (SHLWAPI$StrStrIA(imagePath, "Microsoft") == NULL && 
                        SHLWAPI$StrStrIA(imagePath, "Windows") == NULL &&
                        SHLWAPI$StrStrIA(imagePath, "\\Windows\\") == NULL) {
                        
                        valueSize = sizeof(displayName);
                        ADVAPI32$RegQueryValueExA(serviceKey, "DisplayName", NULL, NULL, (LPBYTE)displayName, &valueSize);
                        
                        BeaconPrintf(CALLBACK_OUTPUT, "[SERVICES] %s", subkeyName);
                        if (MSVCRT$strlen(displayName) > 0) {
                            BeaconPrintf(CALLBACK_OUTPUT, " (%s)", displayName);
                        }
                        BeaconPrintf(CALLBACK_OUTPUT, " - %s\n", imagePath);
                        serviceCount++;
                    }
                }
                ADVAPI32$RegCloseKey(serviceKey);
            }
            subkeyNameSize = sizeof(subkeyName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (serviceCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[SERVICES] No interesting (non-Microsoft) services found\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[SERVICES] Found %d interesting services\n", serviceCount);
    }
}

void CheckWritableServiceRegistry(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] WRITABLE SERVICE REGISTRY CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char serviceName[256];
    DWORD serviceNameSize = sizeof(serviceName);
    int writableCount = 0;
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, serviceName, &serviceNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && writableCount < 10) {
            HKEY serviceKey;
            char servicePath[512];
            MSVCRT$sprintf(servicePath, "SYSTEM\\CurrentControlSet\\Services\\%s", serviceName);
            
            // Try to open with write access
            if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, servicePath, 0, KEY_WRITE, &serviceKey) == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT, "[WRITABLE_SVC_REG] %s (writable)\n", servicePath);
                writableCount++;
                ADVAPI32$RegCloseKey(serviceKey);
            }
            serviceNameSize = sizeof(serviceName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (writableCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[WRITABLE_SVC_REG] No writable service registry keys found\n");
    } else if (writableCount >= 10) {
        BeaconPrintf(CALLBACK_OUTPUT, "[WRITABLE_SVC_REG] ... (showing first 10)\n");
    }
}

void CheckModifiableServices(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] MODIFIABLE SERVICES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Note: Full modifiable services check requires QueryServiceObjectSecurity which is complex
    // This is a simplified check that looks for services with writable registry keys
    BeaconPrintf(CALLBACK_OUTPUT, "[MODIFIABLE_SERVICES] Note: Full check requires QueryServiceObjectSecurity API\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[MODIFIABLE_SERVICES] Note: Use 'accesschk.exe -uwcqv <user> *' or 'sc.exe' for detailed service permissions\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[MODIFIABLE_SERVICES] Note: Check WritableServiceRegistry results for services with writable registry keys\n");
}

void CheckServiceBinaryPermissions(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SERVICE BINARY PERMISSIONS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for service binaries outside system32 with writable permissions
    // This is a simplified check - full implementation would enumerate all services
    BeaconPrintf(CALLBACK_OUTPUT, "[SVC_BINARY_PERMS] Note: Full check requires enumerating all services and checking binary permissions\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[SVC_BINARY_PERMS] Note: Use 'wmic service list full | findstr pathname' and 'icacls' for detailed permissions\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[SVC_BINARY_PERMS] Note: Look for services with binaries outside system32 that have writable permissions\n");
}

void CheckPathDLLHijacking(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] PATH DLL HIJACKING CHECK (Services)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check PATH environment variable for writable directories
    // This is similar to CheckHijackablePaths but specifically for services
    char pathValue[4096];
    DWORD pathSize = sizeof(pathValue);
    
    if (GetEnvironmentVariableA("PATH", pathValue, pathSize) > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PATH_DLL_HIJACK] PATH variable found\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[PATH_DLL_HIJACK] Note: Check each PATH directory for write permissions\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[PATH_DLL_HIJACK] Note: Writable PATH directories can be used for DLL hijacking in services\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[PATH_DLL_HIJACK] Note: Use 'icacls' on each PATH directory to check permissions\n");
    } else {
        // Try reading from registry
        HKEY hKey;
        if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            pathSize = sizeof(pathValue);
            if (ADVAPI32$RegQueryValueExA(hKey, "Path", NULL, NULL, (LPBYTE)pathValue, &pathSize) == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT, "[PATH_DLL_HIJACK] PATH variable found in registry\n");
                BeaconPrintf(CALLBACK_OUTPUT, "[PATH_DLL_HIJACK] Note: Check each PATH directory for write permissions\n");
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[PATH_DLL_HIJACK] PATH variable not found\n");
            }
            ADVAPI32$RegCloseKey(hKey);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[PATH_DLL_HIJACK] Failed to read PATH variable (or access denied)\n");
        }
    }
}


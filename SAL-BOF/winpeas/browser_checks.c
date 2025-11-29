// ============================================================================
// BROWSER INFORMATION CHECKS
// ============================================================================

#include "winpeas.h"

void CheckFirefoxDBs(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] FIREFOX DATABASES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char userProfile[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, sizeof(userProfile)) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[FIREFOX] Failed to get USERPROFILE\n");
        return;
    }
    
    char firefoxPath[MAX_PATH * 2];
    MSVCRT$sprintf(firefoxPath, "%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", userProfile);
    
    // Check if Firefox profiles directory exists
    DWORD attributes = GetFileAttributesA(firefoxPath);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[FIREFOX] Firefox profiles directory not found\n");
        return;
    }
    
    // Look for key3.db and key4.db files
    static const char * firefoxKeyFiles[] = {
        "\\key3.db",
        "\\key4.db",
        "\\signons.sqlite",
        "\\logins.json",
        "\\places.sqlite",
        NULL
    };
    
    int foundCount = 0;
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    MSVCRT$sprintf(searchPath, "%s\\*", firefoxPath);
    
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                    char profilePath[MAX_PATH * 2];
                    MSVCRT$sprintf(profilePath, "%s\\%s", firefoxPath, findData.cFileName);
                    
                    for (int i = 0; firefoxKeyFiles[i] != NULL; i++) {
                        char filePath[MAX_PATH * 2];
                        MSVCRT$sprintf(filePath, "%s%s", profilePath, firefoxKeyFiles[i]);
                        
                        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                        if (hFile != INVALID_HANDLE_VALUE) {
                            BeaconPrintf(CALLBACK_OUTPUT, "[FIREFOX] Found: %s\n", filePath);
                            if (MSVCRT$strstr(firefoxKeyFiles[i], "key") || MSVCRT$strstr(firefoxKeyFiles[i], "signons") || MSVCRT$strstr(firefoxKeyFiles[i], "logins")) {
                                BeaconPrintf(CALLBACK_OUTPUT, "[FIREFOX] Note: This file contains encrypted credentials\n");
                            }
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
        BeaconPrintf(CALLBACK_OUTPUT, "[FIREFOX] No Firefox credential/history databases found\n");
    }
}

void CheckChromeDBs(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] CHROME DATABASES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char userProfile[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, sizeof(userProfile)) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[CHROME] Failed to get USERPROFILE\n");
        return;
    }
    
    static const char * chromeFiles[] = {
        "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies",
        "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
        "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
        "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Bookmarks",
        "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State",
        NULL
    };
    
    int foundCount = 0;
    for (int i = 0; chromeFiles[i] != NULL; i++) {
        char filePath[MAX_PATH * 2];
        MSVCRT$sprintf(filePath, "%s%s", userProfile, chromeFiles[i]);
        
        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_OUTPUT, "[CHROME] Found: %s\n", filePath);
            if (MSVCRT$strstr(chromeFiles[i], "Login Data") || MSVCRT$strstr(chromeFiles[i], "Cookies")) {
                BeaconPrintf(CALLBACK_OUTPUT, "[CHROME] Note: This file contains encrypted credentials\n");
            }
            if (MSVCRT$strstr(chromeFiles[i], "Local State")) {
                BeaconPrintf(CALLBACK_OUTPUT, "[CHROME] Note: This file contains the encryption key\n");
            }
            foundCount++;
            KERNEL32$CloseHandle(hFile);
        }
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[CHROME] No Chrome databases found\n");
    }
}

void CheckIEHistory(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] INTERNET EXPLORER HISTORY CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char valueData[1024];
    DWORD valueSize = sizeof(valueData);
    int urlCount = 0;
    
    // Check TypedURLs in registry
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLs", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD valueIndex = 0;
        char valueName[256];
        DWORD valueNameSize = sizeof(valueName);
        
        while (ADVAPI32$RegEnumValueA(hKey, valueIndex++, valueName, &valueNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            valueSize = sizeof(valueData);
            if (ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT, "[IE] TypedURL: %s\n", valueData);
                urlCount++;
            }
            valueNameSize = sizeof(valueName);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check Favorites
    char userProfile[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, sizeof(userProfile)) != 0) {
        char favoritesPath[MAX_PATH * 2];
        MSVCRT$sprintf(favoritesPath, "%s\\Favorites", userProfile);
        
        WIN32_FIND_DATA findData;
        char searchPath[MAX_PATH * 2];
        MSVCRT$sprintf(searchPath, "%s\\*.url", favoritesPath);
        
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    char urlPath[MAX_PATH * 2];
                    MSVCRT$sprintf(urlPath, "%s\\%s", favoritesPath, findData.cFileName);
                    
                    HANDLE hFile = CreateFileA(urlPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        char buffer[1024];
                        DWORD bytesRead = 0;
                        if (KERNEL32$ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
                            buffer[bytesRead] = '\0';
                            char* urlLine = MSVCRT$strstr(buffer, "URL=");
                            if (urlLine) {
                                urlLine += 4; // Skip "URL="
                                char* newline = MSVCRT$strchr(urlLine, '\n');
                                if (newline) *newline = '\0';
                                BeaconPrintf(CALLBACK_OUTPUT, "[IE] Favorite: %s -> %s\n", findData.cFileName, urlLine);
                                urlCount++;
                            }
                        }
                        KERNEL32$CloseHandle(hFile);
                    }
                }
            } while (KERNEL32$FindNextFileA(hFind, &findData));
            KERNEL32$FindClose(hFind);
        }
    }
    
    if (urlCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[IE] No IE history or favorites found\n");
    }
}

void CheckOperaDBs(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] OPERA DATABASES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char userProfile[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, sizeof(userProfile)) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[OPERA] Failed to get USERPROFILE\n");
        return;
    }
    
    static const char * operaFiles[] = {
        "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Cookies",
        "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data",
        "\\AppData\\Roaming\\Opera Software\\Opera Stable\\History",
        NULL
    };
    
    int foundCount = 0;
    for (int i = 0; operaFiles[i] != NULL; i++) {
        char filePath[MAX_PATH * 2];
        MSVCRT$sprintf(filePath, "%s%s", userProfile, operaFiles[i]);
        
        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_OUTPUT, "[OPERA] Found: %s\n", filePath);
            if (MSVCRT$strstr(operaFiles[i], "Login Data") || MSVCRT$strstr(operaFiles[i], "Cookies")) {
                BeaconPrintf(CALLBACK_OUTPUT, "[OPERA] Note: This file contains encrypted credentials\n");
            }
            foundCount++;
            KERNEL32$CloseHandle(hFile);
        }
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[OPERA] No Opera databases found\n");
    }
}

void CheckBraveDBs(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] BRAVE DATABASES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char userProfile[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, sizeof(userProfile)) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[BRAVE] Failed to get USERPROFILE\n");
        return;
    }
    
    static const char * braveFiles[] = {
        "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Cookies",
        "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data",
        "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History",
        "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Local State",
        NULL
    };
    
    int foundCount = 0;
    for (int i = 0; braveFiles[i] != NULL; i++) {
        char filePath[MAX_PATH * 2];
        MSVCRT$sprintf(filePath, "%s%s", userProfile, braveFiles[i]);
        
        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_OUTPUT, "[BRAVE] Found: %s\n", filePath);
            if (MSVCRT$strstr(braveFiles[i], "Login Data") || MSVCRT$strstr(braveFiles[i], "Cookies")) {
                BeaconPrintf(CALLBACK_OUTPUT, "[BRAVE] Note: This file contains encrypted credentials\n");
            }
            if (MSVCRT$strstr(braveFiles[i], "Local State")) {
                BeaconPrintf(CALLBACK_OUTPUT, "[BRAVE] Note: This file contains the encryption key\n");
            }
            foundCount++;
            KERNEL32$CloseHandle(hFile);
        }
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[BRAVE] No Brave databases found\n");
    }
}


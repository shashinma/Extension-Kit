// ============================================================================
// LOLBAS SEARCH
// ============================================================================

#include "winpeas.h"

void CheckLOLBAS(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] LOLBAS SEARCH (LIVING OFF THE LAND BINARIES AND SCRIPTS)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[LOLBAS] Note: This is a slow check - searching for known LOLBAS binaries\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[LOLBAS] Reference: https://lolbas-project.github.io/\n");
    
    // List of known LOLBAS binaries (subset of most common ones)
    static const char* lolbasFiles[] = {
        "advpack.dll", "appvlp.exe", "at.exe", "atbroker.exe", "bash.exe",
        "bginfo.exe", "bitsadmin.exe", "cdb.exe", "certutil.exe", "cmd.exe",
        "cmdkey.exe", "cmstp.exe", "comsvcs.dll", "control.exe", "csc.exe",
        "cscript.exe", "desktopimgdownldr.exe", "devtoolslauncher.exe", "dfsvc.exe",
        "diskshadow.exe", "dnscmd.exe", "dotnet.exe", "dxcap.exe", "esentutl.exe",
        "eventvwr.exe", "excel.exe", "expand.exe", "extexport.exe", "extrac32.exe",
        "findstr.exe", "forfiles.exe", "ftp.exe", "gfxdownloadwrapper.exe", "gpscript.exe",
        "hh.exe", "ie4uinit.exe", "ieadvpack.dll", "ieaframe.dll", "ieexec.exe",
        "ilasm.exe", "infdefaultinstall.exe", "installutil.exe", "java.exe", "jsc.exe",
        "makecab.exe", "manage-bde.wsf", "mavinject.exe", "mftrace.exe",
        "microsoft.workflow.compiler.exe", "mmc.exe", "msbuild.exe", "msconfig.exe",
        "msdeploy.exe", "msdt.exe", "mshta.exe", "mshtml.dll", "msiexec.exe",
        "netsh.exe", "nc.exe", "nc64.exe", "nmap.exe", "odbcconf.exe", "pcalua.exe",
        "pcwrun.exe", "pcwutl.dll", "pester.bat", "powerpnt.exe", "presentationhost.exe",
        "print.exe", "psr.exe", "pubprn.vbs", "rasautou.exe", "reg.exe", "regasm.exe",
        "regedit.exe", "regini.exe", "register-cimprovider.exe", "regsvcs.exe",
        "regsvr32.exe", "replace.exe", "rpcping.exe", "rundll32.exe", "runonce.exe",
        "runscripthelper.exe", "sqltoolsps.exe", "sc.exe", "schtasks.exe",
        "scriptrunner.exe", "setupapi.dll", "shdocvw.dll", "shell32.dll", "slmgr.vbs",
        "sqldumper.exe", "sqlps.exe", "squirrel.exe", "syncappvpublishingserver.exe",
        "syncappvpublishingserver.vbs", "syssetup.dll", "tracker.exe", "tttracer.exe",
        "update.exe", "url.dll", "verclsid.exe", "wab.exe", "winword.exe", "wmic.exe",
        "wscript.exe", "wsl.exe", "wsreset.exe", "xwizard.exe", "zipfldr.dll", "csi.exe",
        "dnx.exe", "msxsl.exe", "ntdsutil.exe", "rcsi.exe", "te.exe", "vbc.exe",
        "vsjitdebugger.exe", "winrm.vbs",
        NULL
    };
    
    // Search paths (limited for performance)
    static const char* searchPaths[] = {
        "C:\\Windows\\System32",
        "C:\\Windows",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\Users",
        NULL
    };
    
    int foundCount = 0;
    int totalSearched = 0;
    
    // Search in each path
    for (int pathIdx = 0; searchPaths[pathIdx] != NULL && foundCount < 100; pathIdx++) {
        char searchPath[MAX_PATH * 2];
        MSVCRT$sprintf(searchPath, "%s\\*", searchPaths[pathIdx]);
        
        WIN32_FIND_DATA findData;
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    // Skip . and ..
                    if (MSVCRT$strcmp(findData.cFileName, ".") == 0 || 
                        MSVCRT$strcmp(findData.cFileName, "..") == 0) {
                        continue;
                    }
                    
                    // Recursively search in subdirectories (limited depth)
                    char subPath[MAX_PATH * 2];
                    MSVCRT$sprintf(subPath, "%s\\%s", searchPaths[pathIdx], findData.cFileName);
                    
                    // Search for LOLBAS files in this directory
                    for (int fileIdx = 0; lolbasFiles[fileIdx] != NULL && foundCount < 100; fileIdx++) {
                        char filePath[MAX_PATH * 2];
                        MSVCRT$sprintf(filePath, "%s\\%s", subPath, lolbasFiles[fileIdx]);
                        
                        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                        if (hFile != INVALID_HANDLE_VALUE) {
                            // Check if it's not in System32 (those are expected)
                            if (SHLWAPI$StrStrIA(filePath, "\\System32\\") == NULL) {
                                BeaconPrintf(CALLBACK_OUTPUT, "[LOLBAS] Found: %s\n", filePath);
                                foundCount++;
                            }
                            KERNEL32$CloseHandle(hFile);
                        }
                        totalSearched++;
                    }
                } else {
                    // Check if current file is a LOLBAS binary
                    for (int fileIdx = 0; lolbasFiles[fileIdx] != NULL; fileIdx++) {
                        if (MSVCRT$_stricmp(findData.cFileName, lolbasFiles[fileIdx]) == 0) {
                            char filePath[MAX_PATH * 2];
                            MSVCRT$sprintf(filePath, "%s\\%s", searchPaths[pathIdx], findData.cFileName);
                            
                            // Check if it's not in System32 (those are expected)
                            if (SHLWAPI$StrStrIA(filePath, "\\System32\\") == NULL) {
                                BeaconPrintf(CALLBACK_OUTPUT, "[LOLBAS] Found: %s\n", filePath);
                                foundCount++;
                            }
                            break;
                        }
                    }
                    totalSearched++;
                }
            } while (KERNEL32$FindNextFileA(hFind, &findData) && foundCount < 100);
            
            KERNEL32$FindClose(hFind);
        }
    }
    
    // Also check common user directories more thoroughly
    char usersPath[] = "C:\\Users";
    WIN32_FIND_DATA userFindData;
    char userSearchPath[MAX_PATH * 2];
    MSVCRT$sprintf(userSearchPath, "%s\\*", usersPath);
    
    HANDLE hUserFind = KERNEL32$FindFirstFileA(userSearchPath, &userFindData);
    if (hUserFind != INVALID_HANDLE_VALUE && foundCount < 100) {
        do {
            if (userFindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(userFindData.cFileName, ".") != 0 && 
                    MSVCRT$strcmp(userFindData.cFileName, "..") != 0 &&
                    MSVCRT$strcmp(userFindData.cFileName, "Public") != 0 &&
                    MSVCRT$strcmp(userFindData.cFileName, "Default") != 0) {
                    
                    // Search in user's directories
                    char userDirs[][64] = {
                        "Desktop", "Documents", "Downloads", "AppData\\Local", "AppData\\Roaming"
                    };
                    
                    for (int dirIdx = 0; dirIdx < 5 && foundCount < 100; dirIdx++) {
                        char userDirPath[MAX_PATH * 2];
                        MSVCRT$sprintf(userDirPath, "%s\\%s\\%s", usersPath, userFindData.cFileName, userDirs[dirIdx]);
                        
                        for (int fileIdx = 0; lolbasFiles[fileIdx] != NULL && foundCount < 100; fileIdx++) {
                            char filePath[MAX_PATH * 2];
                            MSVCRT$sprintf(filePath, "%s\\%s", userDirPath, lolbasFiles[fileIdx]);
                            
                            HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                            if (hFile != INVALID_HANDLE_VALUE) {
                                BeaconPrintf(CALLBACK_OUTPUT, "[LOLBAS] Found: %s\n", filePath);
                                foundCount++;
                                KERNEL32$CloseHandle(hFile);
                            }
                            totalSearched++;
                        }
                    }
                }
            }
        } while (KERNEL32$FindNextFileA(hUserFind, &userFindData) && foundCount < 100);
        KERNEL32$FindClose(hUserFind);
    }
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[LOLBAS] No LOLBAS binaries found in non-standard locations\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[LOLBAS] Note: Standard Windows binaries in System32 are expected and not shown\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[LOLBAS] Found %d LOLBAS binaries in non-standard locations\n", foundCount);
        BeaconPrintf(CALLBACK_OUTPUT, "[LOLBAS] Note: These binaries can be used for living off the land attacks\n");
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[LOLBAS] Note: Full scan would search entire filesystem (very slow)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[LOLBAS] Note: This is a simplified check focusing on common locations\n");
}


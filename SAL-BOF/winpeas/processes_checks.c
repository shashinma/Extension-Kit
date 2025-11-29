// ============================================================================
// PROCESSES INFORMATION CHECKS
// ============================================================================

#include "winpeas.h"

// Structure to hold process information
typedef struct {
    const char* name;
    const char* description;
} INTERESTING_PROCESS;

void CheckInterestingProcesses(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] INTERESTING PROCESSES CHECK (non-Microsoft)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Check if any interesting processes for memory dump or if you could overwrite some binary running\n");
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    
    // List of interesting process names with descriptions (from original winPEAS)
    static INTERESTING_PROCESS interestingProcesses[] = {
        {"putty.exe", "Putty SSH client"},
        {"pscp.exe", "Putty SCP client"},
        {"psftp.exe", "Putty SFTP client"},
        {"puttytel.exe", "Putty Telnet client"},
        {"plink.exe", "Putty CLI client"},
        {"pageant.exe", "Putty SSH auth agent"},
        {"kitty.exe", "Kitty SSH client"},
        {"SecureCRT.exe", "SecureCRT SSH/Telnet client"},
        {"TeamViewer.exe", "TeamViewer"},
        {"tv_x64.exe", "TeamViewer x64 remote control"},
        {"tv_w32.exe", "TeamViewer x86 remote control"},
        {"keepass.exe", "KeePass password vault"},
        {"mstsc.exe", "Microsoft RDP client"},
        {"vnc.exe", "Possible VNC client"},
        {"WinSCP.exe", "WinSCP client"},
        {"filezilla.exe", "FileZilla Client"},
        {"Code.exe", "Visual Studio Code"},
        {"CmRcService.exe", "Configuration Manager Remote Control Service"},
        {"ftp.exe", "Misc. FTP client"},
        {"LMIGuardian.exe", "LogMeIn Reporter"},
        {"LogMeInSystray.exe", "LogMeIn System Tray"},
        {"RaMaint.exe", "LogMeIn maintenance service"},
        {"mmc.exe", "Microsoft Management Console"},
        {"telnet.exe", "Misc. Telnet client"},
        {"powershell.exe", "PowerShell host process"},
        {"cmd.exe", "Command Prompt"},
        {NULL, NULL}
    };
    
    HANDLE hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PROCESSES] Failed to create process snapshot\n");
        return;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    int foundCount = 0;
    
    if (KERNEL32$Process32First(hSnapshot, &pe32)) {
        do {
            // Check if process is interesting
            for (int i = 0; interestingProcesses[i].name != NULL; i++) {
                if (MSVCRT$_stricmp(pe32.szExeFile, interestingProcesses[i].name) == 0) {
                    foundCount++;
                    
                    // Try to get full path to executable
                    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                    char exePath[MAX_PATH] = {0};
                    DWORD pathSize = MAX_PATH;
                    
                    if (hProcess != NULL) {
                        if (KERNEL32$QueryFullProcessImageNameA(hProcess, 0, exePath, &pathSize)) {
                            // Check file permissions (simplified - just check if file exists)
                            DWORD fileAttrs = GetFileAttributesA(exePath);
                            BOOL hasWritePerms = FALSE;
                            
                            if (fileAttrs != INVALID_FILE_ATTRIBUTES) {
                                // Try to open file for write to check permissions
                                HANDLE hFile = CreateFileA(exePath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                                if (hFile != INVALID_HANDLE_VALUE) {
                                    hasWritePerms = TRUE;
                                    KERNEL32$CloseHandle(hFile);
                                }
                            }
                            
                            BeaconPrintf(CALLBACK_OUTPUT, "  %s (PID: %lu) - %s\n", pe32.szExeFile, pe32.th32ProcessID, interestingProcesses[i].description);
                            BeaconPrintf(CALLBACK_OUTPUT, "    ExecutablePath: %s\n", exePath);
                            if (hasWritePerms) {
                                BeaconPrintf(CALLBACK_OUTPUT, "    [!] Writable executable path!\n");
                            }
                            BeaconPrintf(CALLBACK_OUTPUT, "\n");
                        } else {
                            BeaconPrintf(CALLBACK_OUTPUT, "  %s (PID: %lu) - %s\n", pe32.szExeFile, pe32.th32ProcessID, interestingProcesses[i].description);
                            BeaconPrintf(CALLBACK_OUTPUT, "\n");
                        }
                        
                        KERNEL32$CloseHandle(hProcess);
                    } else {
                        // Process might require elevated privileges
                        BeaconPrintf(CALLBACK_OUTPUT, "  %s (PID: %lu) - %s [Access Denied]\n", pe32.szExeFile, pe32.th32ProcessID, interestingProcesses[i].description);
                        BeaconPrintf(CALLBACK_OUTPUT, "\n");
                    }
                    
                    break;
                }
            }
        } while (KERNEL32$Process32Next(hSnapshot, &pe32));
    }
    
    KERNEL32$CloseHandle(hSnapshot);
    
    if (foundCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PROCESSES] No interesting processes found\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[PROCESSES] Found %d interesting process(es)\n", foundCount);
    }
}

// Note: CheckVulnLeakedHandlers is not implemented as it requires complex NtDuplicateObject
// and handle enumeration which is difficult to implement in BOF context


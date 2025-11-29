// ============================================================================
// EVENTS INFORMATION CHECKS
// ============================================================================

#include "winpeas.h"

void CheckEventLogs(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] EVENT LOGS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for Security event log
    char eventLogPath[] = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx";
    if (GetFileAttributesA(eventLogPath) != INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[EVENT_LOGS] Security event log found\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[EVENT_LOGS] Note: Event logs contain Logon Events (4624), Process Creation Events (4688), PowerShell Events (4104), etc.\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[EVENT_LOGS] Note: Use 'wevtutil qe Security /c:10 /rd:true /f:text' to query events\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[EVENT_LOGS] Security event log not found (or access denied)\n");
    }
    
    // Check for PowerShell event log
    char psLogPath[] = "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx";
    if (GetFileAttributesA(psLogPath) != INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[EVENT_LOGS] PowerShell event log found\n");
    }
    
    // Check for System event log (for Power On/Off events)
    char systemLogPath[] = "C:\\Windows\\System32\\winevt\\Logs\\System.evtx";
    if (GetFileAttributesA(systemLogPath) != INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[EVENT_LOGS] System event log found (contains Power On/Off events)\n");
    }
}

void CheckLogonEvents(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] LOGON EVENTS CHECK (EID 4624, 4648)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check if Security log exists
    char eventLogPath[] = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx";
    if (GetFileAttributesA(eventLogPath) == INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[LOGON_EVENTS] Security event log not accessible (or access denied)\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[LOGON_EVENTS] Security event log exists\n");
    
    // Try to open Security event log using legacy API
    HANDLE hEventLog = ADVAPI32$OpenEventLogA(NULL, "Security");
    if (hEventLog != NULL) {
        DWORD numRecords = 0;
        DWORD oldestRecord = 0;
        
        if (ADVAPI32$GetNumberOfEventLogRecords(hEventLog, &numRecords) && 
            ADVAPI32$GetOldestEventLogRecord(hEventLog, &oldestRecord)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[LOGON_EVENTS] Total records: %lu, Oldest record: %lu\n", numRecords, oldestRecord);
        }
        
        ADVAPI32$CloseEventLog(hEventLog);
    }
    
    // Check registry for audit settings
    HKEY hKey;
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD auditMode = 0;
        DWORD dataSize = sizeof(DWORD);
        
        if (ADVAPI32$RegQueryValueExA(hKey, "AuditMode", NULL, NULL, (LPBYTE)&auditMode, &dataSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[LOGON_EVENTS] Audit mode: %s\n", auditMode ? "Enabled" : "Disabled");
        }
        
        ADVAPI32$RegCloseKey(hKey);
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[LOGON_EVENTS] Event IDs to look for:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - 4624: Successful logon\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - 4625: Failed logon\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - 4648: Explicit credentials used for logon (may contain passwords)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - 4672: Special privileges assigned to new logon\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[LOGON_EVENTS] Authentication types to check:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - NTLM v1 (Type 3) - vulnerable\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - NTLM v2 (Type 3) - can be cracked\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - Kerberos (Type 2) - can be abused\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[LOGON_EVENTS] Query command: wevtutil qe Security /q:\"*[System[EventID=4624 or EventID=4648]]\" /c:10 /rd:true /f:text\n");
}

void CheckProcessCreationEvents(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] PROCESS CREATION EVENTS CHECK (EID 4688)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check if Security log exists
    char eventLogPath[] = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx";
    if (GetFileAttributesA(eventLogPath) == INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PROCESS_CREATION] Security event log not accessible (or access denied)\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[PROCESS_CREATION] Security event log exists\n");
    
    // Check if Process Creation auditing is enabled
    HKEY hKey;
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EventLog-Security", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PROCESS_CREATION] Process Creation auditing may be configured\n");
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check audit policy
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD auditMode = 0;
        DWORD dataSize = sizeof(DWORD);
        
        if (ADVAPI32$RegQueryValueExA(hKey, "AuditMode", NULL, NULL, (LPBYTE)&auditMode, &dataSize) == ERROR_SUCCESS && auditMode) {
            BeaconPrintf(CALLBACK_OUTPUT, "[PROCESS_CREATION] Audit mode is enabled\n");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[PROCESS_CREATION] [!] Audit mode may be disabled - Process Creation events may not be logged\n");
        }
        
        ADVAPI32$RegCloseKey(hKey);
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[PROCESS_CREATION] Event ID 4688 contains:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - Process name and path\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - Command line arguments (may contain passwords, credentials)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - User context\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - Process ID\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[PROCESS_CREATION] Look for interesting command lines:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - Passwords in command line\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - Credential-related arguments\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - Network connections with credentials\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[PROCESS_CREATION] Query command: wevtutil qe Security /q:\"*[System[EventID=4688]]\" /c:10 /rd:true /f:text\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[PROCESS_CREATION] Note: Requires administrator privileges to read Security log\n");
}

void CheckPowerShellEvents(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] POWERSHELL EVENTS CHECK (EID 4104)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for PowerShell operational log file
    char psLogPath[] = "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx";
    BOOL psLogExists = (GetFileAttributesA(psLogPath) != INVALID_FILE_ATTRIBUTES);
    
    // Check registry for PowerShell ScriptBlockLogging
    HKEY hKey;
    BOOL scriptBlockLogging = FALSE;
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD enableScriptBlockLogging = 0;
        DWORD dataSize = sizeof(DWORD);
        
        if (ADVAPI32$RegQueryValueExA(hKey, "EnableScriptBlockLogging", NULL, NULL, (LPBYTE)&enableScriptBlockLogging, &dataSize) == ERROR_SUCCESS) {
            scriptBlockLogging = (enableScriptBlockLogging == 1);
        }
        
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Also check in WOW64 location
    if (!scriptBlockLogging) {
        if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD enableScriptBlockLogging = 0;
            DWORD dataSize = sizeof(DWORD);
            
            if (ADVAPI32$RegQueryValueExA(hKey, "EnableScriptBlockLogging", NULL, NULL, (LPBYTE)&enableScriptBlockLogging, &dataSize) == ERROR_SUCCESS) {
                scriptBlockLogging = (enableScriptBlockLogging == 1);
            }
            
            ADVAPI32$RegCloseKey(hKey);
        }
    }
    
    if (psLogExists) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_EVENTS] PowerShell operational log exists\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_EVENTS] PowerShell operational log file not found\n");
    }
    
    if (scriptBlockLogging) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_EVENTS] [!] ScriptBlockLogging is ENABLED - Scripts are being logged!\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_EVENTS] ScriptBlockLogging is disabled or not configured\n");
    }
    
    // Check for ModuleLogging
    BOOL moduleLogging = FALSE;
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD enableModuleLogging = 0;
        DWORD dataSize = sizeof(DWORD);
        
        if (ADVAPI32$RegQueryValueExA(hKey, "EnableModuleLogging", NULL, NULL, (LPBYTE)&enableModuleLogging, &dataSize) == ERROR_SUCCESS) {
            moduleLogging = (enableModuleLogging == 1);
        }
        
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (moduleLogging) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PS_EVENTS] ModuleLogging is enabled\n");
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[PS_EVENTS] Event ID 4104 (Script Block Logging) contains:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - Full PowerShell script blocks\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - May contain passwords, credentials, API keys\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - Command execution details\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[PS_EVENTS] Query command: wevtutil qe Microsoft-Windows-PowerShell/Operational /q:\"*[System[EventID=4104]]\" /c:10 /rd:true /f:text\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[PS_EVENTS] Note: Script block logs may contain sensitive data - review carefully!\n");
}

void CheckPowerOnOffEvents(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] POWER ON/OFF EVENTS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check for System event log
    char systemLogPath[] = "C:\\Windows\\System32\\winevt\\Logs\\System.evtx";
    if (GetFileAttributesA(systemLogPath) == INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[POWER_EVENTS] System event log not accessible (or access denied)\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[POWER_EVENTS] System event log exists\n");
    
    // Try to open System event log using legacy API
    HANDLE hEventLog = ADVAPI32$OpenEventLogA(NULL, "System");
    if (hEventLog != NULL) {
        DWORD numRecords = 0;
        DWORD oldestRecord = 0;
        
        if (ADVAPI32$GetNumberOfEventLogRecords(hEventLog, &numRecords) && 
            ADVAPI32$GetOldestEventLogRecord(hEventLog, &oldestRecord)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[POWER_EVENTS] Total records: %lu, Oldest record: %lu\n", numRecords, oldestRecord);
        }
        
        ADVAPI32$CloseEventLog(hEventLog);
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[POWER_EVENTS] Event IDs to look for:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - 12: System startup (Kernel-General)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - 13: System shutdown (Kernel-General)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - 42: System sleep (Kernel-General)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - 1: System awake (Power-Troubleshooter)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - 6005: Event log service started\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - 6006: Event log service stopped\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - 6008: Unexpected shutdown\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - 1074: User initiated shutdown/restart\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - 1076: System wake from sleep\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[POWER_EVENTS] Use cases:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - Timeline analysis\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - Detecting unexpected reboots (may indicate compromise)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  - Identifying maintenance windows\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[POWER_EVENTS] Query command: wevtutil qe System /q:\"*[System[EventID=12 or EventID=13 or EventID=42 or EventID=6008 or EventID=1074]]\" /c:10 /rd:true /f:text\n");
}

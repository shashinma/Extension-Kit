// ============================================================================
// WINPEAS FLAGS PARSING
// ============================================================================

#include "winpeas.h"
#include "winpeas_flags.h"

void InitWinPEASFlags(WINPEAS_FLAGS* flags) {
    MSVCRT$memset(flags, 0, sizeof(WINPEAS_FLAGS));
    
    // Default: run all checks (except slow ones)
    flags->run_all_checks = TRUE;
}

BOOL MatchFlag(const char* arg, const char* flag) {
    if (!arg || !flag) return FALSE;
    
    // Case insensitive comparison
    int i = 0;
    while (arg[i] && flag[i]) {
        char a = (arg[i] >= 'A' && arg[i] <= 'Z') ? (arg[i] + 32) : arg[i];
        char f = (flag[i] >= 'A' && flag[i] <= 'Z') ? (flag[i] + 32) : flag[i];
        if (a != f) return FALSE;
        i++;
    }
    
    return (arg[i] == '\0' && flag[i] == '\0');
}

void ParseWinPEASFlags(const char* raw_cmdline, WINPEAS_FLAGS* flags) {
    if (!raw_cmdline || MSVCRT$strlen(raw_cmdline) == 0) {
        return;  // No arguments, use defaults
    }
    
    // Parse flags from command line string (format: "systeminfo userinfo domain")
    // Only space-separated format is supported
    char* args_copy = (char*)intAlloc(MSVCRT$strlen(raw_cmdline) + 1);
    if (!args_copy) return;
    
    MSVCRT$strcpy(args_copy, raw_cmdline);
    
    char* token = MSVCRT$strtok(args_copy, " \t");
    while (token != NULL) {
        // Help flags
        if (MatchFlag(token, "-h") || MatchFlag(token, "--help") || 
            MatchFlag(token, "help") || MatchFlag(token, "/h")) {
            PrintWinPEASUsage();
            intFree(args_copy);
            return;
        }
        
        // Category flags
        if (MatchFlag(token, "systeminfo")) {
            flags->systeminfo = TRUE;
            flags->run_all_checks = FALSE;
        } else if (MatchFlag(token, "userinfo")) {
            flags->userinfo = TRUE;
            flags->run_all_checks = FALSE;
        } else if (MatchFlag(token, "processinfo")) {
            flags->processinfo = TRUE;
            flags->run_all_checks = FALSE;
        } else if (MatchFlag(token, "servicesinfo")) {
            flags->servicesinfo = TRUE;
            flags->run_all_checks = FALSE;
        } else if (MatchFlag(token, "applicationsinfo")) {
            flags->applicationsinfo = TRUE;
            flags->run_all_checks = FALSE;
        } else if (MatchFlag(token, "networkinfo")) {
            flags->networkinfo = TRUE;
            flags->run_all_checks = FALSE;
        } else if (MatchFlag(token, "eventsinfo")) {
            flags->eventsinfo = TRUE;
            flags->run_all_checks = FALSE;
        } else if (MatchFlag(token, "activedirectoryinfo")) {
            flags->activedirectoryinfo = TRUE;
            flags->domain = TRUE;
            flags->run_all_checks = FALSE;
        } else if (MatchFlag(token, "domain")) {
            flags->domain = TRUE;
            flags->activedirectoryinfo = TRUE;
            flags->run_all_checks = FALSE;
        } else if (MatchFlag(token, "cloudinfo")) {
            flags->cloudinfo = TRUE;
            flags->run_all_checks = FALSE;
        } else if (MatchFlag(token, "windowscreds")) {
            flags->windowscreds = TRUE;
            flags->run_all_checks = FALSE;
        } else if (MatchFlag(token, "browserinfo")) {
            flags->browserinfo = TRUE;
            flags->run_all_checks = FALSE;
        } else if (MatchFlag(token, "filesinfo")) {
            flags->filesinfo = TRUE;
            flags->run_all_checks = FALSE;
        } else if (MatchFlag(token, "fileanalysis")) {
            flags->fileanalysis = TRUE;
            flags->filesinfo = TRUE;
            flags->run_all_checks = FALSE;
        } else if (MatchFlag(token, "all")) {
            flags->all = TRUE;
            flags->fileanalysis = TRUE;
            flags->filesinfo = TRUE;
            flags->run_all_checks = TRUE;
        }
        
        // General flags
        else if (MatchFlag(token, "quiet")) {
            flags->quiet = TRUE;
        } else if (MatchFlag(token, "wait")) {
            flags->wait = TRUE;
        } else if (MatchFlag(token, "debug")) {
            flags->debug = TRUE;
        }
        
        // Slow checks
        else if (MatchFlag(token, "lolbas")) {
            flags->lolbas = TRUE;
        }
        
        token = MSVCRT$strtok(NULL, " \t");
    }
    
    intFree(args_copy);
}

void PrintWinPEASUsage(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  WinPEAS BOF - Usage\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "WinPEAS is a BOF to enumerate possible paths to escalate privileges locally.\n");
    BeaconPrintf(CALLBACK_OUTPUT, "By default it'll run all checks unless otherwise specified.\n");
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "Category flags (run specific checks):\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  systeminfo           - Search system information\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  userinfo             - Search user information\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  processinfo          - Search processes information\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  servicesinfo         - Search services information\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  applicationsinfo     - Search installed applications information\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  networkinfo          - Search network information\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  eventsinfo           - Display interesting events information\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  activedirectoryinfo - Quick AD checks (gMSA, AD CS)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  domain               - Enumerate domain information (alias for activedirectoryinfo)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  cloudinfo            - Enumerate cloud information\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  windowscreds         - Search windows credentials\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  browserinfo          - Search browser information\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  filesinfo            - Search generic files that can contain credentials\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  fileanalysis         - [NOT RUN BY DEFAULT] Search specific files and regexes (slow)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  all                  - Run all checks including fileanalysis\n");
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "General flags:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  quiet                - Do not print banner\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  wait                 - Wait for user input between checks\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  debug                - Display debugging information\n");
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "Additional checks (slower):\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  lolbas               - Run additional LOLBAS check\n");
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "Examples:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  winpeas                                    - Run all checks\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  winpeas systeminfo userinfo                - Only system and user checks\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  winpeas domain                             - Include domain enumeration\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  winpeas lolbas                             - Include LOLBAS check\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  winpeas quiet debug                        - Quiet mode with debug\n");
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
}

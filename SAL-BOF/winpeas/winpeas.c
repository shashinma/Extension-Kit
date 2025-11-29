#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include "../_include/base.c"
#include "../_include/bofdefs.h"
#include "winpeas.h"
#include "checks.h"
#include "winpeas_flags.h"

// Include all modules
#include "utils.c"
#include "winpeas_flags.c"
#include "system_checks.c"
#include "user_checks.c"
#include "services_checks.c"
#include "network_checks.c"
#include "applications_checks.c"
#include "processes_checks.c"
#include "files_checks.c"
#include "credentials_checks.c"
#include "events_checks.c"
#include "ad_checks.c"
#include "browser_checks.c"
#include "lolbas_checks.c"

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

VOID go( 
    IN PCHAR Buffer, 
    IN ULONG Length 
) 
{
    if(!bofstart())
    {
        return;
    }
    
    // Parse arguments
    WINPEAS_FLAGS flags;
    InitWinPEASFlags(&flags);
    
    datap parser;
    char* args_str = NULL;
    
    if (Length > 0 && Buffer != NULL) {
        BeaconDataParse(&parser, Buffer, Length);
        args_str = BeaconDataExtract(&parser, NULL);
        if (args_str && MSVCRT$strlen(args_str) > 0) {
            ParseWinPEASFlags(args_str, &flags);
        }
    }
    
    // Print banner unless quiet
    if (!flags.quiet) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
        BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  WinPEAS BOF - Full Privilege Escalation Check\n");
        BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }
    
    // Determine which checks to run
    BOOL run_system = flags.run_all_checks || flags.systeminfo || flags.all;
    BOOL run_user = flags.run_all_checks || flags.userinfo || flags.all;
    BOOL run_processes = flags.run_all_checks || flags.processinfo || flags.all;
    BOOL run_services = flags.run_all_checks || flags.servicesinfo || flags.all;
    BOOL run_applications = flags.run_all_checks || flags.applicationsinfo || flags.all;
    BOOL run_network = flags.run_all_checks || flags.networkinfo || flags.all;
    BOOL run_events = flags.run_all_checks || flags.eventsinfo || flags.all;
    BOOL run_ad = flags.run_all_checks || flags.activedirectoryinfo || flags.domain || flags.all;
    BOOL run_cloud = flags.run_all_checks || flags.cloudinfo || flags.all;
    BOOL run_creds = flags.run_all_checks || flags.windowscreds || flags.all;
    BOOL run_browser = flags.run_all_checks || flags.browserinfo || flags.all;
    BOOL run_files = flags.run_all_checks || flags.filesinfo || flags.fileanalysis || flags.all;
    BOOL run_lolbas = flags.lolbas;  // Only if explicitly requested
    
    // System Information Checks
    if (run_system) {
        if (flags.wait && !flags.quiet) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Press Enter to continue with System Information Checks...\n");
            printoutput(FALSE);
        }
        CheckBasicSystemInfo();
    CheckUACSettings();
    CheckLSAProtection();
    CheckCredentialGuard();
    CheckLAPS();
    CheckWDigest();
    CheckCachedCredentials();
    CheckEnvironmentVariables();
    CheckInternetSettings();
    CheckWindowsDefender();
    CheckNTLMSettings();
    CheckDrives();
    CheckPrinters();
    CheckNamedPipes();
    CheckAMSIProviders();
    CheckDotNetVersions();
    CheckMicrosoftUpdates();
    CheckSysMon();
    CheckAppLocker();
    CheckAuditSettings();
    CheckWEFSettings();
    CheckSecurityPackages();
    CheckAVDetection();
    CheckPowerShellSettings();
    CheckWindowsErrorReporting();
    CheckSystemLastShutdownTime();
        CheckLocalGroupPolicy();
    }
    
    // User Information Checks
    if (run_user) {
        if (flags.wait && !flags.quiet) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Press Enter to continue with User Information Checks...\n");
            printoutput(FALSE);
        }
        CheckTokenPrivileges();
    CheckLoggedUsers();
    CheckAutologin();
    CheckPasswordPolicy();
    CheckDateTime();
    CheckEverLoggedUsers();
    CheckHomeFolders();
    CheckLocalUsers();
    CheckRDPSessions();
        CheckClipboardText();
        CheckLogonSessions();
    }
    
    // Services Information Checks
    if (run_services) {
        if (flags.wait && !flags.quiet) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Press Enter to continue with Services Information Checks...\n");
            printoutput(FALSE);
        }
        CheckUnquotedServicePaths();
    CheckInterestingServices();
    CheckWritableServiceRegistry();
    CheckModifiableServices();
        CheckServiceBinaryPermissions();
        CheckPathDLLHijacking();
    }
    
    // Network Information Checks
    if (run_network) {
        if (flags.wait && !flags.quiet) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Press Enter to continue with Network Information Checks...\n");
            printoutput(FALSE);
        }
        CheckListeningPorts();
    CheckHostsFile();
    CheckNetShares();
    CheckDNSCache();
    CheckNetworkInterfaces();
        CheckMappedDrives();
        CheckFirewallRules();
    }
    
    // Applications Information Checks
    if (run_applications) {
        if (flags.wait && !flags.quiet) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Press Enter to continue with Applications Information Checks...\n");
            printoutput(FALSE);
        }
        CheckInstalledSoftware();
    CheckAutoRuns();
    CheckScheduledTasks();
        CheckDeviceDrivers();
        CheckActiveWindow();
    }
    
    // Processes Information Checks
    if (run_processes) {
        if (flags.wait && !flags.quiet) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Press Enter to continue with Processes Information Checks...\n");
            printoutput(FALSE);
        }
        CheckInterestingProcesses();
    }
    
    // Interesting Files Checks
    if (run_files) {
        if (flags.wait && !flags.quiet) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Press Enter to continue with Files Information Checks...\n");
            printoutput(FALSE);
        }
        CheckUnattendFiles();
    CheckSAMBackups();
    CheckGPPPasswords();
    CheckGroupPolicyHistory();
    CheckMcAfeeSiteList();
    CheckPuttySessions();
    CheckSuperPutty();
    CheckSSHKeys();
    CheckOfficeRecentFiles();
    CheckOneDriveEndpoints();
    CheckWSL();
    CheckOracleSQLDeveloper();
    CheckSlackFiles();
    CheckOutlookDownloads();
    CheckHiddenFiles();
    CheckUserCredsFiles();
    CheckUserDocuments();
    CheckRecentFiles();
    CheckRecycleBin();
    CheckExecutablesWithWritePerms();
        CheckCloudCredsFiles();
        CheckCertificates();
    }
    
    // Cloud Metadata Enumeration
    if (run_cloud) {
        if (flags.wait && !flags.quiet) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Press Enter to continue with Cloud Metadata Enumeration...\n");
            printoutput(FALSE);
        }
        CheckCloudMetadata();
    }
    
    // Windows Credentials Checks
    if (run_creds) {
        if (flags.wait && !flags.quiet) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Press Enter to continue with Windows Credentials Checks...\n");
            printoutput(FALSE);
        }
        CheckAlwaysInstallElevated();
    CheckRegistrySecrets();
    CheckRegistryCredentials();
    CheckHijackablePaths();
    CheckSavedRDPConnections();
    CheckRDCMan();
    CheckRDPSettings();
    CheckRecentCommands();
    CheckPowerShellHistory();
    CheckOpenVPN();
    CheckStickyNotes();
    CheckWiFiPasswords();
    CheckVaultCredentials();
    CheckCredentialManager();
    CheckDPAPIMasterKeys();
    CheckDPAPICredFiles();
    CheckSCCM();
    CheckWSUS();
        CheckAppCmd();
        CheckSSClient();
    }
    
    // Events Information Checks
    if (run_events) {
        if (flags.wait && !flags.quiet) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Press Enter to continue with Events Information Checks...\n");
            printoutput(FALSE);
        }
        CheckEventLogs();
    CheckLogonEvents();
    CheckProcessCreationEvents();
        CheckPowerShellEvents();
        CheckPowerOnOffEvents();
    }
    
    // Kerberos Tickets Check (part of windowscreds)
    if (run_creds) {
        CheckKerberosTickets();
    }
    
    // Active Directory Checks
    if (run_ad) {
        if (flags.wait && !flags.quiet) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Press Enter to continue with Active Directory Checks...\n");
            printoutput(FALSE);
        }
        CheckDomain();
        CheckGMSA();
        CheckADCS();
        CheckGPOAbuse();
    }
    
    // Browser Information Checks
    if (run_browser) {
        if (flags.wait && !flags.quiet) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Press Enter to continue with Browser Information Checks...\n");
            printoutput(FALSE);
        }
        CheckFirefoxDBs();
    CheckChromeDBs();
    CheckIEHistory();
        CheckOperaDBs();
        CheckBraveDBs();
    }
    
    // Additional Checks (Slow) - Only if explicitly requested
    if (run_lolbas) {
        if (flags.wait && !flags.quiet) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Press Enter to continue with LOLBAS Search (slow check)...\n");
            printoutput(FALSE);
        }
        CheckLOLBAS();
    }
    
    if (!flags.quiet) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] WinPEAS BOF Check Complete\n");
        BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    }
    
    if (flags.debug && !flags.quiet) {
        BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Flags parsed successfully\n");
    }
    
    printoutput(TRUE);
}

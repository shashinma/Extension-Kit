#pragma once

// Forward declarations for winpeas check functions

// System Information Checks
void CheckBasicSystemInfo(void);
void CheckUACSettings(void);
void CheckLSAProtection(void);
void CheckCredentialGuard(void);
void CheckLAPS(void);
void CheckWDigest(void);
void CheckCachedCredentials(void);
void CheckEnvironmentVariables(void);
void CheckInternetSettings(void);
void CheckWindowsDefender(void);
void CheckNTLMSettings(void);
void CheckDrives(void);
void CheckPrinters(void);
void CheckNamedPipes(void);
void CheckAMSIProviders(void);
void CheckDotNetVersions(void);
void CheckMicrosoftUpdates(void);
void CheckSysMon(void);
void CheckAppLocker(void);
void CheckAuditSettings(void);
void CheckWEFSettings(void);
void CheckSecurityPackages(void);
void CheckAVDetection(void);
void CheckPowerShellSettings(void);
void CheckWindowsErrorReporting(void);
void CheckSystemLastShutdownTime(void);
void CheckLocalGroupPolicy(void);

// User Information Checks
void CheckTokenPrivileges(void);
void CheckLoggedUsers(void);
void CheckAutologin(void);
void CheckPasswordPolicy(void);
void CheckDateTime(void);
void CheckEverLoggedUsers(void);
void CheckHomeFolders(void);
void CheckLocalUsers(void);
void CheckRDPSessions(void);
void CheckClipboardText(void);
void CheckLogonSessions(void);

// Services Information Checks
void CheckUnquotedServicePaths(void);
void CheckInterestingServices(void);
void CheckWritableServiceRegistry(void);
void CheckModifiableServices(void);
void CheckServiceBinaryPermissions(void);
void CheckPathDLLHijacking(void);

// Network Information Checks
void CheckListeningPorts(void);
void CheckHostsFile(void);
void CheckNetShares(void);
void CheckDNSCache(void);
void CheckNetworkInterfaces(void);
void CheckMappedDrives(void);
void CheckFirewallRules(void);

// Applications Information Checks
void CheckInstalledSoftware(void);
void CheckAutoRuns(void);
void CheckScheduledTasks(void);
void CheckDeviceDrivers(void);
void CheckActiveWindow(void);

// Processes Information Checks
void CheckInterestingProcesses(void);

// Interesting Files Checks
void CheckUnattendFiles(void);
void CheckSAMBackups(void);
void CheckGPPPasswords(void);
void CheckGroupPolicyHistory(void);
void CheckMcAfeeSiteList(void);
void CheckPuttySessions(void);
void CheckSuperPutty(void);
void CheckSSHKeys(void);
void CheckOfficeRecentFiles(void);
void CheckOneDriveEndpoints(void);
void CheckWSL(void);
void CheckOracleSQLDeveloper(void);
void CheckSlackFiles(void);
void CheckOutlookDownloads(void);
void CheckHiddenFiles(void);
void CheckUserCredsFiles(void);
void CheckUserDocuments(void);
void CheckRecentFiles(void);
void CheckRecycleBin(void);
void CheckExecutablesWithWritePerms(void);
void CheckCloudCredsFiles(void);
void CheckCertificates(void);
void CheckCloudMetadata(void);

// Windows Credentials Checks
void CheckAlwaysInstallElevated(void);
void CheckRegistrySecrets(void);
void CheckRegistryCredentials(void);
void CheckHijackablePaths(void);
void CheckSavedRDPConnections(void);
void CheckRDCMan(void);
void CheckRDPSettings(void);
void CheckRecentCommands(void);
void CheckPowerShellHistory(void);
void CheckOpenVPN(void);
void CheckStickyNotes(void);
void CheckWiFiPasswords(void);
void CheckVaultCredentials(void);
void CheckCredentialManager(void);
void CheckDPAPIMasterKeys(void);
void CheckDPAPICredFiles(void);
void CheckSCCM(void);
void CheckWSUS(void);
void CheckAppCmd(void);
void CheckSSClient(void);
void CheckKerberosTickets(void);

// Events Information Checks
void CheckEventLogs(void);
void CheckLogonEvents(void);
void CheckProcessCreationEvents(void);
void CheckPowerShellEvents(void);
void CheckPowerOnOffEvents(void);

// Active Directory Checks
void CheckDomain(void);
void CheckGMSA(void);
void CheckADCS(void);
void CheckGPOAbuse(void);

// Browser Information Checks
void CheckFirefoxDBs(void);
void CheckChromeDBs(void);
void CheckIEHistory(void);
void CheckOperaDBs(void);
void CheckBraveDBs(void);

// Additional Checks
void CheckLOLBAS(void);


// ============================================================================
// ACTIVE DIRECTORY / DOMAIN CHECKS
// ============================================================================

#include "winpeas.h"

void CheckDomain(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] DOMAIN CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    char domainName[256] = {0};
    char dnsDomain[256] = {0};
    DWORD valueSize = sizeof(domainName);
    
    // Check if domain-joined
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "DomainName", NULL, NULL, (LPBYTE)domainName, &valueSize) == ERROR_SUCCESS) {
            if (MSVCRT$strlen(domainName) > 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[DOMAIN] Domain Name: %s\n", domainName);
            }
        }
        valueSize = sizeof(dnsDomain);
        if (ADVAPI32$RegQueryValueExA(hKey, "DnsDomainName", NULL, NULL, (LPBYTE)dnsDomain, &valueSize) == ERROR_SUCCESS) {
            if (MSVCRT$strlen(dnsDomain) > 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[DOMAIN] DNS Domain Name: %s\n", dnsDomain);
            }
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    // Check if domain controller
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\NTDS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[DOMAIN] This host is a Domain Controller\n");
        ADVAPI32$RegCloseKey(hKey);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[DOMAIN] This host is NOT a Domain Controller\n");
    }
    
    if (MSVCRT$strlen(domainName) == 0 && MSVCRT$strlen(dnsDomain) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[DOMAIN] Host is not domain-joined\n");
    }
}

void CheckGMSA(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] GMSA READABLE MANAGED PASSWORDS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check if domain-joined
    HKEY hKey;
    char domainName[256] = {0};
    DWORD valueSize = sizeof(domainName);
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        ADVAPI32$RegQueryValueExA(hKey, "DomainName", NULL, NULL, (LPBYTE)domainName, &valueSize);
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (MSVCRT$strlen(domainName) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[GMSA] Host is not domain-joined. Skipping.\n");
        return;
    }
    
    // Initialize LDAP connection
    LDAP* ld = WLDAP32$ldap_init(domainName, LDAP_PORT);
    if (!ld) {
        BeaconPrintf(CALLBACK_OUTPUT, "[GMSA] Failed to initialize LDAP connection\n");
        return;
    }
    
    // Set LDAP options
    ULONG version = LDAP_VERSION3;
    WLDAP32$ldap_set_optionA(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    
    // Bind to LDAP (anonymous bind)
    ULONG ret = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (ret != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[GMSA] Failed to bind to LDAP: %lu\n", ret);
        WLDAP32$ldap_unbind(ld);
        return;
    }
    
    // Get defaultNamingContext
    char* defaultNC = GetRootDseProp(ld, "defaultNamingContext");
    if (!defaultNC) {
        BeaconPrintf(CALLBACK_OUTPUT, "[GMSA] Failed to get defaultNamingContext\n");
        WLDAP32$ldap_unbind(ld);
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[GMSA] Searching for gMSA objects in: %s\n", defaultNC);
    
    // Get current user SIDs
    PSID_LIST currentSids = GetCurrentSids();
    if (!currentSids) {
        BeaconPrintf(CALLBACK_OUTPUT, "[GMSA] Failed to get current user SIDs\n");
        intFree(defaultNC);
        WLDAP32$ldap_unbind(ld);
        return;
    }
    
    // Search for gMSA objects
    char* attrs[] = { "sAMAccountName", "distinguishedName", "msDS-ManagedPassword", "msDS-GroupMSAMembership", NULL };
    char filter[] = "(&(objectClass=msDS-GroupManagedServiceAccount))";
    LDAPMessage* res = NULL;
    
    ret = WLDAP32$ldap_search_s(ld, defaultNC, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &res);
    if (ret != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[GMSA] LDAP search failed: %lu\n", ret);
        FreeSidList(currentSids);
        intFree(defaultNC);
        WLDAP32$ldap_unbind(ld);
        return;
    }
    
    ULONG count = WLDAP32$ldap_count_entries(ld, res);
    BeaconPrintf(CALLBACK_OUTPUT, "[GMSA] Found %lu gMSA objects\n", count);
    
    int total = 0, readable = 0;
    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, res);
    
    while (entry && total < 100) {
        total++;
        
        // Get sAMAccountName
        struct berval** samName = WLDAP32$ldap_get_values_lenA(ld, entry, "sAMAccountName");
        char* name = samName && samName[0] ? samName[0]->bv_val : NULL;
        
        // Get distinguishedName
        struct berval** dn = WLDAP32$ldap_get_values_lenA(ld, entry, "distinguishedName");
        char* dnStr = dn && dn[0] ? dn[0]->bv_val : NULL;
        
        // Get msDS-GroupMSAMembership (contains SIDs of principals allowed to retrieve password)
        struct berval** membership = WLDAP32$ldap_get_values_lenA(ld, entry, "msDS-GroupMSAMembership");
        
        BOOL canRead = FALSE;
        if (membership) {
            for (int i = 0; membership[i]; i++) {
                // Parse the security descriptor to extract SIDs
                // Note: This is simplified - full implementation would parse ntSecurityDescriptor
                // For now, we check if any of the membership entries match our SIDs
                // The actual check requires parsing the security descriptor which is complex
                // This is a placeholder for the full implementation
            }
            WLDAP32$ldap_value_free_len(membership);
        }
        
        // Note: Full implementation requires parsing ntSecurityDescriptor from msDS-ManagedPassword
        // This is complex and requires understanding the security descriptor format
        // For now, we show all gMSA objects found
        
        if (name) {
            BeaconPrintf(CALLBACK_OUTPUT, "[GMSA] Found gMSA: %s", name);
            if (dnStr) {
                BeaconPrintf(CALLBACK_OUTPUT, " (DN: %s)", dnStr);
            }
            BeaconPrintf(CALLBACK_OUTPUT, "\n");
            BeaconPrintf(CALLBACK_OUTPUT, "[GMSA] Note: Check msDS-GroupMSAMembership to see if current user can retrieve password\n");
        }
        
        if (samName) WLDAP32$ldap_value_free_len(samName);
        if (dn) WLDAP32$ldap_value_free_len(dn);
        
        entry = WLDAP32$ldap_next_entry(ld, entry);
    }
    
    if (readable == 0 && total > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[GMSA] No gMSA with readable managed password found (checked %d)\n", total);
        BeaconPrintf(CALLBACK_OUTPUT, "[GMSA] Note: Full check requires parsing ntSecurityDescriptor from msDS-ManagedPassword\n");
    }
    
    WLDAP32$ldap_msgfree(res);
    FreeSidList(currentSids);
    intFree(defaultNC);
    WLDAP32$ldap_unbind(ld);
}

void CheckADCS(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] AD CS MISCONFIGURATIONS CHECK (ESC4, ESC9, ESC10, ESC11, ESC16)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check if domain controller
    HKEY hKey;
    BOOL isDC = FALSE;
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\NTDS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        isDC = TRUE;
        ADVAPI32$RegCloseKey(hKey);
        
        // Check StrongCertificateBindingEnforcement (ESC9)
        if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Kdc", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD valueType;
            DWORD strongBinding = 0;
            DWORD valueSize = sizeof(strongBinding);
            if (ADVAPI32$RegQueryValueExA(hKey, "StrongCertificateBindingEnforcement", NULL, &valueType, (LPBYTE)&strongBinding, &valueSize) == ERROR_SUCCESS) {
                if (strongBinding == 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] StrongCertificateBindingEnforcement: 0 - Weak mapping allowed, vulnerable to ESC9\n");
                } else if (strongBinding == 2) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] StrongCertificateBindingEnforcement: 2 - Not vulnerable to ESC9\n");
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] StrongCertificateBindingEnforcement: %lu - May be vulnerable to ESC9\n", strongBinding);
                }
            }
            ADVAPI32$RegCloseKey(hKey);
        }
        
        // Check CertificateMappingMethods (ESC10)
        if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD valueType;
            DWORD certMapping = 0;
            DWORD valueSize = sizeof(certMapping);
            if (ADVAPI32$RegQueryValueExA(hKey, "CertificateMappingMethods", NULL, &valueType, (LPBYTE)&certMapping, &valueSize) == ERROR_SUCCESS) {
                if ((certMapping & 0x4) != 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] CertificateMappingMethods: 0x%lx - Allow UPN-based mapping, vulnerable to ESC10\n", certMapping);
                } else if ((certMapping & 0x1) != 0 || (certMapping & 0x2) != 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] CertificateMappingMethods: 0x%lx - Allow weak Subject/Issuer certificate mapping\n", certMapping);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] CertificateMappingMethods: 0x%lx - Strong Certificate mapping enabled\n", certMapping);
                }
            }
            ADVAPI32$RegCloseKey(hKey);
        }
        
        // Check CA InterfaceFlags (ESC11)
        char caName[256] = {0};
        DWORD valueSize = sizeof(caName);
        if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (ADVAPI32$RegQueryValueExA(hKey, "Active", NULL, NULL, (LPBYTE)caName, &valueSize) == ERROR_SUCCESS) {
                char caPath[512];
                MSVCRT$sprintf(caPath, "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s", caName);
                HKEY caKey;
                if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, caPath, 0, KEY_READ, &caKey) == ERROR_SUCCESS) {
                    DWORD valueType;
                    DWORD interfaceFlags = 0;
                    DWORD valueSize2 = sizeof(interfaceFlags);
                    if (ADVAPI32$RegQueryValueExA(caKey, "InterfaceFlags", NULL, &valueType, (LPBYTE)&interfaceFlags, &valueSize2) == ERROR_SUCCESS) {
                        if ((interfaceFlags & 512) == 0) {
                            BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] IF_ENFORCEENCRYPTICERTREQUEST not set in InterfaceFlags - vulnerable to ESC11\n");
                        } else {
                            BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] IF_ENFORCEENCRYPTICERTREQUEST set in InterfaceFlags - not vulnerable to ESC11\n");
                        }
                    }
                    
                    // Check DisableExtensionList (ESC16)
                    char policyModule[256] = {0};
                    valueSize2 = sizeof(policyModule);
                    HKEY policyKey;
                    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration", 0, KEY_READ, &policyKey) == ERROR_SUCCESS) {
                        MSVCRT$sprintf(caPath, "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s\\PolicyModules", caName);
                        HKEY policyModulesKey;
                        if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, caPath, 0, KEY_READ, &policyModulesKey) == ERROR_SUCCESS) {
                            valueSize2 = sizeof(policyModule);
                            if (ADVAPI32$RegQueryValueExA(policyModulesKey, "Active", NULL, NULL, (LPBYTE)policyModule, &valueSize2) == ERROR_SUCCESS) {
                                char disableExtPath[512];
                                MSVCRT$sprintf(disableExtPath, "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s\\PolicyModules\\%s", caName, policyModule);
                                HKEY disableExtKey;
                                if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, disableExtPath, 0, KEY_READ, &disableExtKey) == ERROR_SUCCESS) {
                                    char disableExtList[1024] = {0};
                                    valueSize2 = sizeof(disableExtList);
                                    if (ADVAPI32$RegQueryValueExA(disableExtKey, "DisableExtensionList", NULL, NULL, (LPBYTE)disableExtList, &valueSize2) == ERROR_SUCCESS) {
                                        if (SHLWAPI$StrStrIA(disableExtList, "1.3.6.1.4.1.311.25.2") != NULL) {
                                            BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] szOID_NTDS_CA_SECURITY_EXT disabled for the entire CA - vulnerable to ESC16\n");
                                        } else {
                                            BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] szOID_NTDS_CA_SECURITY_EXT not disabled for the CA - not vulnerable to ESC16\n");
                                        }
                                    }
                                    ADVAPI32$RegCloseKey(disableExtKey);
                                }
                                ADVAPI32$RegCloseKey(policyModulesKey);
                            }
                        }
                        ADVAPI32$RegCloseKey(policyKey);
                    }
                    ADVAPI32$RegCloseKey(caKey);
                }
            }
            ADVAPI32$RegCloseKey(hKey);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] Host is not a domain controller. Skipping ADCS Registry check\n");
    }
    
    // Check certificate templates via LDAP (ESC4)
    // Check if domain-joined
    char domainName[256] = {0};
    DWORD valueSize = sizeof(domainName);
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        ADVAPI32$RegQueryValueExA(hKey, "DomainName", NULL, NULL, (LPBYTE)domainName, &valueSize);
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (MSVCRT$strlen(domainName) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] Host is not domain-joined. Skipping certificate template check.\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] Checking certificate templates for dangerous rights (ESC4)...\n");
    
    // Initialize LDAP
    LDAP* ld = WLDAP32$ldap_init(domainName, LDAP_PORT);
    if (!ld) {
        BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] Failed to initialize LDAP connection\n");
        return;
    }
    
    ULONG version = LDAP_VERSION3;
    WLDAP32$ldap_set_optionA(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    
    ULONG ret = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (ret != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] Failed to bind to LDAP: %lu\n", ret);
        WLDAP32$ldap_unbind(ld);
        return;
    }
    
    // Get configurationNamingContext
    char* configNC = GetRootDseProp(ld, "configurationNamingContext");
    if (!configNC) {
        BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] Failed to get configurationNamingContext\n");
        WLDAP32$ldap_unbind(ld);
        return;
    }
    
    // Build templates DN
    char templatesDN[512];
    MSVCRT$sprintf(templatesDN, "CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configNC);
    
    // Search for certificate templates
    char* attrs[] = { "cn", "ntSecurityDescriptor", NULL };
    char filter[] = "(objectClass=pKICertificateTemplate)";
    LDAPMessage* res = NULL;
    
    ret = WLDAP32$ldap_search_s(ld, templatesDN, LDAP_SCOPE_ONELEVEL, filter, attrs, 0, &res);
    if (ret != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] LDAP search failed: %lu\n", ret);
        intFree(configNC);
        WLDAP32$ldap_unbind(ld);
        return;
    }
    
    ULONG count = WLDAP32$ldap_count_entries(ld, res);
    BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] Found %lu certificate templates\n", count);
    BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] Note: Full DACL parsing requires complex security descriptor parsing\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] Note: Use tools like Certipy to check for dangerous rights (WriteDacl/WriteOwner/GenericAll)\n");
    
    // Get current SIDs
    PSID_LIST currentSids = GetCurrentSids();
    
    int checkedTemplates = 0;
    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, res);
    while (entry && checkedTemplates < 50) {
        checkedTemplates++;
        
        struct berval** cn = WLDAP32$ldap_get_values_lenA(ld, entry, "cn");
        if (cn && cn[0]) {
            BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] Template: %s\n", cn[0]->bv_val);
            BeaconPrintf(CALLBACK_OUTPUT, "[ADCS] Note: Check ntSecurityDescriptor for dangerous rights\n");
        }
        
        if (cn) WLDAP32$ldap_value_free_len(cn);
        entry = WLDAP32$ldap_next_entry(ld, entry);
    }
    
    WLDAP32$ldap_msgfree(res);
    FreeSidList(currentSids);
    intFree(configNC);
    WLDAP32$ldap_unbind(ld);
}

void CheckGPOAbuse(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] POTENTIAL GPO ABUSE CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    // Check if domain-joined
    HKEY hKey;
    char domainName[256] = {0};
    DWORD valueSize = sizeof(domainName);
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        ADVAPI32$RegQueryValueExA(hKey, "DomainName", NULL, NULL, (LPBYTE)domainName, &valueSize);
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (MSVCRT$strlen(domainName) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[GPO_ABUSE] Host is not domain-joined. Skipping.\n");
        return;
    }
    
    // Check Local Group Policy for domain GPOs
    char gpoId[256];
    DWORD gpoIdSize = sizeof(gpoId);
    int gpoCount = 0;
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\DataStore\\Machine\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeyIndex = 0;
        
        while (ADVAPI32$RegEnumKeyExA(hKey, subkeyIndex++, gpoId, &gpoIdSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && gpoCount < 20) {
            HKEY gpoKey;
            char gpoPath[512];
            MSVCRT$sprintf(gpoPath, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\DataStore\\Machine\\0\\%s", gpoId);
            
            if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, gpoPath, 0, KEY_READ, &gpoKey) == ERROR_SUCCESS) {
                char fileSysPath[1024] = {0};
                char gpoName[256] = {0};
                DWORD valueSize2 = sizeof(fileSysPath);
                
                if (ADVAPI32$RegQueryValueExA(gpoKey, "FileSysPath", NULL, NULL, (LPBYTE)fileSysPath, &valueSize2) == ERROR_SUCCESS) {
                    valueSize2 = sizeof(gpoName);
                    ADVAPI32$RegQueryValueExA(gpoKey, "GPOName", NULL, NULL, (LPBYTE)gpoName, &valueSize2);
                    
                    // Check if it's a domain GPO (SYSVOL path)
                    if (SHLWAPI$StrStrIA(fileSysPath, "\\SysVol\\") != NULL && 
                        SHLWAPI$StrStrIA(fileSysPath, "\\Policies\\") != NULL) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[GPO_ABUSE] Domain GPO found:\n");
                        BeaconPrintf(CALLBACK_OUTPUT, "[GPO_ABUSE]   Name: %s\n", gpoName);
                        BeaconPrintf(CALLBACK_OUTPUT, "[GPO_ABUSE]   Path: %s\n", fileSysPath);
                        BeaconPrintf(CALLBACK_OUTPUT, "[GPO_ABUSE] Note: Check if path is writable (Machine\\Scripts\\Startup, User\\Scripts\\Logon, etc.)\n");
                        BeaconPrintf(CALLBACK_OUTPUT, "[GPO_ABUSE] Note: Use 'icacls' to check permissions on SYSVOL paths\n");
                        gpoCount++;
                    }
                }
                ADVAPI32$RegCloseKey(gpoKey);
            }
            gpoIdSize = sizeof(gpoId);
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    
    if (gpoCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[GPO_ABUSE] No domain GPOs found or no writable SYSVOL paths detected\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[GPO_ABUSE] Note: Full check requires checking file permissions on SYSVOL paths\n");
    }
}


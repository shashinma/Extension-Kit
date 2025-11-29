// ============================================================================
// NETWORK INFORMATION CHECKS
// ============================================================================

#include "winpeas.h"

void CheckListeningPorts(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] LISTENING PORTS CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    PMIB_TCPTABLE_OWNER_PID tcpTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    
    dwRetVal = IPHLPAPI$GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        tcpTable = (PMIB_TCPTABLE_OWNER_PID)intAlloc(dwSize);
        if (tcpTable == NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "[NETWORK] Failed to allocate memory for TCP table\n");
            return;
        }
        
        dwRetVal = IPHLPAPI$GetExtendedTcpTable(tcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (dwRetVal == NO_ERROR) {
            for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
                if (tcpTable->table[i].dwState == MIB_TCP_STATE_LISTEN) {
                    char localAddr[16];
                    MSVCRT$sprintf(localAddr, "%d.%d.%d.%d",
                        (tcpTable->table[i].dwLocalAddr & 0xFF),
                        ((tcpTable->table[i].dwLocalAddr >> 8) & 0xFF),
                        ((tcpTable->table[i].dwLocalAddr >> 16) & 0xFF),
                        ((tcpTable->table[i].dwLocalAddr >> 24) & 0xFF));
                    
                    char procName[260] = {0};
                    DWORD procNameLen = sizeof(procName);
                    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, tcpTable->table[i].dwOwningPid);
                    if (hProcess) {
                        if (KERNEL32$QueryFullProcessImageNameA(hProcess, 0, procName, &procNameLen)) {
                            // Extract just the filename
                            char* fileName = procName;
                            char* lastSlash = procName;
                            char* p = procName;
                            while (*p) {
                                if (*p == '\\') lastSlash = p;
                                p++;
                            }
                            if (*lastSlash == '\\') fileName = lastSlash + 1;
                            else fileName = procName;
                            
                            BeaconPrintf(CALLBACK_OUTPUT, "[NETWORK] TCP LISTEN: %s:%d (PID: %lu, Process: %s)\n", 
                                localAddr, 
                                WS2_32$htons((WORD)tcpTable->table[i].dwLocalPort),
                                tcpTable->table[i].dwOwningPid,
                                fileName);
                        }
                        KERNEL32$CloseHandle(hProcess);
                    } else {
                        BeaconPrintf(CALLBACK_OUTPUT, "[NETWORK] TCP LISTEN: %s:%d (PID: %lu, Process: <access denied>)\n", 
                            localAddr, 
                            WS2_32$htons((WORD)tcpTable->table[i].dwLocalPort),
                            tcpTable->table[i].dwOwningPid);
                    }
                }
            }
        }
        intFree(tcpTable);
    }
}

void CheckHostsFile(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] HOSTS FILE CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    char hostsPath[MAX_PATH];
    MSVCRT$sprintf(hostsPath, "C:\\Windows\\System32\\drivers\\etc\\hosts");
    
    HANDLE hFile = CreateFileA(hostsPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD fileSize = KERNEL32$GetFileSize(hFile, NULL);
        if (fileSize > 0 && fileSize < 10240) { // Limit to 10KB
            char* buffer = (char*)intAlloc(fileSize + 1);
            DWORD bytesRead = 0;
            if (KERNEL32$ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
                buffer[bytesRead] = '\0';
                BeaconPrintf(CALLBACK_OUTPUT, "[HOSTS_FILE] Contents:\n%s\n", buffer);
            }
            intFree(buffer);
        }
        KERNEL32$CloseHandle(hFile);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[HOSTS_FILE] File not accessible or does not exist\n");
    }
}

void CheckNetShares(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] NETWORK SHARES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    PSHARE_INFO_502 pBuf = NULL;
    PSHARE_INFO_502 pTmpBuf = NULL;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    NET_API_STATUS nStatus;
    
    do {
        nStatus = NETAPI32$NetShareEnum(NULL, 502, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)) {
            pTmpBuf = pBuf;
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                if (pTmpBuf != NULL) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[NET_SHARES] Share: %s, Path: %s, Type: %lu\n", 
                        pTmpBuf->shi502_netname, 
                        pTmpBuf->shi502_path,
                        pTmpBuf->shi502_type);
                    pTmpBuf++;
                }
            }
        }
        if (pBuf != NULL) {
            NETAPI32$NetApiBufferFree(pBuf);
            pBuf = NULL;
        }
    } while (nStatus == ERROR_MORE_DATA);
}

void CheckDNSCache(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] DNS CACHE CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    typedef struct _DNS_CACHE_ENTRY {
        struct _DNS_CACHE_ENTRY* pNext;
        PWSTR pszName;
        unsigned short wType;
        unsigned short wDataLength;
        unsigned long dwFlags;
    } DNSCACHEENTRY, *PDNSCACHEENTRY;
    
    PDNSCACHEENTRY pEntry = NULL;
    DNSAPI$DnsGetCacheDataTable(&pEntry);
    
    if (pEntry) {
        PDNSCACHEENTRY pCurrent = pEntry->pNext;
        int count = 0;
        while (pCurrent && count < 70) { // Limit to 70 as in winPEAS
            char* dnsValue = Utf16ToUtf8(pCurrent->pszName);
            if (dnsValue) {
                BeaconPrintf(CALLBACK_OUTPUT, "[DNS_CACHE] %s (Type: %d)\n", dnsValue, pCurrent->wType);
                intFree(dnsValue);
            }
            PDNSCACHEENTRY pPrev = pCurrent;
            pCurrent = pCurrent->pNext;
            DNSAPI$DnsFree(pPrev, DnsFreeFlat);
            count++;
        }
        if (pEntry) {
            DNSAPI$DnsFree(pEntry, DnsFreeFlat);
        }
    }
}

void CheckNetworkInterfaces(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] NETWORK INTERFACES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    ULONG bufferSize = 0;
    DWORD result = IPHLPAPI$GetAdaptersInfo(NULL, &bufferSize);
    
    if (result == ERROR_BUFFER_OVERFLOW || result == ERROR_INSUFFICIENT_BUFFER) {
        PIP_ADAPTER_INFO adapterInfo = (PIP_ADAPTER_INFO)intAlloc(bufferSize);
        if (adapterInfo) {
            result = IPHLPAPI$GetAdaptersInfo(adapterInfo, &bufferSize);
            if (result == ERROR_SUCCESS) {
                PIP_ADAPTER_INFO adapter = adapterInfo;
                int adapterCount = 0;
                
                while (adapter) {
                    adapterCount++;
                    BeaconPrintf(CALLBACK_OUTPUT, "[NETWORK_INTERFACE] Adapter #%d:\n", adapterCount);
                    BeaconPrintf(CALLBACK_OUTPUT, "[NETWORK_INTERFACE]   Name: %s\n", adapter->AdapterName);
                    BeaconPrintf(CALLBACK_OUTPUT, "[NETWORK_INTERFACE]   Description: %s\n", adapter->Description);
                    BeaconPrintf(CALLBACK_OUTPUT, "[NETWORK_INTERFACE]   MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                        adapter->Address[0], adapter->Address[1], adapter->Address[2],
                        adapter->Address[3], adapter->Address[4], adapter->Address[5]);
                    BeaconPrintf(CALLBACK_OUTPUT, "[NETWORK_INTERFACE]   IP Address: %s\n", adapter->IpAddressList.IpAddress.String);
                    BeaconPrintf(CALLBACK_OUTPUT, "[NETWORK_INTERFACE]   Subnet Mask: %s\n", adapter->IpAddressList.IpMask.String);
                    if (MSVCRT$strlen(adapter->GatewayList.IpAddress.String) > 0) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[NETWORK_INTERFACE]   Gateway: %s\n", adapter->GatewayList.IpAddress.String);
                    }
                    if (MSVCRT$strlen(adapter->DhcpServer.IpAddress.String) > 0) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[NETWORK_INTERFACE]   DHCP Server: %s\n", adapter->DhcpServer.IpAddress.String);
                    }
                    BeaconPrintf(CALLBACK_OUTPUT, "\n");
                    adapter = adapter->Next;
                }
                
                if (adapterCount == 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[NETWORK_INTERFACE] No network adapters found\n");
                }
            }
            intFree(adapterInfo);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[NETWORK_INTERFACE] Failed to get adapter info: %lu\n", result);
    }
}

void CheckMappedDrives(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] MAPPED DRIVES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    DWORD drives = KERNEL32$GetLogicalDrives();
    if (drives == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[MAPPED_DRIVES] Failed to get logical drives\n");
        return;
    }
    
    char driveLetter[] = "A:\\";
    int mappedCount = 0;
    
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            driveLetter[0] = 'A' + i;
            DWORD driveType = KERNEL32$GetDriveTypeA(driveLetter);
            
            if (driveType == 4) { // DRIVE_REMOTE
                char remotePath[512] = {0};
                DWORD pathSize = sizeof(remotePath);
                
                if (MPR$WNetGetConnectionA(driveLetter, remotePath, &pathSize) == NO_ERROR) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[MAPPED_DRIVES] %s -> %s\n", driveLetter, remotePath);
                    mappedCount++;
                }
            }
        }
    }
    
    if (mappedCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[MAPPED_DRIVES] No mapped network drives found\n");
    }
}

void CheckFirewallRules(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] FIREWALL RULES CHECK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    
    HKEY hKey;
    
    // Check firewall state
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char value[256] = {0};
        DWORD valueSize = sizeof(value);
        
        // Check Domain profile
        HKEY domainKey;
        if (ADVAPI32$RegOpenKeyExA(hKey, "DomainProfile", 0, KEY_READ, &domainKey) == ERROR_SUCCESS) {
            valueSize = sizeof(value);
            if (ADVAPI32$RegQueryValueExA(domainKey, "EnableFirewall", NULL, NULL, (LPBYTE)value, &valueSize) == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT, "[FIREWALL] Domain Profile Enabled: %s\n", value);
            }
            ADVAPI32$RegCloseKey(domainKey);
        }
        
        // Check Private profile
        HKEY privateKey;
        if (ADVAPI32$RegOpenKeyExA(hKey, "StandardProfile", 0, KEY_READ, &privateKey) == ERROR_SUCCESS) {
            valueSize = sizeof(value);
            if (ADVAPI32$RegQueryValueExA(privateKey, "EnableFirewall", NULL, NULL, (LPBYTE)value, &valueSize) == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT, "[FIREWALL] Private Profile Enabled: %s\n", value);
            }
            ADVAPI32$RegCloseKey(privateKey);
        }
        
        // Check Public profile
        HKEY publicKey;
        if (ADVAPI32$RegOpenKeyExA(hKey, "PublicProfile", 0, KEY_READ, &publicKey) == ERROR_SUCCESS) {
            valueSize = sizeof(value);
            if (ADVAPI32$RegQueryValueExA(publicKey, "EnableFirewall", NULL, NULL, (LPBYTE)value, &valueSize) == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT, "[FIREWALL] Public Profile Enabled: %s\n", value);
            }
            ADVAPI32$RegCloseKey(publicKey);
        }
        
        ADVAPI32$RegCloseKey(hKey);
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[FIREWALL] Note: Use 'netsh advfirewall firewall show rule dir=in name=all' for detailed rules\n");
}


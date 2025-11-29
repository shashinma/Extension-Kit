// ============================================================================
// UTILITY FUNCTIONS FOR WINPEAS
// ============================================================================

#include "winpeas.h"

// Helper function to get current user and group SIDs
PSID_LIST GetCurrentSids(void) {
    PSID_LIST sidList = NULL;
    HANDLE hToken = NULL;
    
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return NULL;
    }
    
    DWORD tokenInfoSize = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoSize);
    if (tokenInfoSize > 0) {
        PTOKEN_USER pTokenUser = (PTOKEN_USER)intAlloc(tokenInfoSize);
        if (pTokenUser && ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, tokenInfoSize, &tokenInfoSize)) {
            PSID pSid = pTokenUser->User.Sid;
            LPSTR sidString = NULL;
            if (ADVAPI32$ConvertSidToStringSidA(pSid, &sidString)) {
                PSID_LIST newItem = (PSID_LIST)intAlloc(sizeof(SID_LIST));
                if (newItem) {
                    MSVCRT$strcpy(newItem->sid, sidString);
                    newItem->next = sidList;
                    sidList = newItem;
                }
                KERNEL32$LocalFree(sidString);
            }
        }
        if (pTokenUser) intFree(pTokenUser);
    }
    
    // Get groups
    ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &tokenInfoSize);
    if (tokenInfoSize > 0) {
        PTOKEN_GROUPS pTokenGroups = (PTOKEN_GROUPS)intAlloc(tokenInfoSize);
        if (pTokenGroups && ADVAPI32$GetTokenInformation(hToken, TokenGroups, pTokenGroups, tokenInfoSize, &tokenInfoSize)) {
            for (DWORD i = 0; i < pTokenGroups->GroupCount; i++) {
                PSID pSid = pTokenGroups->Groups[i].Sid;
                LPSTR sidString = NULL;
                if (ADVAPI32$ConvertSidToStringSidA(pSid, &sidString)) {
                    PSID_LIST newItem = (PSID_LIST)intAlloc(sizeof(SID_LIST));
                    if (newItem) {
                        MSVCRT$strcpy(newItem->sid, sidString);
                        newItem->next = sidList;
                        sidList = newItem;
                    }
                    KERNEL32$LocalFree(sidString);
                }
            }
        }
        if (pTokenGroups) intFree(pTokenGroups);
    }
    
    KERNEL32$CloseHandle(hToken);
    return sidList;
}

void FreeSidList(PSID_LIST sidList) {
    while (sidList) {
        PSID_LIST next = sidList->next;
        intFree(sidList);
        sidList = next;
    }
}

BOOL IsSidInList(PSID_LIST sidList, const char* sid) {
    while (sidList) {
        if (MSVCRT$_stricmp(sidList->sid, sid) == 0) {
            return TRUE;
        }
        sidList = sidList->next;
    }
    return FALSE;
}

// Get RootDSE property via LDAP
char* GetRootDseProp(LDAP* ld, const char* prop) {
    char* attrs[] = { (char*)prop, NULL };
    LDAPMessage* res = NULL;
    char* result = NULL;
    
    ULONG ret = WLDAP32$ldap_search_s(ld, "", LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &res);
    if (ret == LDAP_SUCCESS && res) {
        LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, res);
        if (entry) {
            struct berval** vals = WLDAP32$ldap_get_values_lenA(ld, entry, (PCHAR)prop);
            if (vals && vals[0]) {
                result = (char*)intAlloc(vals[0]->bv_len + 1);
                if (result) {
                    MSVCRT$memcpy(result, vals[0]->bv_val, vals[0]->bv_len);
                    result[vals[0]->bv_len] = '\0';
                }
                WLDAP32$ldap_value_free_len(vals);
            }
        }
        WLDAP32$ldap_msgfree(res);
    }
    
    return result;
}


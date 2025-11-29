#pragma once

// Structure to hold all WinPEAS flags
typedef struct {
    // Category flags (check categories)
    BOOL systeminfo;
    BOOL userinfo;
    BOOL processinfo;
    BOOL servicesinfo;
    BOOL applicationsinfo;
    BOOL networkinfo;
    BOOL eventsinfo;
    BOOL activedirectoryinfo;
    BOOL domain;  // Alias for activedirectoryinfo
    BOOL cloudinfo;
    BOOL windowscreds;
    BOOL browserinfo;
    BOOL filesinfo;
    BOOL fileanalysis;
    BOOL all;  // Run all checks including fileanalysis
    
    // General flags
    BOOL quiet;  // Don't print banner
    BOOL wait;  // Wait for user input between checks
    BOOL debug;  // Display debug information
    
    // Slow checks (additional)
    BOOL lolbas;  // Run LOLBAS check
    
    // Internal flags
    BOOL run_all_checks;  // If no specific categories specified, run all
} WINPEAS_FLAGS;

// Function to initialize flags structure with defaults
void InitWinPEASFlags(WINPEAS_FLAGS* flags);

// Function to parse command line arguments
void ParseWinPEASFlags(const char* args, WINPEAS_FLAGS* flags);

// Function to print usage/help
void PrintWinPEASUsage(void);

// Helper function to check if a string matches a flag (case insensitive)
BOOL MatchFlag(const char* arg, const char* flag);

// Helper function to split string by spaces and parse
void ParseArgsString(const char* args, WINPEAS_FLAGS* flags);


var metadata = {
    name: "SAL-BOF",
    description: "Situation Awareness Local BOFs"
};


var cmd_arp = ax.create_command("arp", "List ARP table", "arp");
cmd_arp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/arp." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: arp");
});

var cmd_cacls = ax.create_command("cacls", "List user permissions for the specified file or directory, wildcards supported", "cacls C:\\test.txt");
cmd_cacls.addArgString("path", true);
cmd_cacls.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let path = parsed_json["path"];

    let bof_params = ax.bof_pack("wstr", [path]);
    let bof_path = ax.script_dir() + "_bin/cacls." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF implementation: cacls");
});

var cmd_dir = ax.create_command("dir", "Lists files in a specified directory. Supports wildcards (e.g. \"C:\\Windows\\S*\"). Optionally, it can perform a recursive list with the /s argument", "dir C:\\Users /s");
cmd_dir.addArgString("directory", ".\\");
cmd_dir.addArgBool("/s", "Recursive list");
cmd_dir.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let directory = parsed_json["directory"];
    let recursive = 0;

    if(parsed_json["/s"]) { recursive = 1; }

    let bof_params = ax.bof_pack("wstr,int", [directory, recursive]);
    let bof_path = ax.script_dir() + "_bin/dir." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF implementation: dir");
});

var cmd_env = ax.create_command("env", "List process environment variables", "env");
cmd_env.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/env." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "List process environment variables (BOF)");
});

var cmd_ipconfig = ax.create_command("ipconfig", "List IPv4 address, hostname, and DNS server", "ipconfig");
cmd_ipconfig.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/ipconfig." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: ipconfig");
});

var cmd_listdns = ax.create_command("listdns", "List DNS cache entries. Attempt to query and resolve each", "listdns");
cmd_listdns.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/listdns." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: ipconfig /displaydns");
});

var cmd_netstat = ax.create_command("netstat", "Executes the netstat command to display network connections", "netstat");
cmd_netstat.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/netstat." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: netstat");
});

var cmd_nslookup = ax.create_command("nslookup", "Make a DNS query", "nslookup google.com -s 8.8.8.8 -t A");
cmd_nslookup.addArgString("domain", true);
cmd_nslookup.addArgFlagString("-s", "server", "DNS server is the server you want to query", "");
cmd_nslookup.addArgFlagString("-t", "type", "Record type is something like A, AAAA, or ANY", "A");
cmd_nslookup.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let domain = parsed_json["domain"];
    let server = parsed_json["server"];
    let type   = parsed_json["type"];

    let bof_params = ax.bof_pack("cstr,cstr,cstr", [domain, type, server]);
    let bof_path = ax.script_dir() + "_bin/nslookup." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF implementation: nslookup");
});

var _cmd_privcheck_alwayselevated = ax.create_command("alwayselevated", "Checks if Always Install Elevated is enabled using the registry", "privcheck alwayselevated");
_cmd_privcheck_alwayselevated.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/alwayselevated." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Checks AlwaysInstallElevated");
});
var _cmd_privcheck_hijackablepath = ax.create_command("hijackablepath", "Checks the path environment variable for writable directories (FILE_ADD_FILE) that can be exploited to elevate privileges", "privcheck hijackablepath");
_cmd_privcheck_hijackablepath.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/hijackablepath." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Checks HijackablePath");
});
var _cmd_privcheck_tokenpriv = ax.create_command("tokenpriv", "Lists the current token privileges and highlights known vulnerable ones", "privcheck tokenpriv");
_cmd_privcheck_tokenpriv.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/tokenpriv." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Checks TokenPrivileges");
});
var _cmd_privcheck_unattendfiles = ax.create_command("unattendfiles", "Checks for leftover unattend files that might contain sensitive information", "privcheck unattendfiles");
_cmd_privcheck_unattendfiles.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/unattendfiles." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Checks UnattendFiles");
});
var _cmd_privcheck_unquotedsvc = ax.create_command("unquotedsvc", "Checks for unquoted service paths", "privcheck unquotedsvc");
_cmd_privcheck_unquotedsvc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/unquotedsvc." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Checks Unquoted Service Path");
});
var _cmd_privcheck_vulndrivers = ax.create_command("vulndrivers", "Checks if any service on the system uses a known vulnerable driver (based on loldrivers.io)", "privcheck vulndrivers");
_cmd_privcheck_vulndrivers.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/vulndrivers." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Checks Vulnerable Drivers");
});
var cmd_findobj = ax.create_command("privcheck", "Perform privcheck functions");
cmd_findobj.addSubCommands([_cmd_privcheck_alwayselevated, _cmd_privcheck_hijackablepath, _cmd_privcheck_tokenpriv, _cmd_privcheck_unattendfiles, _cmd_privcheck_unquotedsvc, _cmd_privcheck_vulndrivers]);

var cmd_routeprint = ax.create_command("routeprint", "List IPv4 routes", "routeprint");
cmd_routeprint.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/routeprint." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: route");
});

var cmd_uptime = ax.create_command("uptime", "List system boot time and how long it has been running", "uptime");
cmd_uptime.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/uptime." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: uptime");
});

var cmd_useridletime = ax.create_command("useridletime", "Shows how long the user as been idle, displayed in seconds, minutes, hours and days", "useridletime");
cmd_useridletime.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/useridletime." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: useridletime");
});

var cmd_whoami = ax.create_command("whoami", "List whoami /all, hours and days", "whoami");
cmd_whoami.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/whoami." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: whoami /all");
});

var cmd_winpeas = ax.create_command("winpeas", "Comprehensive Windows privilege escalation enumeration (WinPEAS BOF)", "winpeas");
// Category flags
cmd_winpeas.addArgBool("systeminfo", "Search system information");
cmd_winpeas.addArgBool("userinfo", "Search user information");
cmd_winpeas.addArgBool("processinfo", "Search processes information");
cmd_winpeas.addArgBool("servicesinfo", "Search services information");
cmd_winpeas.addArgBool("applicationsinfo", "Search installed applications information");
cmd_winpeas.addArgBool("networkinfo", "Search network information");
cmd_winpeas.addArgBool("eventsinfo", "Display interesting events information");
cmd_winpeas.addArgBool("activedirectoryinfo", "Quick AD checks (gMSA, AD CS)");
cmd_winpeas.addArgBool("domain", "Enumerate domain information (alias for activedirectoryinfo)");
cmd_winpeas.addArgBool("cloudinfo", "Enumerate cloud information");
cmd_winpeas.addArgBool("windowscreds", "Search windows credentials");
cmd_winpeas.addArgBool("browserinfo", "Search browser information");
cmd_winpeas.addArgBool("filesinfo", "Search generic files that can contain credentials");
cmd_winpeas.addArgBool("fileanalysis", "[NOT RUN BY DEFAULT] Search specific files and regexes (slow)");
cmd_winpeas.addArgBool("all", "Run all checks including fileanalysis");
// General flags
cmd_winpeas.addArgBool("quiet", "Do not print banner");
cmd_winpeas.addArgBool("wait", "Wait for user input between checks");
cmd_winpeas.addArgBool("debug", "Display debugging information");
// Additional checks (slower)
cmd_winpeas.addArgBool("lolbas", "Run additional LOLBAS check");
cmd_winpeas.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/winpeas." + ax.arch(id) + ".o";
    
    // Build flags string from parsed arguments
    let flags_parts = [];
    
    // Category flags
    if (parsed_json["systeminfo"]) flags_parts.push("systeminfo");
    if (parsed_json["userinfo"]) flags_parts.push("userinfo");
    if (parsed_json["processinfo"]) flags_parts.push("processinfo");
    if (parsed_json["servicesinfo"]) flags_parts.push("servicesinfo");
    if (parsed_json["applicationsinfo"]) flags_parts.push("applicationsinfo");
    if (parsed_json["networkinfo"]) flags_parts.push("networkinfo");
    if (parsed_json["eventsinfo"]) flags_parts.push("eventsinfo");
    if (parsed_json["activedirectoryinfo"]) flags_parts.push("activedirectoryinfo");
    if (parsed_json["domain"]) flags_parts.push("domain");
    if (parsed_json["cloudinfo"]) flags_parts.push("cloudinfo");
    if (parsed_json["windowscreds"]) flags_parts.push("windowscreds");
    if (parsed_json["browserinfo"]) flags_parts.push("browserinfo");
    if (parsed_json["filesinfo"]) flags_parts.push("filesinfo");
    if (parsed_json["fileanalysis"]) flags_parts.push("fileanalysis");
    if (parsed_json["all"]) flags_parts.push("all");
    
    // General flags
    if (parsed_json["quiet"]) flags_parts.push("quiet");
    if (parsed_json["wait"]) flags_parts.push("wait");
    if (parsed_json["debug"]) flags_parts.push("debug");
    
    // Additional checks
    if (parsed_json["lolbas"]) flags_parts.push("lolbas");
    
    // Join flags with spaces (BOF will parse both space-separated and dash-concatenated)
    let flags_str = flags_parts.join(" ");
    
    // Pass cmdline as first argument (like SauronEyeBOF) for backward compatibility
    let bof_params = ax.bof_pack("cstr", [flags_str || cmdline.replace(/^winpeas\s+/, "").trim()]);
    
    let cmd = "execute bof";
    if (ax.agent_info(id, "type") == "kharon") { cmd = "exec-bof"; }
    
    ax.execute_alias(id, cmdline, `${cmd} ${bof_path} ${bof_params}`, "BOF implementation: WinPEAS privilege escalation check");
});

var group_test = ax.create_commands_group("SAL-BOF", [cmd_arp, cmd_cacls, cmd_dir, cmd_env, cmd_ipconfig, cmd_listdns, cmd_netstat, cmd_nslookup, cmd_findobj, cmd_routeprint, cmd_uptime, cmd_useridletime, cmd_whoami, cmd_winpeas]);
ax.register_commands_group(group_test, ["beacon", "gopher", "kharon"], ["windows"], []);

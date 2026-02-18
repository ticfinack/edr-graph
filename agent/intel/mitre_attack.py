"""Bundled MITRE ATT&CK technique data for EDR-relevant techniques.

Covers ~80 techniques across: Execution, Persistence, Privilege Escalation,
Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection,
Exfiltration, and Command & Control.
"""

from __future__ import annotations

TECHNIQUES: dict[str, dict[str, str]] = {
    # --- Execution ---
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "mitigations": "Disable or remove unnecessary scripting interpreters; use application whitelisting.",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in Windows.",
        "mitigations": "Enable PowerShell Script Block Logging; use Constrained Language Mode; restrict PowerShell execution policy.",
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "description": "Adversaries may abuse the Windows command shell (cmd.exe) for execution.",
        "mitigations": "Restrict cmd.exe execution; monitor for unusual command-line arguments.",
    },
    "T1059.004": {
        "name": "Unix Shell",
        "tactic": "Execution",
        "description": "Adversaries may abuse Unix shell commands and scripts for execution. Unix shells such as sh, bash, and zsh are common on Linux and macOS.",
        "mitigations": "Restrict shell access; monitor shell command history and audit logs.",
    },
    "T1059.005": {
        "name": "Visual Basic",
        "tactic": "Execution",
        "description": "Adversaries may abuse Visual Basic (VB) for execution. VB includes VBScript and macros in Office documents.",
        "mitigations": "Disable Office VBA macros; block VBScript execution.",
    },
    "T1059.006": {
        "name": "Python",
        "tactic": "Execution",
        "description": "Adversaries may abuse Python commands and scripts for execution.",
        "mitigations": "Restrict Python installation; monitor for unexpected Python processes.",
    },
    "T1059.007": {
        "name": "JavaScript",
        "tactic": "Execution",
        "description": "Adversaries may abuse JavaScript for execution. JavaScript can run via wscript, cscript, or Node.js.",
        "mitigations": "Restrict JS/JScript execution; disable Windows Script Host.",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Execution",
        "description": "Adversaries may abuse task scheduling to execute malicious code at system startup or on a scheduled basis.",
        "mitigations": "Restrict task creation permissions; audit scheduled tasks regularly.",
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactic": "Execution",
        "description": "Adversaries may abuse the Windows Task Scheduler to schedule programs for recurring execution.",
        "mitigations": "Limit schtasks.exe access; audit the task folder.",
    },
    "T1053.003": {
        "name": "Cron",
        "tactic": "Execution",
        "description": "Adversaries may abuse the cron utility to execute malicious code on Linux/macOS at recurring intervals.",
        "mitigations": "Restrict crontab access; monitor /var/spool/cron and /etc/cron.*.",
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "description": "An adversary relies upon a user to execute a malicious file or link.",
        "mitigations": "User awareness training; restrict execution of unknown files.",
    },
    "T1106": {
        "name": "Native API",
        "tactic": "Execution",
        "description": "Adversaries may use the OS native API to execute behaviors.",
        "mitigations": "Monitor API calls; use endpoint detection and response tools.",
    },
    # --- Persistence ---
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "description": "Adversaries may configure system settings to run a program during system boot or logon.",
        "mitigations": "Monitor autostart locations (registry Run keys, startup folders, LaunchAgents).",
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry Run key.",
        "mitigations": "Monitor HKCU/HKLM Run keys and startup folder for changes.",
    },
    "T1547.011": {
        "name": "Plist Modification",
        "tactic": "Persistence",
        "description": "Adversaries may modify property list (plist) files to run programs during system boot or user login on macOS.",
        "mitigations": "Monitor LaunchAgent/LaunchDaemon plist directories.",
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "Persistence",
        "description": "Adversaries may create or modify system-level processes to execute malicious payloads as part of persistence.",
        "mitigations": "Audit new services/daemons; restrict service creation permissions.",
    },
    "T1543.001": {
        "name": "Launch Agent",
        "tactic": "Persistence",
        "description": "Adversaries may create or modify Launch Agents to execute malicious payloads on macOS.",
        "mitigations": "Monitor ~/Library/LaunchAgents and /Library/LaunchAgents.",
    },
    "T1543.002": {
        "name": "Systemd Service",
        "tactic": "Persistence",
        "description": "Adversaries may create or modify systemd services to execute malicious payloads on Linux.",
        "mitigations": "Monitor /etc/systemd/ and ~/.config/systemd/; audit systemctl commands.",
    },
    "T1543.003": {
        "name": "Windows Service",
        "tactic": "Persistence",
        "description": "Adversaries may install a new service or modify an existing one to execute at startup.",
        "mitigations": "Restrict service creation; audit sc.exe and services registry keys.",
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "Persistence",
        "description": "Adversaries may create an account to maintain access to victim systems.",
        "mitigations": "Monitor for new account creation events; restrict account creation permissions.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Persistence",
        "description": "Adversaries may use stolen credentials to maintain persistence and access.",
        "mitigations": "Enforce MFA; monitor for unusual logon patterns.",
    },
    "T1546.004": {
        "name": ".bash_profile and .bashrc",
        "tactic": "Persistence",
        "description": "Adversaries may establish persistence by executing malicious commands via shell profile files.",
        "mitigations": "Monitor modifications to .bash_profile, .bashrc, .zshrc, etc.",
    },
    "T1053.005_persist": {
        "name": "Scheduled Task (Persistence)",
        "tactic": "Persistence",
        "description": "Adversaries may create scheduled tasks for persistence.",
        "mitigations": "Audit scheduled task creation; restrict schtasks.exe.",
    },
    # --- Privilege Escalation ---
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevated privileges.",
        "mitigations": "Enforce UAC; audit sudo configuration; monitor for SUID/SGID abuse.",
    },
    "T1548.001": {
        "name": "Setuid and Setgid",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may abuse setuid/setgid bits on Linux/macOS to gain elevated privileges.",
        "mitigations": "Audit SUID/SGID binaries; remove unnecessary setuid bits.",
    },
    "T1548.002": {
        "name": "Bypass User Account Control",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may bypass UAC mechanisms on Windows to elevate process privileges.",
        "mitigations": "Set UAC to 'Always Notify'; monitor known UAC bypass techniques.",
    },
    "T1548.003": {
        "name": "Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit sudo and its caching mechanism to escalate privileges.",
        "mitigations": "Restrict sudo access; require password for all sudo commands; reduce timestamp_timeout.",
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities to elevate privileges.",
        "mitigations": "Keep systems patched; use exploit mitigation (ASLR, DEP).",
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may inject code into processes to evade defenses and elevate privileges.",
        "mitigations": "Monitor for process injection indicators; use endpoint protection.",
    },
    # --- Defense Evasion ---
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or modify artifacts to remove evidence of their presence.",
        "mitigations": "Centralize log collection; protect log integrity.",
    },
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "description": "Adversaries may clear Windows Event Logs to hide activity.",
        "mitigations": "Forward logs to SIEM; alert on log clearing events.",
    },
    "T1070.002": {
        "name": "Clear Linux or Mac System Logs",
        "tactic": "Defense Evasion",
        "description": "Adversaries may clear system logs on Linux/macOS to conceal activity.",
        "mitigations": "Centralize syslog; monitor for log truncation.",
    },
    "T1070.003": {
        "name": "Clear Command History",
        "tactic": "Defense Evasion",
        "description": "Adversaries may clear command history (bash_history, etc.) to cover tracks.",
        "mitigations": "Forward command history to SIEM; set HISTFILE to read-only.",
    },
    "T1070.004": {
        "name": "File Deletion",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete files to remove indicators of compromise.",
        "mitigations": "Monitor file deletion events; use file integrity monitoring.",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obfuscate payloads and data to evade detection.",
        "mitigations": "Use behavioral detection; analyze decoded/deobfuscated content.",
    },
    "T1036": {
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "description": "Adversaries may manipulate features of artifacts to make them appear legitimate.",
        "mitigations": "Verify digital signatures; monitor for process name/path mismatches.",
    },
    "T1036.005": {
        "name": "Match Legitimate Name or Location",
        "tactic": "Defense Evasion",
        "description": "Adversaries may match or approximate names/locations of legitimate files to evade detection.",
        "mitigations": "Monitor for executables in non-standard paths matching system binary names.",
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "description": "Adversaries may bypass process-based defenses using trusted system binaries to proxy execution of malicious content.",
        "mitigations": "Monitor LOLBin usage; restrict execution of proxied content.",
    },
    "T1218.011": {
        "name": "Rundll32",
        "tactic": "Defense Evasion",
        "description": "Adversaries may abuse rundll32.exe to proxy execution of malicious code.",
        "mitigations": "Monitor rundll32.exe arguments; block suspicious DLL loading.",
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversaries may maliciously modify security tools to avoid detection.",
        "mitigations": "Protect security tool configurations; monitor for tampering.",
    },
    "T1562.001": {
        "name": "Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": "Adversaries may disable security tools to avoid detection.",
        "mitigations": "Use tamper protection; alert on security service stop/modification.",
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may deobfuscate/decode data to reveal payloads.",
        "mitigations": "Monitor for certutil -decode, base64, or similar decoding commands.",
    },
    # --- Credential Access ---
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may dump credentials from the OS to obtain account login information.",
        "mitigations": "Enable Credential Guard; restrict access to LSASS; monitor for dumping tools.",
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversaries may access LSASS process memory to extract credentials.",
        "mitigations": "Enable Credential Guard; restrict access to LSASS process.",
    },
    "T1003.008": {
        "name": "/etc/passwd and /etc/shadow",
        "tactic": "Credential Access",
        "description": "Adversaries may read /etc/passwd and /etc/shadow to obtain user credentials.",
        "mitigations": "Restrict file permissions on /etc/shadow; monitor read access.",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to brute force credentials using password guessing or cracking.",
        "mitigations": "Enforce account lockout policies; use MFA; monitor for failed logon attempts.",
    },
    "T1110.001": {
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries may guess passwords to attempt access to accounts.",
        "mitigations": "Account lockout policies; MFA; monitor repeated failed logins.",
    },
    "T1555": {
        "name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "description": "Adversaries may search for credentials in password stores like browsers or keychains.",
        "mitigations": "Monitor access to password store files; use unique master passwords.",
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may search for insecurely stored credentials in files, registries, or environment variables.",
        "mitigations": "Avoid plaintext credential storage; scan for exposed secrets.",
    },
    "T1556": {
        "name": "Modify Authentication Process",
        "tactic": "Credential Access",
        "description": "Adversaries may modify authentication mechanisms to access user credentials or bypass authentication.",
        "mitigations": "Monitor auth module configuration; use file integrity monitoring on PAM.",
    },
    # --- Discovery ---
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to enumerate local or domain accounts.",
        "mitigations": "Monitor for account enumeration commands (net user, whoami, id).",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate files and directories to find information of interest.",
        "mitigations": "Monitor for broad file enumeration commands; restrict directory listing.",
    },
    "T1057": {
        "name": "Process Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate running processes to gain situational awareness.",
        "mitigations": "Monitor for ps, tasklist, or similar process enumeration.",
    },
    "T1049": {
        "name": "System Network Connections Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate current network connections (netstat, ss, lsof).",
        "mitigations": "Monitor for network enumeration commands.",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate system information such as OS version, hostname, and hardware.",
        "mitigations": "Monitor for sysinfo enumeration commands (uname, systeminfo, hostnamectl).",
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may look for network configuration details (ifconfig, ipconfig, route).",
        "mitigations": "Monitor for network config enumeration commands.",
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may scan for remote systems on the network.",
        "mitigations": "Monitor for ping sweeps, nmap, arp commands.",
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may identify the primary user or currently logged-in user.",
        "mitigations": "Monitor for whoami, id, w, who commands.",
    },
    # --- Lateral Movement ---
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use remote services (SSH, RDP, SMB, WinRM) to move laterally.",
        "mitigations": "Restrict remote service access; require MFA; monitor remote logons.",
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use RDP to move laterally between systems.",
        "mitigations": "Restrict RDP access; require NLA; monitor for unusual RDP sessions.",
    },
    "T1021.004": {
        "name": "SSH",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use SSH to move laterally within an environment.",
        "mitigations": "Restrict SSH access; enforce key-based authentication; monitor auth logs.",
    },
    "T1021.006": {
        "name": "Windows Remote Management",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use WinRM for lateral movement and remote command execution.",
        "mitigations": "Restrict WinRM access; monitor for unusual WinRM sessions.",
    },
    "T1570": {
        "name": "Lateral Tool Transfer",
        "tactic": "Lateral Movement",
        "description": "Adversaries may transfer tools or files between systems within a network.",
        "mitigations": "Monitor for file transfers via SMB, SCP, or similar protocols.",
    },
    # --- Collection ---
    "T1560": {
        "name": "Archive Collected Data",
        "tactic": "Collection",
        "description": "Adversaries may compress or encrypt collected data before exfiltration.",
        "mitigations": "Monitor for archiving commands (tar, zip, 7z, rar) on sensitive data.",
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Adversaries may search and collect data from the local file system.",
        "mitigations": "Monitor for broad file access patterns; use DLP tools.",
    },
    "T1074": {
        "name": "Data Staged",
        "tactic": "Collection",
        "description": "Adversaries may stage collected data in a central location before exfiltration.",
        "mitigations": "Monitor for data accumulation in temp directories.",
    },
    "T1115": {
        "name": "Clipboard Data",
        "tactic": "Collection",
        "description": "Adversaries may collect data from the clipboard.",
        "mitigations": "Monitor for clipboard access APIs; restrict clipboard sharing in RDP.",
    },
    "T1119": {
        "name": "Automated Collection",
        "tactic": "Collection",
        "description": "Adversaries may use automated techniques to collect data.",
        "mitigations": "Monitor for scripts performing bulk file operations.",
    },
    # --- Exfiltration ---
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data over the existing command and control channel.",
        "mitigations": "Monitor outbound traffic volume; use DLP; inspect C2 traffic.",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data using a different protocol than the C2 channel.",
        "mitigations": "Monitor for unusual protocol usage (DNS, ICMP for data transfer).",
    },
    "T1048.001": {
        "name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data over encrypted channels separate from C2.",
        "mitigations": "Monitor for unexpected encrypted outbound connections.",
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "description": "Adversaries may use legitimate web services (cloud storage, paste sites) to exfiltrate data.",
        "mitigations": "Monitor uploads to cloud storage services; block unauthorized services.",
    },
    "T1020": {
        "name": "Automated Exfiltration",
        "tactic": "Exfiltration",
        "description": "Adversaries may use automated data exfiltration after collection.",
        "mitigations": "Monitor for scheduled/recurring large outbound transfers.",
    },
    # --- Command and Control ---
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using OSI application layer protocols to avoid detection.",
        "mitigations": "Inspect HTTP/HTTPS/DNS traffic; use deep packet inspection.",
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate over HTTP/HTTPS for C2.",
        "mitigations": "Inspect HTTPS traffic; monitor for beaconing patterns.",
    },
    "T1071.004": {
        "name": "DNS",
        "tactic": "Command and Control",
        "description": "Adversaries may use DNS for C2 communications (DNS tunneling).",
        "mitigations": "Monitor for high-volume/unusual DNS queries; block DNS over HTTPS to unauthorized resolvers.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools from an external system into the compromised environment.",
        "mitigations": "Monitor for curl, wget, certutil, bitsadmin downloads; restrict outbound connections.",
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using non-application layer protocols (ICMP, raw sockets).",
        "mitigations": "Monitor for unusual ICMP or raw socket traffic.",
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactic": "Command and Control",
        "description": "Adversaries may tunnel network communications through another protocol to avoid detection.",
        "mitigations": "Monitor for SSH tunneling, DNS tunneling, ICMP tunneling.",
    },
    "T1090": {
        "name": "Proxy",
        "tactic": "Command and Control",
        "description": "Adversaries may use a proxy to direct C2 traffic through an intermediary.",
        "mitigations": "Monitor for proxy tool usage; restrict outbound proxy access.",
    },
    "T1573": {
        "name": "Encrypted Channel",
        "tactic": "Command and Control",
        "description": "Adversaries may employ encryption to conceal C2 traffic.",
        "mitigations": "Use TLS inspection where appropriate; monitor for self-signed certificates.",
    },
    "T1102": {
        "name": "Web Service",
        "tactic": "Command and Control",
        "description": "Adversaries may use legitimate web services (GitHub, Pastebin, cloud APIs) for C2.",
        "mitigations": "Monitor for unusual API calls to web services; restrict access to paste sites.",
    },
    "T1571": {
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "description": "Adversaries may use non-standard ports for C2 to bypass filtering.",
        "mitigations": "Monitor for common protocols on unusual ports (HTTP on 8443, SSH on 2222).",
    },
}


def lookup(query: str) -> list[dict[str, str]]:
    """Look up MITRE ATT&CK techniques by ID or keyword.

    Returns up to 5 matching techniques with id, name, tactic, description,
    and mitigations.

    Args:
        query: A technique ID (e.g., 'T1059.004') or keyword (e.g., 'powershell').
    """
    query_lower = query.strip().lower()
    query_upper = query.strip().upper()

    # Exact ID match first
    if query_upper in TECHNIQUES:
        t = TECHNIQUES[query_upper]
        return [{"id": query_upper, **t}]

    # Keyword search across name + description
    results = []
    for tid, t in TECHNIQUES.items():
        text = f"{t['name']} {t['description']} {t['tactic']}".lower()
        if query_lower in text:
            results.append({"id": tid, **t})
            if len(results) >= 5:
                break

    return results

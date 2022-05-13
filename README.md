## Windows Active Directory penetration testing
Technical notes and list of tools, scripts and Windows commands that I find useful during internal penetration tests (Windows environment/Active Directory).  
The output files included here are the results of tools, scripts and Windows commands that I ran against a vulnerable Windows AD lab that I created to test attacks/exploits and deliver hands-on penetration testing training sessions to security auditors at my job.


### <i>**** Classic Windows Active Directory attack paths - Internal penetration test **** </i>

#### Step 1. Bypassing Network Access Control (NAC) - if any
```
➤ Bypass MAC address filtering solution by using/spoofing the MAC address of a whitelisted device (e.g. a printer, smart TV in meeting room)
➤ Hack the captive portal authentication used to control network access
➤ ...
```

#### Step 2. Reconnaissance
<i>The purpose of the reconnaissance phase is to gather as much as possible information about the target (Windows domains and internal network). It includes Windows domain(s) enumeration, DNS enumeration, targeted network scans...</i>
```
Black-box penetration test (we start with no account)
-----------------------------------------------------
➤ On our laptop connected to the LAN or Wifi, we run commands like 'ipconfig /all', 'ip a' and 'nslookup' to identify:
   - the IP address range of the user network (our laptop IP address is part of it)
   - the IP address range of a production (server) network/VLAN (thanks to the IP address of the DNS server which is usually also the IP address of a Domain Controller)
➤ Network sniffing
➤ Reconnaissance using DNS queries (e.g. reverse IP lookup, DNS zone transfer) and the naming convention of the hostnames
   Examples:
   - Domain Controllers have often a hostname like 'pr<bla>dc1', 'dv<bla>ad2', 'usdc02', 'prodfrdc3', etc.
   - Web servers have often a hostname like 'prweb01', 'wwwserver02', 'win2k16iis03', 'devJBOSS04', etc.
   - Database servers have often a hostname like 'sqlsrv01', 'prdbserver02', 'prodorasrv08', 'devmongodb14', etc. 
   - Citrix servers have often a hostname like 'prctxsrv1', 'printctx02', 'citrixsrv02', etc.
➤ Targeted network scans (e.g. Nmap and NSE scripts)

Grey-box penetration test (we start with 1 low-privileged Windows account)
--------------------------------------------------------------------------
➤ AD and Windows domain information gathering (enumerate accounts, groups, computers, ACLs, password policies, GPOs, Kerberos delegation, ...)
➤ Numerous tools and scripts can be used to enumerate a Windows domain
   Examples:
   - Windows native DOS and Powershell commands (e.g. 'net' commands, PowerShell ActiveDirectory module)
   - Sysinternals tools (e.g. ADexplorer.exe)
   - PowerView framework / SharpView
   - Powershell scripts like ADrecon.ps1
   - BloodHound 
   - PingCastle
   - ADCollector
```

#### Step 3. Gaining Access
<i>The purpose of this phase is to gain (unauthorized) access to several internal systems (e.g. servers, file shares, databases) by exploiting common security issues such as: default/weak passwords, OS security misconfiguration, insecure network protocols and unpatched known vulnerabilities.</i>
```
Black-box penetration test (we start with no account)
-----------------------------------------------------
➤ LLMNR & NBT-NS poisonning attacks (tool: Responder) to collect NTLMv2 password hashes from the network + Offline password cracking (tools: John, hashcat)
➤ DNS poisoning attacks via IPv6 DHCP requests (tool: MITM6) to collect NTLMv2 password hashes from the network + Offline password cracking (tools: John, hashcat)
➤ NTLM relay attacks (tool: Ntlmrelayx) by exploiting vulnerabilities like PetitPotam and PrinterBug or poisonning attacks (LLMNR / NBT-NS / DNS & IPV6)
➤ Default/weak admin credentials for a software installed on a Windows server that will lead to a RCE
   Examples:
   - Web servers (e.g. Tomcat, WebLogic, JBoss) => Webshell upload
   - Jenkins, JIRA => OS command execution
   - CMS (e.g. WordPress) => Webshell upload
   - Databases (e.g. MSSQL, Oracle, PostgreSQL, Sybase) => OS command execution
   - SAP => OS command execution
➤ Windows password spray attacks
➤ Anonymous access to data storage spaces (e.g. FTP/TFTP/NFS) + Windows clear-text credentials hardcoded in scripts, logs and configuration files 
➤ Upload of malicious SCF files to anonymously writable Windows network shares + collect NTLMv2 password hashes + Offline password cracking (tools: John, hashcat)
➤ Unpatched/obsolete systems prone to an unauthenticated Remote Code Execution (RCE) vulnerability with a public exploit available
   Examples:
   - Windows: MS17-010 (EternalBlue), CVE-2020-1472 (Zerologon, risky to run in a production environment), old MS08-067, ...
   - Web servers: WebLogic RCE (CVE-2020-14882, CVE-2017-10271), Apache Struts RCE (CVE-2017-9805), JBoss RCE (CVE-2017-12149), Java RMI RCE, ...
   - CMS: Telerik (CVE 2019-18935, CVE-2017-9248), Kentico (CVE-2019-10068), Drupal (DrupalGeddon2/CVE-2018-7600), DotNetNuke (CVE-2017-9822), ...
   - Citrix NetScaler: CVE-2020-8193, CVE-2019-19781
   - Applications using the Java library Log4j: CVE-2021-44228 (Log4shell)
   - Outlook: ProxyLogon (CVE-2021-26855)
  
Grey-box penetration test (we start with 1 low-privileged Windows account)
--------------------------------------------------------------------------
➤ All the attacks listed above in the 'black-box pentest' section
➤ Kerberoasting attack (request Kerberos TGS for services with an SPN and retrieve crackable hashes) + Offline password cracking (tools: John, hashcat)
➤ AS-REP Roasting attack (retrieve crackable hashes/encrypted TGT for users without kerberoast pre-authentication enabled) + Offline password cracking (tools: John, hashcat)
➤ Find clear-text passwords in files shared on Domain Shares, NAS, SharePoint sites, internal github accessible to all Domain users
➤ Find a Windows server that is insecurely sharing configuration files, cron job scripts and executable files with write permissions granted to all Domain users 
   + Privesc by adding a backdoor in a cron job script or modifying a configuration file, ...
➤ Upload of malicious SCF files to Windows network shares (writable by any authenticated users) + collect NTLMv2 password hashes + Offline password cracking (tools: John, hashcat)
➤ Clear-text passwords stored in AD fields (e.g. account description, comments)
➤ Citrix servers accessible to all Domain users + Citrix jailbreak to get a Windows CMD or PowerShell console + Local privesc 
➤ WsuXploit attack – Compromising Windows machines via malicious Windows Update (i.e. tru to inject 'fake' updates into non-SSL WSUS traffic)
➤ Unpatched/obsolete systems prone to an authenticated Remote Code Execution vulnerability with a public exploit available 
   Examples:
   - Windows: SamAccountName impersonation vulnerability (CVE-2021-42278/CVE-2021-42287), PrintNightmare (CVE-2021-1675 & CVE-2021-34527), 
              KrbRelayUp local privesc technique, ADCS + PetitPotam + NLTM Relay technique (CVE-2021-44228), MS14-068, ...
   - Outlook: CVE-2020-0688
➤ ...
```

#### Step 4. Post-exploitation and local privilege escalation
<i>The purpose of the post-exploitation phase is to determine the value of the systems compromised during the previous phase (e.g. sensitivity of the data stored on it, usefulness in further compromising the network) and to escalate privileges to harvest credentials (e.g. to steal the password of a privileged account from the memory of a Windows server/laptop).</i>

```
Windows local privilege escalation to become local administrator and/or "NT AUTHORITY\SYSTEM"
---------------------------------------------------------------------------------------------
 ➤ Exploiting OS security misconfiguration 
   Examples:
   - weak service permissions
   - weak file permissions
   - weak registry permissions
   - dll hijacking
   - weak passwords and password re-use
   - clear-text passwords stored in scripts, unattended install files, configuration files (e.g. Web.config), ...
   - AlwaysInstallElevated trick
  
 ➤ Exploiting an unpatched local privesc vulnerability with a public exploit 
   (e.g. PrintNightmare, SeriousSam/HiveNightmare, Windows Installer LPE, Juicy/Rotten/Hot Potato exploits, MS16-032, ...)
 
 ➤ Bypassing Antivirus and Endpoint Detection and Response (EDR) software 
   Examples:
   - AMSI bypass techniques + Obfuscated offensive PowerShell scripts
   - Write your own 'shellcode loader into memory' tool or obfuscate and recompile a good one that is open source
   - Temporarily disable or uninstall the AV or EDR (once you are local admin or NT System)
   - Temporarily add rules in the local Windows firewall (once you are local admin or NT System) that will prevent the AV software and/or EDR agents to send alerts to the AV and/or EDR central console
   - Use as much as possible the same tools that the IT admins are using to 'blend in'. 
   - ...

 Dumping Windows credentials from memory and registry hives 
 ----------------------------------------------------------
 ➤ Dumping the registry hives (SAM, SYSTEM, SECURITY)
   Examples:
   - Reg save
   - Volume Shadow Copy (VSSadmin)
   - SecretsDump (Impacket)
 ➤ Memory dumping of the LSASS process 
   Examples:
   - ProcDump (Windows Sysinternals)
   - Task manager + "Create dump file" of lsass.exe
   - SecretsDump (Impacket)
   - Mimikatz / Invoke-mimikatz.ps1
   - ...

 Dumping credentials
 --------------------
   - The LaZagne application can be used to retrieve passwords stored in browsers, DBA tools (e.g. dbvis, SQLdevelopper) and Sysadmin tools (e.g. WinSCP, PuttyCM, OpenSSH, VNC, OpenVPN)
   - The script SessionGopher.ps1 can be used to find and decrypt saved session information for remote access tools (PuTTY, WinSCP, FileZilla, SuperPuTTY, RDP)
   - Dumping KeePass master password from memory using tools like 'Keethief' or 'KeePassHax'
   - Clear-text passwords hardcoded in scripts, configuration files (e.g. Web.config, tomcat-users.xml), backup files, log files, ...
```

#### Step 5. Network lateral movement and 'Domain Admin' credentials hunting
<i>The purpose of the lateral movement phase is to identify sensitive Windows servers and laptops on which the credentials of high privileged accounts (e.g. Domain admins) are stored in memory and then try to get access to them (for example by re-using the credentials harvested during the previous phase). </i>
```
➤ Network lateral movement using RDP, PowerShell remoting, WMIexec, SMBexec, PsExec, ...
➤ Pass-The-Hash, Pass-The-Ticket and Over-Pass-The-Hash techniques 
➤ Pivoting techniques
   Examples:
   - Meterpreter with 'post/multi/manage/autoroute' + socks proxy + use of proxychains
   - SSH tunnelling (dynamic port forwarding + use of proxychains, local port forwarding, remote port forwarding)
➤ 'Domain Admin' credentials hunting
   Examples:
   - BloodHound
   - PowerView and various PowerShell scripts
   - Windows native commands such as 'qwinsta /server:hostname' and 'net session'
   - Windows Sysinternals command-line tool 'PsLoggedOn' (e.g. psloggedon.exe \\computername username)
```
#### Step 6. Windows domain compromise (privilege escalation to become "Domain Admin")
<i>The purpose of this phase is to take full control over the target Windows domain.</i>

```
➤ Dumping from a Windows server's memory the clear-text password (or hash) of an acccount member of the group 'Domain Admins' or 'Administrators' of the Domain Controller
➤ Exploiting AD / Windows domain security misconfiguration
   Examples:
   - abusing weak ACL or GPO permissions, 
   - abusing LAPS misconfiguration, 
   - identifying password reuse 
     > the same password is used to protect multiple high privileged accounts and low-privileged accounts, 
     > the same password is used to protect the default local administrator account of the Windows servers and the Domain Controllers (i.e. no hardening, no LAPS)
➤ Compromise an account member of the default security group 'DNSAdmins' and take over the Windows domain by executing a DLL as 'NT AUTHORITY\SYSTEM' on the Domain Controller (known privesc)
➤ Compromise an account member of the default security groups 'Backup Operators' or 'Server Operators' and take over the Windows domain by backuping the NTDS.dit file and HKLM\SYSTEM and then extracting the password hash of 'Domain admins' accounts (known privesc)
➤ Compromise an account member of the default security group 'Account Operators' that can be used to privesc and take over the Windows domain (known privesc)
➤ Find a backup/snapshot of a Windows Domain Controller on a NAS/FTP/Share and extract the password hashes (NTDS.DIT + SYSTEM) of high privileged acccounts (e.g. Domain Admins, Enterprise Admins, krbtgt account)
➤ Abusing Microsoft Exchange for privilege escalation ('PrivExchange' vulnerability)
➤ Hack the Hypervisor (e.g. vCenter) on which the Domain Controllers are running, then perform a snapshot of the DCs, copy/download their memory dump files (.vmsn & .vmem) and finally extract the password hashes of high privileged acccounts (e.g. Domain Admins, Administrators of DC, krbtgt account)
➤ Kerberos Unconstrained Delegation attack (+ Printer Bug or PetitPotam)
➤ Kerberos Constrained Delegation attack
➤ Kerberos Resource-based Constrained Delegation attack
➤ ...
```

#### Step 7. Forest root domain compromise (privilege escalation to become "Enterprise Admin")
<i>The purpose of this phase is to take full control over the Forest root domain and all the other domains in the target network.</i>
```
➤ Post-exploitation AD
  - Dump, extract and crack the password hashes of all the Windows domain accounts (file 'NTDS.DIT' + SYSTEM registry hive)
➤ Persistence techniques
   Examples:
   - Use of the KRBTGT account’s password hash to create of a Kerberos Golden ticket
   - Add temporarily an account in a default AD security group such as 'Domain Admins', 'BUILTIN\Administrators' or 'Account Operators' 
   - Keep temporarily the password hash of a highly-privileged service account (e.g. Domain Admin) with a password that never expire
   - Modify temporarily ACLs
➤ Take over the Forest root domain
   - Forge a Kerberos Golden Ticket (TGT) with a 'SID History' for the Forest 'Enterprise Admins' group
   - Forge an inter-realm trust ticket (cross-domain trust kerberos ticket) and then create TGS for the services LDAP/CIFS/HOST/... in the parent domain 
➤ Take over other Windows domains due to password re-use across domains for high privileged accounts
➤ Take over other Windows domains thanks to AD Forest Trusts and/or misconfiguration (e.g. the group 'Domain Admins' of the domain A is member of the group 'Domain Admins' of the domain B) 
➤ ...
```

#### Useful tools and scripts
```
➤ Windows Sysinternals (https://docs.microsoft.com/en-us/sysinternals/)
➤ Windows native DOS commands and PowerShell commands (including AD module)
➤ ADRecon - Active Directory gathering information tool (https://github.com/adrecon/ADRecon)
➤ ADCollector - Tool to quickly extract valuable information from the AD environment for both attacking and defending (https://github.com/dev-2null/ADCollector)
➤ PingCastle - Active Directory security audit tool (https://www.pingcastle.com)
➤ BloodHound - Tool to easily identify complex Windows domain attack paths (https://github.com/BloodHoundAD/BloodHound)
➤ Rubeus - Toolset for raw Kerberos interaction and abuses (https://github.com/GhostPack/Rubeus)
➤ Mimikatz - Extract plaintexts passwords, hash, PIN code and kerberos tickets from memory (https://github.com/gentilkiwi/mimikatz)
➤ Powercat - PowerShell TCP/IP swiss army knife like netcat (https://github.com/besimorhino/powercat)
➤ Responder - LLMNR/NBTNS/mDNS poisoner and NTLMv1/2 relay (https://github.com/lgandx/Responder)
➤ PowerSploit (incl. PowerView & PowerUp) - PowerShell offensive security framework (https://github.com/PowerShellMafia/PowerSploit)
➤ Impacket (incl. Secretsdump, SMBrelayx & WMIexec) - Python offensive security framework (https://github.com/SecureAuthCorp/impacket)
➤ CrackMapExec - Swiss army knife for pentesting Windows networks (https://github.com/byt3bl33d3r/CrackMapExec)
➤ PowerSharpPack - Many usefull offensive CSharp Projects wraped into Powershell for easy usage (https://github.com/S3cur3Th1sSh1t/PowerSharpPack)
➤ ACLight - A tool for advanced discovery of privileged accounts including Shadow Admins (https://github.com/cyberark/ACLight)
➤ ADACLScanner - A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory (https://github.com/canix1/ADACLScanner).
➤ Liza - Active Directory Security, Permission and ACL Analysis (http://www.ldapexplorer.com/en/liza.htm)
➤ LAPSToolkit - LAPS auditing for pentesters (https://github.com/leoloobeek/LAPSToolkit)
➤ PrivescCheck.ps1 - This script aims to enumerate common Windows configuration issues that can be leveraged for local privilege escalation (https://github.com/itm4n/PrivescCheck)
➤ Juicy potato exploit (https://github.com/ohpe/juicy-potato)
➤ Rotten potato exploit (https://github.com/breenmachine/RottenPotatoNG)
➤ Hydra - Online password bruteforce tool (https://github.com/vanhauser-thc/thc-hydra)
➤ John the Ripper - Offline password cracker (https://www.openwall.com/john/)
➤ Hashcat - Offline password cracker (https://hashcat.net/hashcat/)
➤ Enum4linux - Tool for enumerating information from Windows and Samba systems (https://tools.kali.org/information-gathering/enum4linux)
➤ Metasploit penetration testing framework (https://www.metasploit.com)
➤ Vulnerability scanners (e.g. OpenVAS, Nessus, Qualys, Nexpose, ...)
➤ NMAP - Network port scanner and (NSE) scripts (https://nmap.org)
➤ Various scripts (source:kali/Github/your owns)
```

#### Useful resources
```
➤ ADsecurity website (https://adsecurity.org)
➤ MITRE (https://attack.mitre.org/tactics/enterprise/; https://attack.mitre.org/mitigations/M1015/)
➤ GitHub - swisskyrepo/PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
➤ GitHub - https://github.com/infosecn1nja/AD-Attack-Defense
➤ Att&cking Active Directory for fun and profit (https://identityaccessdotmanagement.files.wordpress.com/2020/01/attcking-ad-for-fun-and-profit.pdf)
➤ Windows / Linux Local Privilege Escalation Workshop (https://github.com/sagishahar/lpeworkshop)
➤ CIS benchmarks (https://www.cisecurity.org/benchmark/microsoft_windows_server/)
➤ ...
```

## Windows Active Directory penetration testing
Technical notes, AD pentest methodology, list of tools, scripts and Windows commands that I find useful during internal penetration tests (Windows environment). 
The output files included here are the results of tools, scripts and Windows commands that I ran against a vulnerable Windows AD lab that I created to test attacks/exploits and deliver hands-on penetration testing training sessions to security auditors at my job.


### <i>**** Classic internal penetration test methodology - Windows Active Directory attack paths **** </i>

----------------
#### STEP 1. BYPASSING NETWORK ACCESS CONTROL (NAC) - if any 🔐🕸🧑🏼‍💻
<i>If a NAC solution is implemented, the purpose of this phase will be to bypass it to get access to the internal network and start the internal penetration test.</i>
```
1. Pre-connect scenario => NAC checks are made before granting any access to the internal network
-------------------------------------------------------------------------------------------------
➤ MAC address spoofing technique
  - Bypass MAC address filtering solution by spoofing the MAC address of a whitelisted device (e.g. printer, smart TV in meeting room, VOIP phone)
➤ Pre-authenticated device technique
  - Bypass wired network 802.1x protection (NAC) by placing a rogue device (with 2 network adapters) between a pre-authenticated device and the network switch. 
    Using scripts like 'fenrir-ocd' or 'nac_bypass-setup.sh', the traffic will then flow through the rogue device which will be able to log into the network and smuggle network packets.
➤ Captive portal bypass technique
  - Hack the captive authentication portal used to control network access
➤ VOIP hopping and VLAN hopping techniques
➤ ...
```
```
2. Post-connect scenario => Network access is temporarily granted while NAC checks are ran against your laptop
--------------------------------------------------------------------------------------------------------------
➤ MAC address randomization technique
  - Change your MAC address automatically (e.g. every minute) with a script to obtain a new IP address prior getting blocked
    and keep accessing the network resources.
➤ ...
```

-----------------
#### STEP 2. RECONNAISSANCE 🕵
<i>The purpose of the reconnaissance phase is to gather as much as possible information about the targets (Windows domains and internal network). It includes Windows domain(s) enumeration, DNS enumeration, targeted network scans...</i>
```
1. Black-box penetration test (we start with no account)
--------------------------------------------------------
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
```
```
2. Grey-box penetration test (we start with 1 low-privileged Windows account)
-----------------------------------------------------------------------------
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

-----------------
#### STEP 3. GAINING ACCESS 🔓🧑🏼‍💻
<i>The purpose of this phase is to gain (unauthorized) access to several internal systems (e.g. servers, file shares, databases) by exploiting common security issues such as: default/weak passwords, OS security misconfiguration, insecure network protocols and unpatched known vulnerabilities.</i>
```
1. Black-box penetration test (we start with no account)
--------------------------------------------------------
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
➤ Windows password spray attacks (goal: find accounts protected by an easy guessable password or even a blank password / be careful not to lock accounts)
➤ Anonymous access to data storage spaces (e.g. FTP/TFTP/NFS) + Windows clear-text credentials hardcoded in scripts, logs and configuration files 
➤ Upload of malicious SCF or URL files to anonymously writable Windows network shares + collect NTLMv2 password hashes + Offline password cracking (tools: John, hashcat)
➤ Unpatched/obsolete systems prone to an unauthenticated Remote Code Execution (RCE) vulnerability with a public exploit available
   Examples:
   - Windows: MS17-010 (EternalBlue), CVE-2020-1472 (Zerologon, risky to run in a production environment), old MS08-067, ...
   - Web servers: WebLogic RCE (CVE-2020-14882, CVE-2022-21371, CVE-2019-2725), Apache Struts RCE (CVE-2017-9805), JBoss RCE (CVE-2017-12149), Java RMI RCE, ...
   - CMS: Telerik (CVE 2019-18935, CVE-2017-9248), Kentico (CVE-2019-10068), Drupal (DrupalGeddon2/CVE-2018-7600), DotNetNuke (CVE-2017-9822), ...
   - Citrix NetScaler: CVE-2020-8193, CVE-2019-19781
   - Atlassian software: Jira (CVE-2019-11581), Confluence (CVE-2022-26134)
   - Applications using the Java library Log4j: CVE-2021-44228 (Log4shell)
   - Outlook: ProxyLogon (CVE-2021-26855), ProxyNotShell (CVE-2022-41040, CVE-2022-41082)
```
```
2. Grey-box penetration test (we start with 1 low-privileged Windows account)
-----------------------------------------------------------------------------
➤ All the attacks listed above in the 'black-box pentest' section
➤ Kerberoasting attack (request Kerberos TGS for services with an SPN and retrieve crackable hashes) + Offline password cracking (tools: John, hashcat)
➤ AS-REP Roasting attack (retrieve crackable hashes/encrypted TGT for users without kerberoast pre-authentication enabled) + Offline password cracking (tools: John, hashcat)
➤ Find clear-text passwords in files shared on Domain Shares, NAS, SharePoint sites, internal github accessible to all Domain users
➤ Find a Windows server that is insecurely sharing configuration files, cron job scripts and executable files with write permissions granted to all Domain users 
   + Privesc by adding a backdoor in a cron job script or modifying a configuration file, ...
➤ Upload of malicious SCF or URL files to Windows network shares (writable by any authenticated users) + collect NTLMv2 password hashes + Offline password cracking (tools: John, hashcat)
➤ Clear-text passwords stored in AD fields (e.g. account description, comments)
➤ Citrix servers accessible to all Domain users + Citrix jailbreak to get a Windows CMD or PowerShell console + Local privesc 
➤ WsuXploit attack – Compromising Windows machines via malicious Windows Update (i.e. tru to inject 'fake' updates into non-SSL WSUS traffic)
➤ Find and exploit ADCS misconfiguration (very often ADCS misconfiguration can lead to a Domain Admin account compromise)
➤ NLTM Relay techniques + ADCS attacks (i.e. ESC8 - NTLM Relay to AD CS HTTP Endpoints)
➤ Unpatched/obsolete systems prone to an authenticated Remote Code Execution vulnerability with a public exploit available 
   Examples:
   - Windows: 
     - Certifried vulnerability (CVE-2022-26923)
     - noPAC / SamAccountName impersonation vulnerability (CVE-2021-42278/CVE-2021-42287), 
     - PrintNightmare vulnerability (CVE-2021-1675 & CVE-2021-34527), 
     - Drop-the-MIC vulnerabilities (CVE-2019-1040 & CVE-2019-1166)
     - KrbRelayUp local privesc technique, 
     - ...
   - Outlook: CVE-2020-0688
➤ ...
```

---------------
#### STEP 4. POST-EXPLOITATION and LOCAL PRIVILEGE ESCALATION 🛠🧑🏼‍💻 
<i>The purpose of the post-exploitation phase is to determine the value of the systems compromised during the previous phase (e.g. sensitivity of the data stored on it, usefulness in further compromising the network) and to escalate privileges to harvest credentials (e.g. to steal the password of a privileged account from the memory of a Windows server/laptop). During this phase, the system(s) compromised can be set-up as a pivot to reach machines that are located in other networks. </i>

```
1. Windows local privilege escalation to become local administrator and/or "NT AUTHORITY\SYSTEM"
------------------------------------------------------------------------------------------------
➤ Exploiting OS security misconfiguration 
   Examples:
   - weak service permissions (file & binpath)
   - service unquoted path
   - autorun and weak file permissions
   - weak registry permissions
   - dll hijacking
   - weak passwords and password re-use
   - clear-text passwords stored in scripts, unattended install files, configuration files (e.g. Web.config), ...
   - AlwaysInstallElevated trick
   - bring your own vulnerable driver
  
➤ Exploiting an unpatched local Windows vulnerability 
  (e.g. KrbrelayUp, PrintNightmare, SeriousSam/HiveNightmare, Windows Installer LPE, Juicy/Rotten/Hot Potato exploits, MS16-032, ...)

➤ Exploiting an unpatched vulnerability affecting a third party software running with high privileges
```
```
2. Dumping Windows credentials from memory and registry hives (requires local admin priv)
-----------------------------------------------------------------------------------------
➤ Dumping the registry hives (SAM, SYSTEM, SECURITY)
   Examples:
   - Reg save
   - Esentutl.exe
   - Volume Shadow Copy (VSSadmin)
   - SecretsDump (Impacket)
   - SharpSecDump
   - OLD/Legacy - pwdumpX
   
➤ Memory dumping of the LSASS process 
   Examples:
   - Mimikatz / invoke-mimikatz.ps1
   - NanoDump
   - SharpKatz
   - SafetyDump
   - Lsassy
   - EDRSandblast
   - OLD/Legacy techniques
      - ProcDump (Sysinternals tool)
      - Task manager + "Create dump file" of lsass.exe
      - Process Explorer (Sysinternals tool) + "Create dump" of lsass.exe
      - Process Hacker + "Create dump file" of lsass.exe
      - Dumping lsass with rundll32 and comsvcs.dll
      - Dumpert
      - SQLDumper (included with Microsoft SQL) 
      - WCE (Windows Credentials Editor)
   - ...
```
```
3. Dumping other credentials
----------------------------
   - The LaZagne application can be used to retrieve passwords stored in browsers, DBA tools (e.g. dbvis, SQLdevelopper) and Sysadmin tools (e.g. WinSCP, PuttyCM, OpenSSH, VNC, OpenVPN)
   - The script SessionGopher.ps1 can be used to find and decrypt saved session information for remote access tools (PuTTY, WinSCP, FileZilla, SuperPuTTY, RDP)
   - Dumping KeePass master password from memory using tools like 'Keethief', 'KeePassHax' or 'KeePwn'
   - Clear-text passwords hardcoded in scripts, configuration files (e.g. Web.config, tomcat-users.xml), backup files, log files, ...
```
```
4. Bypassing Antivirus and EDR software (defense evasion)
---------------------------------------------------------
➤ Common AV bypass techniques
   - Fileless techniques + AMSI and ETW bypass techniques
   - Write your own hacking tools (e.g. obfuscated/encrypted shellcode loader into memory)
   - Regularly obfuscate and recompile your favorite (open source) hacking tools and scripts
   - Use 'PE' packers and 'shellcode' packers that implement obfuscation, encryption and sandbox evasion techniques
   - Run into memory encrypted/obfuscated C2 agents (e.g. Cobalt Strike, Sliver, Metasploit, Havoc)
   - Abuse potential AV exclusions set for files, folders, processes, and process-opened files.
   - Kill the anti-malware (AV) protected processes using "Bring Your Own Vulnerable Driver" (BYOVD) techniques
   - Temporarily disable or uninstall the AV (once you are local admin or Local System)
   - Use as much as possible legitimate software and IT admin tools not flagged as malware by AV solutions (e.g. pivoting with remote access tools like TeamViewer and AnyDesk)
   - ...
➤ Common EDR bypass techniques
   - AMSI and ETW bypass techniques, NTDLL unhooking technique, use of direct and indirect syscalls, suspended process method, ...
   - Abuse potential EDR exclusions set for files, folders, processes, and process-opened files.
   - Kill the anti-malware (EDR) protected processes using "Bring Your Own Vulnerable Driver" (BYOVD) techniques
   - Temporarily disable or uninstall the EDR agent (once you are local admin or Local System) if it is not protected by a password
   - Temporarily add rules in the local Windows firewall (once you are local admin or NT System) that will prevent the EDR agent to send alerts to the EDR central console
   - Use as much as possible the IT admin tools already installed on the target systems to 'blend in' among the legitimate system administrators
   - Find server(s) in the network that have not been yet onboarded in the EDR solution
   - ...
```
-----------------
#### STEP 5. NETWORK LATERAL MOVEMENT and 'DOMAIN ADMINs' CREDENTIALS HUNTING 🕸🧑🏼‍💻 
<i>The purpose of the lateral movement phase is to identify sensitive Windows servers and laptops on which the credentials of high privileged accounts (e.g. Domain admins) are stored in memory and then try to get access to them (for example by re-using the credentials harvested during the previous phase). </i>
```
1. Network lateral movement techniques 
--------------------------------------
➤ Network lateral movement using RDP, PowerShell remoting (WinRM), WMIC, WMIexec, SMBexec, PsExec, SSH, ...
➤ Pass-The-Hash, Pass-The-Ticket, Over-Pass-The-Hash and Pass-The-Certificate techniques 
```
```
2. Network pivoting techniques 
------------------------------
➤ Use a C2 post-exploitation agent (e.g. Meterpreter, Cobalt Strike, Sliver) + SOCKS proxy + proxychains
➤ SSH tunnelling using Putty.exe or Plink.exe (e.g. local/remote port forwarding)
➤ Remote access tools such as TeamViewer and AnyDesk portable software, Chrome Remote Desktop, VNC, ...
➤ Tunneling/pivoting tools like Rpivot, Ligolo, Socat, ...
➤ Pivoting with TCP tunnelling over HTTP via Webshells (e.g. Tunna webshell, fulcrom webshell, reGeorg and neo-reGeorg client/webshell)
```
```
3. 'Domain Admins' credentials hunting
--------------------------------------
➤ Windows native commands (e.g. 'qwinsta /server:hostname' OR 'query user /server:hostname')
➤ PowerView and various PowerShell scripts (e.g. Invoke-UserHunter, Get-NetLoggedon, ADrecon)
➤ Windows Sysinternals command-line tool 'PsLoggedOn' (i.e. psloggedon.exe \\computername username)
➤ BloodHound
```

-----------------
#### STEP 6. WINDOWS DOMAIN COMPROMISE (Privilege escalation to become "Domain Admin" + Persistence) 🔥🧑🏼‍💻 
<i>The purpose of this phase is to take full control over the target Windows domain.</i>

```
1. Privilege escalation to become "Domain Admin"
------------------------------------------------
➤ Dumping from a Windows server's memory the clear-text password (or hash) of an account member of the group 'Domain Admins' or 'Administrators' of the Domain Controller
➤ Exploiting AD / Windows domain security misconfiguration
   Examples:
   - abusing weak ACL or GPO permissions
   - abusing LAPS misconfiguration
   - exploiting password reuse issues
     > the same password is used to protect multiple high privileged accounts and low-privileged accounts 
     > the same password is used to protect the default local administrator account of the Windows servers and the Domain Controllers (i.e. no hardening, no LAPS)
➤ Exploiting Active Directory Certificate Services (ADCS) misconfiguration
   Examples:
   - abusing misconfigured Certificate Templates - ESC1 & ESC2
   - abusing misconfigured Enrolment Agent Templates - ESC3
   - abusing vulnerable Certificate Template Access Control - ESC4
   - abusing vulnerable PKI Object Access Control - ESC5
   - abusing "EDITF_ATTRIBUTESUBJECTALTNAME2" flag issue - ESC6
   - abusing vulnerable Certificate Authority Access Control - ESC7
   - abusing NTLM Relay to AD CS HTTP Endpoints – ESC8
   - abusing "no Security Extension" issue - ESC9
   - abusing weak Certificate Mappings - ESC10
   - abusing NTLM relay to ICPR - ESC11
➤ Compromise an account member of the default security group 'DNSAdmins' and take over the Windows domain by executing a DLL as 'NT AUTHORITY\SYSTEM' on the Domain Controller (known privesc)
➤ Compromise an account member of the default security groups 'Backup Operators' or 'Server Operators' and take over the Windows domain by backuping the NTDS.dit file and HKLM\SYSTEM and then extracting the password hash of 'Domain admins' accounts (known privesc)
➤ Compromise an account member of the default security group 'Account Operators' that can be used to privesc and take over the Windows domain (known privesc)
➤ Find a backup/snapshot of a Windows Domain Controller on a NAS/FTP/Share and extract the password hashes (NTDS.DIT + SYSTEM) of high privileged acccounts (e.g. Domain Admins, Enterprise Admins, krbtgt account)
➤ Abusing Microsoft Exchange for privilege escalation ('PrivExchange' vulnerability)
➤ Exploiting an unpatched vulnerability on a DC with a public exploit available (e.g. CVE-2020-1472  Zerologon, risky to run in a production environment)
➤ Hack the Hypervisor (e.g. vCenter) on which the Domain Controllers are running, then perform a snapshot of the DCs, copy/download their memory dump files (.vmsn & .vmem) and finally extract the password hashes of high privileged acccounts (e.g. Domain Admins, Administrators of DC, krbtgt account)
➤ Kerberos Unconstrained Delegation attack (+ Printer Bug or PetitPotam)
➤ Kerberos Constrained Delegation attack
➤ Kerberos Resource-based Constrained Delegation attack
➤ ...
```
```
2. AD password dumping & cracking (NTDS) 
----------------------------------------
➤ Dump and extract the password hashes of all the Windows domain accounts (file 'NTDS.DIT' + SYSTEM registry hive)
   Examples:
   - Ntdsutil + Secretsdump
   - Wbadmin + Secretsdump
   - Secretsdump
   - CrackMapExec
   - Mimikatz (dcsync technique)
   - ...
➤ Crack (with John or Hashcat) the password hashes of all the Windows domain accounts
```
```
3. Creating persistence (examples)
----------------------------------
➤ Use the KRBTGT account’s password hash to forge of a Kerberos Golden ticket with Domain Administrator privileges
➤ Add temporarily an account in a default AD security group such as 'Domain Admins', 'BUILTIN\Administrators' or 'Account Operators' 
➤ Keep temporarily the password hash of a highly-privileged service account (e.g. Domain Admin) with a password set to never expire
➤ Modify temporarily the ACLs to allow an account that you control to perform DCsync attack.
➤ ...
```
-----------------
#### STEP 7. FOREST ROOT DOMAIN COMPROMISE (Privilege escalation to become "Enterprise Admin") 🔥🔥🧑🏼‍💻 
<i>The purpose of this phase is to take full control over the Forest root domain and all the other domains in the target network.</i>
```
➤ Forge a Kerberos Golden Ticket (TGT) with a 'SID History' for the Forest 'Enterprise Admins' group
➤ Forge an inter-realm trust ticket (cross-domain trust kerberos ticket) and then create TGS for the services LDAP/CIFS/HOST/... in the parent domain 
➤ Take over other Windows domains due to password re-use across domains for high privileged accounts
➤ Take over other Windows domains thanks to AD Forest Trusts and/or misconfiguration (e.g. the group 'Domain Admins' of the domain A is member of the group 'Domain Admins' of the domain B) 
➤ ...
```
-----------------
#### LIST OF SOME USEFUL TOOLS & SCRIPTS

| TOPIC | TOOL | URL | DESCRIPTION | 
| :-----: | :-----: | :-----: | :------: |
| Recon, Audit, Post-Exploitation | Windows Sysinternals | </br>https://docs.microsoft.com/en-us/sysinternals/ | Adexplorer, procdump, procmon, autorun, ...  |
| Recon, Audit, Post-Exploitation | Windows native commands | - | Windows native DOS commands (e.g. net commands, nltest) and PowerShell commands (including AD module) |
| Recon, Audit | ADRecon | </br> https://github.com/adrecon/ADRecon | Active Directory gathering information tool |
| Recon, Audit | ADCollector | </br> https://github.com/dev-2null/ADCollector |  Tool to quickly extract valuable information from the AD environment for both attacking and defending | 
| Recon, Audit | NMAP | </br> https://nmap.org | Network port scanner and (NSE) scripts | 
| Recon, Audit| PingCastle | </br> https://www.pingcastle.com | Active Directory security audit tool  |  
| Recon, Audit | BloodHound | </br> https://github.com/BloodHoundAD/BloodHound | Tool to easily identify complex Windows domain attack paths |
| Recon, Audit | ACLight | </br> https://github.com/cyberark/ACLight | A tool for advanced discovery of privileged accounts including Shadow Admins|
| Recon, Audit | ADACLScanner | </br> https://github.com/canix1/ADACLScanner |A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory|
| Recon, Audit | Liza | </br> http://www.ldapexplorer.com/en/liza.htm | Active Directory Security, Permission and ACL Analysis |
| Recon, Audit | LAPSToolkit | </br> https://github.com/leoloobeek/LAPSToolkit | LAPS auditing for pentesters |
| Gaining Access | Rubeus | </br> https://github.com/GhostPack/Rubeus | Toolset for raw Kerberos interaction and abuses |
| Audit, Privesc | Certify | </br> https://github.com/GhostPack/Certify | C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS) |
| Gaining Access, MITM | Responder | </br> https://github.com/lgandx/Responder | LLMNR/NBTNS/mDNS poisoner and NTLMv1/2 relay |
| Gaining Access, MITM | Inveigh | </br> https://github.com/Kevin-Robertson/Inveigh | .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers |
| Gaining Access, MITM | Smbrelayx & Ntlmrelayx |  </br> https://github.com/fortra/impacket/tree/master/examples | SMB and NTLM relay tools which are part of the Python offensive security framework 'Impackets' |
| Recon, Gaining Access | Vulnerability scanners |  </br> (https://github.com/greenbone/openvas-scanner/releases) (https://www.tenable.com/) (https://www.qualys.com/) (https://www.rapid7.com/products/nexpose/) | e.g. OpenVAS, Nessus, Qualys, Nexpose, ... | 
| Gaining Access | Hydra | </br> https://github.com/vanhauser-thc/thc-hydra | Online password bruteforce tool | 
| Post-Exploitation, Privesc | Mimikatz | </br> https://github.com/gentilkiwi/mimikatz | Extract plaintexts passwords, hash, PIN code and kerberos tickets from memory|
| Post-Exploitation, Creds dumping | SharpKatz | </br> https://github.com/b4rtik/SharpKatz | Porting in C# of mimikatz sekurlsa::logonpasswords, sekurlsa::ekeys and lsadump::dcsync commands |
| Post-Exploitation, Creds dumping | Nanodump | </br> https://github.com/helpsystems/nanodump | The swiss army knife of LSASS dumping |
| Password cracking | Hashcat | </br> https://github.com/hashcat/hashcat/ | World's fastest and most advanced password recovery utility |
| Password cracking | John the Ripper | </br> https://www.openwall.com/john/ | Offline password cracker |
| Post-Exploitation, Privesc | PowerSploit (incl. PowerView & PowerUp) | </br> https://github.com/PowerShellMafia/PowerSploit | PowerShell offensive security framework |
| Recon, Audit, Post-Exploitation, Privesc | PowerSharpPack | </br> https://github.com/S3cur3Th1sSh1t/PowerSharpPack/ | Many usefull offensive CSharp Projects wraped into Powershell for easy usage |
| Post-Exploitation, Privesc | PrivescCheck  | </br> https://github.com/itm4n/PrivescCheck | This script aims to enumerate common Windows configuration issues that can be leveraged for local privilege escalation |
| Post-Exploitation, Privesc  | Seatbelt | </br> https://github.com/GhostPack/Seatbelt | C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive & defensive security perspectives |
| Post-Exploitation, Privesc | KrbRelayUp  | </br> https://github.com/Dec0ne/KrbRelayUp | KrbRelayUp - a universal no-fix local privilege escalation in windows domain environments where LDAP signing is not enforced (the default settings) |
| Privesc | Juicy potato exploit | </br> https://github.com/ohpe/juicy-potato | Local privesc tool |
| Privesc | Rotten potato exploit | </br> https://github.com/breenmachine/RottenPotatoNG | Local privesc tool |
| Post-Exploitation, Privesc | Nightly builds of common C# offensive tools | </br> https://github.com/Flangvik/SharpCollection | Nightly builds of common C# offensive tools, fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines |
| AD Privesc | BloodyAD | </br> https://github.com/CravateRouge/bloodyAD |BloodyAD is an Active Directory Privilege Escalation Framework |
| Post-Exploitation, Defense evasion | AMSI.fail | <br> https://amsi.fail | It generates obfuscated PowerShell snippets that break or disable AMSI for the current process  |
| Post-Exploitation, Defense evasion | Nimcrypt2 | </br> https://github.com/icyguider/Nimcrypt2 | .NET, PE and raw shellcode packer/loader designed to bypass AV/EDR |
| Post-Exploitation, Defense evasion | ProtectMyTooling | </br> https://github.com/mgeeky/ProtectMyTooling | Multi-Packer wrapper letting us daisy-chain various packers, obfuscators and other Red Team oriented weaponry.|
| Post-Exploitation, Defense evasion | FilelessRemotePE | </br> https://github.com/D1rkMtr/FilelessRemotePE | Loading Fileless Remote PE from URI to memory with argument passing and ETW patching and NTDLL unhooking and no new thread technique|
| Post-Exploitation, Defense evasion | Invoke-Obfuscation | </br> https://github.com/danielbohannon/Invoke-Obfuscation | PowerShell scripts obfuscator|
| Post-Exploitation, Defense evasion | Chameleon | </br> https://github.com/klezVirus/chameleon | PowerShell scripts obfuscator|
| Post-Exploitation C2, Network Lateral Movement, Pivoting | Cobalt Strike | </br> https://www.cobaltstrike.com | Cobalt Strike gives you a post-exploitation agent and covert channels to emulate a quiet long-term embedded actor in your customer's network |
| Post-Exploitation C2, Network Lateral Movement, Pivoting | Metasploit | </br> https://www.metasploit.com | Penetration testing framework and post-exploitation C2 | 
| Post-Exploitation C2, Network Lateral Movement, Pivoting | Sliver | </br> https://github.com/BishopFox/sliver| Open source cross-platform adversary emulation/red team framework |
| Post-Exploitation C2, Network Lateral Movement, Pivoting | Havoc | </br> https://github.com/HavocFramework/Havoc| Havoc is a modern and malleable post-exploitation command and control framework|
| Post-Exploitation C2, Network Lateral Movement, Pivoting | Covenant | </br> https://github.com/cobbr/Covenant| Covenant is a collaborative .NET C2 framework for red teamers|
| Network Lateral Movement, Pivoting | Impacket Framework | </br> https://github.com/SecureAuthCorp/impacket | Python offensive security framework (e.g. WMIexec.py, SMBexec.py, Secretsdump.py) |
| Network Lateral Movement, Pivoting | CrackMapExec | </br> https://github.com/byt3bl33d3r/CrackMapExec | Swiss army knife for pentesting Windows networks|
| Network Lateral Movement, Pivoting | SharpMapExec | </br> https://github.com/cube0x0/SharpMapExec | Swiss army knife for pentesting Windows networks |
| Network Lateral Movement, Pivoting | Powercat | </br> https://github.com/besimorhino/powercat | PowerShell TCP/IP swiss army knife like netcat | 
| Network Lateral Movement, Pivoting | Invoke-TheHash  | </br> https://github.com/Kevin-Robertson/Invoke-TheHash | It contains PowerShell functions for performing pass-the-hash WMI and SMB tasks |
| Network Lateral Movement, Pivoting | Rpivot  | </br> https://github.com/klsecservices/rpivot | Socks4 reverse proxy for penetration testing |
| Network Lateral Movement, Pivoting | Ligolo  | </br> https://github.com/sysdream/ligolo | Reverse Tunneling made easy for pentesters, by pentesters |
| NAC bypass | Fenrir  | </br> https://github.com/Orange-Cyberdefense/fenrir-ocd | Tool/script designed to bypass wired network 802.1x protection (NAC) |

----------------
#### USEFUL RESOURCES
```
➤ ADsecurity website (https://adsecurity.org)
➤ MITRE (https://attack.mitre.org/tactics/enterprise/; https://attack.mitre.org/mitigations/M1015/)
➤ GitHub - swisskyrepo/PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
➤ GitHub - https://github.com/infosecn1nja/AD-Attack-Defense
➤ Att&cking Active Directory for fun and profit (https://identityaccessdotmanagement.files.wordpress.com/2020/01/attcking-ad-for-fun-and-profit.pdf)
➤ Windows / Linux Local Privilege Escalation Workshop (https://github.com/sagishahar/lpeworkshop)
➤ CIS benchmarks (https://www.cisecurity.org/benchmark/microsoft_windows_server/)
➤ Evaluation matrix of Command and Control (C2) frameworks (https://www.thec2matrix.com/matrix)
➤ ...
```

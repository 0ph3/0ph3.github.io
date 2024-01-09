---
categories: [HTB, Medium]
---
# HTB CTF - Authority (Medium)

## Enumeration

### Port Scan

I like to start by gathering a list of open ports before running nmap enumeration scripts against all ports. 
This saves a bit of time on the scan and also reduces the amount of traffic sent over the network.
Starting off with a basic port scan reveals the following ports open on the machine.
```console
0ph3@parrot~$ nmap -p- --min-rate=5000 10.10.11.222
Nmap scan report for 10.10.11.222
Host is up (0.11s latency).
Not shown: 963 closed tcp ports (reset)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
8443/tcp  open  https-alt
9389/tcp  open  adws
47001/tcp open  winrm
<SNIP>                                                                                                                                                                 
```
At a glance we can already guess this is an Active Directory (AD) domain controller (DC) just from the open ports. 
Usually the combination of Kerberos (88/TCP), ldap (389,636/TCP), microsoft-ds (445) is a good giveaway the target is acting as DC.

Using the list of open ports, we can try enumerating each service running on them.

```console
0ph3@parrot~$ nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,8443,9389,47001 -sV -sC 10.10.11.222
Stats: 0:00:34 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Nmap scan report for 10.10.11.222
Host is up (0.095s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-09 23:16:35Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2024-01-09T23:17:24+00:00; +4h00m18s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2024-01-09T23:17:25+00:00; +4h00m18s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2024-01-09T23:17:25+00:00; +4h00m18s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2024-01-09T23:17:24+00:00; +4h00m17s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp  open  ssl/https-alt
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2024-01-07T22:24:31
|_Not valid after:  2026-01-09T10:02:55
| fingerprint-strings:
|   FourOhFourRequest, GetRequest:
|     HTTP/1.1 200
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Tue, 09 Jan 2024 23:16:41 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions:
|     HTTP/1.1 200
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Tue, 09 Jan 2024 23:16:41 GMT
|     Connection: close
|   RTSPRequest:
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Tue, 09 Jan 2024 23:16:47 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {fo
nt-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description<
/b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
9389/tcp  open  mc-nmf        .NET Message Framing
7001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.93%T=SSL%I=7%D=1/9%Time=659D9B87%P=x86_64-pc-linux-gnu
<SNIP>  
```
Immediately we can note that ldap ssl cert is leaking the AD domain name authority.htb
```console
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2024-01-09T23:17:24+00:00; +4h00m18s from scanner time.
```

The nmap output has a lot of information so we will try to look at each service individually. 
It's a good idea prioritize and plan out enumeration when a target has a long list of ports and services.
Spending a long time trying to brute force 

### DNS (53/TCP)
Let's try a DNS zone transfer using the domain name found in the ldap ssl certificate.
```console
0ph3@parrot~$ dig axfr authority.htb @10.10.11.222

; <<>> DiG 9.18.16-1~deb12u1~bpo11+1-Debian <<>> axfr authority.htb @10.10.11.222
;; global options: +cmd
; Transfer failed.
```
Doesn't seem zone transfers are allowed. Let's move on to enumerating the web services on the target.

### HTTP (80/TCP)
The web page on 80/TCP shows a standard IIS landing page. There does not seem to be much else here.
picture-IIS
Directory busting doesn't prove fruitful either. 
```
0ph3@parrot~$ feroxbuster -u http://10.10.11.222

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.222
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
[####################] - 30s    30000/30000   0s      found:0       errors:0      
[####################] - 30s    30000/30000   997/s   http://10.10.11.222
```
If we wanted to go down this IIS rabbit hole we could maybe try IIS tilde enumeration. For now let's move on to the other web service.

### HTTPS (8443/TCP)
Navigating to https://10.10.11.222/ redirects to a login page for a [PWM](https://github.com/pwm-project/pwm/) web application. 
Doing some research reveals PWM is a java based application that allows users to login and submit password resets through LDAP.
Trying some common default credentials on the login page does not have any sucess.
If we look below the login form, we can see a message stating the application is in configuration mode.
This misconfiguration allows access to the configuration manager and configuration editor with only a password.

GIF-PWA

Before we fall down a password bruteforcing rabbit hole early on, let's continue to enumerate and see if we can find anything useful on any SMB shares. 

### SMB (445/TCP)
```console
0ph3@parrot~$ cme smb 10.10.11.222 -u 0ph3 -p '' --shares
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\0ph3: 
SMB         10.10.11.222    445    AUTHORITY        [*] Enumerated shares
SMB         10.10.11.222    445    AUTHORITY        Share           Permissions     Remark
SMB         10.10.11.222    445    AUTHORITY        -----           -----------     ------
SMB         10.10.11.222    445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.10.11.222    445    AUTHORITY        C$                              Default share
SMB         10.10.11.222    445    AUTHORITY        Department Shares                 
SMB         10.10.11.222    445    AUTHORITY        Development     READ            
SMB         10.10.11.222    445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.10.11.222    445    AUTHORITY        NETLOGON                        Logon server share 
SMB         10.10.11.222    445    AUTHORITY      
```
Looks like we only have READ access to the ```Development``` share. Let's see what we can find!
We could use smbclient to manually navigate the share but mounting the share will making searching through directories and files easier.

```console
0ph3@parrot~$ mkdir /mnt/authority/
0ph3@parrot~$mount -t cifs //10.10.11.222/Development /mnt/authority/development/
Password for 0ph3@//10.10.11.222/Development:
```
With the share mounted, lets take a look at the contents
```console
0ph3@parrot~$ tree -L 3 /mnt/authority/development/
/mnt/authority/development/
└── Automation
    └── Ansible
        ├── ADCS
        ├── LDAP
        ├── PWM
        └── SHARE
```
The share appears to host folders for different services under the Automation\Ansible folder.
If you are unfamiliar with [Ansible](https://docs.ansible.com/ansible/latest/getting_started/introduction.html), know that it is essentially software used to automate complex tasks.
It is often used by development teams and IT professionals to automatically deploy, maintain, update and manage software/system components and configurations amongst other uses.
That being said, the PWM folder looks interesting. With some luck, there may be credentials to the PWM login page we found.

ansible_inventory file seems to contain winrm credentials.
```
0ph3@parrot~$ cat /mnt/authority/development/Automation/Ansible/PWM/ansible_inventory 
ansible_user: administrator
ansible_password: Welcome1
ansible_port: 5985
ansible_connection: winrm
ansible_winrm_transport: ntlm
ansible_winrm_server_cert_validation: ignore
```
Trying the credentials against the DC fails



##
## User foothold svc_ldap




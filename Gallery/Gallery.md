# Gallery

“Try to exploit our image gallery system”

A detailed walkthrough on the room [Gallery](https://tryhackme.com/room/gallery666) on [tryhackme](http://tryhackme.com).

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled.png)

Difficulty : Easy

## 1- Scanning And Enumeration

First of all let’s run a scan on the system, I will be using rustscan.

After running the scan I found 2 ports, 80 and 8080.

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%201.png)

So now I visited the port 80 HTTP page and found this.

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%202.png)

A default apache2 page, so now I decided to visit the port 8080 HTTP page and that port redirects us to port 80 on the directory named `/gallery`.

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%203.png)

This shows us a simple login page but we can do much as we don’t know the creds yet to lets enumerate further. 

## 2- Exploring The Webpage

Now I tried to find the password or any hint for a long time and then I tried a SQLI in the login page as suggested in the room’s *tools used section.*

Here’s the payload I used for both user and password section. `'or 1=1 -- -`

Now you should be logged in!

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%204.png)

## 3- Finding The Admin Hash

Now let’s try to find the hash of admin, when it comes to hashes it is *usually* obtained using SQLI in CTF so I tried the same but before we need to find a injection point. 

So I decided to visit the `Albums` page and clicked on the sample images tab.

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%205.png)

If you look at the link it has a parameter `id=` which could be vulnerable to let’s try it out. 

To use sqlmap effectively I decided to save the request using burpsuite.

You can save the file by right-clicking and then clicking on save item. Let’s run it up!

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%206.png)

After the scan finishes we are met with 2 databases. 

 

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%207.png)

Now let’s check the tables of the database `gallery_db`

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%208.png)

After the scan I found these tables present. 

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%209.png)

The `users` table caught my attention so I decided to scan the following and found this.

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%2010.png)

Let’s check the `password` here!

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%2011.png)

Here’s what I found!

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%2012.png)

## 4- Receiving A Shell

Now we need to more further and enumerate more, as one of the question on the room’s page asks you for the CMS being used in the website I decided to search for the CMS’s flaws.

Finally, after some searching around I came across this github page. 

[Simple-Image-Gallery-Web-App/README.md at main · dumpling-soup/Simple-Image-Gallery-Web-App](https://github.com/dumpling-soup/Simple-Image-Gallery-Web-App/blob/main/README.md)

Here this guy demonstrates how a `.php` shell can be updates when we change our profile picture. So I decided to try the same using pentest monkey’s reverse shell. 

Here are the steps to receive the reverse shell.

1- Click on the Administrator Admin button above.

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%2013.png)

2- Click on My Account.

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%2014.png)

3- Setting up a reverse shell.

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%2015.png)

4- Scroll down and click Browse to select your new avatar and select the PHP reverse shell. 

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%2016.png)

5- Click Update.

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%2017.png)

6- Boom! You have the shell! 

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%2018.png)

## 5- Obtaining User.txt

Now we have the foothold of the system, now we need to get the user.txt, upon further enumeration we find out that the user `Mike` has the user.txt on his home directory.

And we do not have permissions to access the file, now we need to find some way to escalate your privileges from `www-data` to `mike`.

Actually, I was stuck at this part for a very long time but finally after some help from the internet and discord of tryhackme. I found out how to actually do it!

To obtain the user.txt first we have to visit the directory `/var/backups/mike_home_backups` this is the place where mike stores his backups and if we take a look at the `.bash_history` we find the password for mike!

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%2019.png)

Now we can finally escalate to `mike`.

But before we try to add the password using `sudo -l` we have to get a TTY shell which can be done using python.

`/usr/bin/python3.6- c 'import pty; pty.spawn("/bin/bash")'`

Now we can escalate without any problem and get the `user.txt` file!

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%2020.png)

![https://c.tenor.com/jUTgyIXKOtUAAAAC/mrrobot-wemadeit.gif](https://c.tenor.com/jUTgyIXKOtUAAAAC/mrrobot-wemadeit.gif)

## 6- Privilege Escalation To Root

So now we need the root perms, to do so I tried some basic escalation methods and found this while running `sudo -l`

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%2021.png)

It looks like a `.sh` file which can be ran by us to lets run it, using this command.

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%2022.png)

Now if we type in `read` in the input field it opens up a `nano` edit window for us and we can get root using that by hitting these 2 shortcut keys as seen on gtfobins.

![Untitled](https://github.com/3J0SKA/THM-WriteUps/blob/main/Gallery/Images/Untitled%2023.png)

Once done you will have the root access!

[https://tenor.com/view/naruto-wink-smile-happy-sarcastic-gif-7551863](https://tenor.com/view/naruto-wink-smile-happy-sarcastic-gif-7551863)
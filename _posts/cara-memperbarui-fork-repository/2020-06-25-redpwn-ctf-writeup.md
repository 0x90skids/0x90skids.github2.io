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

+  [Crypto](#crypto)
+  [Misc](#misc)
+  [Pwn](#pwn)
+  [Rev](#rev)
+  [Web](#web)

## Crypto

#### web/inspector-general   
**Solved By:** Name  
**Points:** 112

## Misc
### misc/uglybash
**Solved By:** tbutler0x90  
**Points:** 359  
**Flag:** flag{us3_zsh,-dummy}

##### Challenge
This bash script evaluates to echo dont just run it, dummy # flag{...} where the flag is in the comments.The comment won't be visible if you just execute the script. How can you mess with bash to get the value right before it executes?  
#### *Exerpt of Challenge Script, cmd.sh*
>  ${*%c-dFqjfo}  e$'\u0076'al "$(   ${*%%Q+n\{}   "${@~}" $'\160'r""$'\151'$@nt"f" %s   ' }~~@{$  ")   }La?cc87J##@{$   ;   }  ;  }8CC3vD/qX$t/*{$   }~~*{$   "}] "}^@{$"  y4R2SV$   "}cIqe[\(\%@{$" "}xk:W=Y2##@{$" [JzbY6E{$"   s%   ft'"'"'n'"'"''"'"'i'"'"'r\p  { ; }*!{$ ]  )e#22+)2}8Kr6>#*{$#82*01#3}^*{$((   [$ "};(\S-[\/@{$"   "},@{$"   ]  )71}|$1+d/$_dj/*{$#8+)2#16*1"}xp.{\$Z~[\%@{$"#}~*{$7"1"-((  [$ "@$"  "}oMAHn%%@{$"   ))  )0"1"01"}^@{$"#4}]\oh>-%%@{$+)"

##### Solution
1) To see what the bash script evaluates to just prior to execution, the subshell option was used to run the entire script in debug mode. Additionally, 

```bash
#!/bin/bash

exec 5> debug_output.txt
BASH_XTRACEFD="5"

### original script goes below here
```
2) Run the script with -x flag 
```bash
bash -x cmd.exe
```

3) Flag is located in the comments along the left side in the debug_output.txt, lines 70 -108

<figure>
<img src="/ugly-bash-flag.png" alt="results of debug">
<figcaption>Fig 1. Terminal emulator, instalasi package dan check service.</figcaption>
</figure>





#### web/inspector-general 
**Solved By:** Name  
**Points:** 112

## Pwn

#### web/inspector-general 
**Solved By:** Name  
**Points:** 112

## Rev

#### web/inspector-general 
**Solved By:** Name  
**Points:** 112

## Web

#### web/inspector-general 
**Solved By:** Name  
**Points:** 112

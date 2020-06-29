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


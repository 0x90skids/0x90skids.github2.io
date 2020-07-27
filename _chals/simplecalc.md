---
layout: default
title: simplecalc
category: pwn
author: <a href="https://cerne.xyz">cernec1999</a>
date: 2020-07-18 01:00 +0700
modified: 2020-07-18 01:00 +0700
description: simplecalc
link: https://github.com/0x90skids/simplecalc
image: /assets/img/simplecalc-ctf.png
tip: none
popup: false 
popup_title: View Message
popupcontent: I think there may be a secret code hidden in the application... I wonder what it does?
summary: simplecalc is a beginner / intermediate pwn challenge with an emphasis on binary exploitation.
---
Just a simple calculator application. Nothing suspicious to see here!

There's two challenges here that each yield their own flag. Both challenges have the same source code, but one challenge has a different compiler option enabled. Can you guess which one?

The challenge repository is linked here. To solve remotely, connect to the TCP servers.

simplecalc0 is at ```nc server.cerne.xyz 1337``` and simplecalc1 is at ```nc server.cerne.xyz 1338```
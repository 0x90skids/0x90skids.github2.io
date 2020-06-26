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
# Overview 

+  [Cryptp](#crypto)
+  [Web](#web-️)
+  [Rev](#rev)


Berawal dari saya pengen memperbarui repo yang tua dari suatu organisasi, niatnya pengen rumat ulang nih, ternyata dari orginal reponya ada update, sekalian buat artikel deh, lebih kurang gambaranya seperti ini.

## Crypto

#### Challenge Name 
**Solved By:** Name

Ada dua cara untuk memperbarui forked repository menggunakan web interface yang disediakan oleh github tapi ribet, atau melalui terminal yang lebih ribet lagi.

```python
# define punctuation
punctuations = '''!()-[]{};:'"\,<>./?@#$%^&*_~'''

my_str = "Hello!!!, he said ---and went."

# To take input from the user
# my_str = input("Enter a string: ")

# remove punctuation from the string
no_punct = ""
for char in my_str:
   if char not in punctuations:
       no_punct = no_punct + char

# display the unpunctuated string
print(no_punct)
```

1. Buka repo yang hasil fork di Github.
2. Klik **Pull Requests** di sebelah kanan, lalu **New Pull Request**.
3. Akan memunculkan hasil compare antara repo upstream dengan repo kamu(forked repo), dan jika menyatakan "There isn’t anything to compare.", tekan link **switching the base**, yang mana sekarang repo kamu(forked repo) akan dibalik menjadi base repo dan repo upstream menjadi head repo.
4. Tekan **Create Pull Request**, beri judul pull request, Tekan **Send Pull Request**.
5. Tekan **Merge Pull Request** dan **Confirm Merge**.

\* _pastikan kamu tidak merubah apapun pada forked repo, supaya melakukan merge secara otomatis, kalo tidak ya paling2 konflik._

### Web ⌨️

Tambahkan remote alamat repository yang aslinya disini tak beri nama `upstream`., ganti `ORIGINAL_OWNER` dan `ORIGINAL_REPO` dengan alamat repo aslimu.



```bash
$ git add remote upstream git@github.com:ORIGINAL_OWNER/ORIGINAL_REPO.git
$ git remote -v
> origin    git@github.com:piharpi/www.git (fetch) # forked repo
> origin    git@github.com:piharpi/www.git (push) # forked repo
> upstream    git@github.com:ORIGINAL_OWNER/ORIGINAL_REPO.git (fetch) # upstream repo / original repo
> upstream    git@github.com:ORIGINAL_OWNER/ORIGINAL_REPO.git (push) # upstream repo / original repo
```


## Rev 

Checkout ke local branch `master`.

```bash
$ git checkout master
> Switched to branch 'master'
```

<figure>
<img src="{{ page.image }}" alt="ilustrasi repo yang mau diupdate">
<figcaption>Fig 1. Gambaran ribetnya.</figcaption>
</figure>

Jika sudah, Merge local repo dengan remote `upstream/master`.

```bash
$ git merge upstream/master
```

Terakhir push local repo ke remote `origin`.

```bash
$ git add -A
$ git commit -m "updating origin repo" && git push -u origin master
```

Selamat mencoba cara ribet ini, semoga bisa dipahami, saya sendiri lebih senang melalui terminal, klo ada yang ribet kenapa cari yang mudah.

##### Resources

- [Syncing a fork](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/syncing-a-fork)
- [Update your fork directly on Github](https://rick.cogley.info/post/update-your-forked-repository-directly-on-github/#top)

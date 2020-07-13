# 0x90skids 

[![Netlify Status](https://api.netlify.com/api/v1/badges/01246265-66d4-4aae-bc5f-e78700c6b606/deploy-status)](https://app.netlify.com/sites/0x90skids2/deploys)

The website for the 0x90skids CTF team.  

## Table of Contents

- [0x90skids](#0x90skids)
  - [Table of Contents](#table-of-contents)
  - [Making Edits to the Website](#making-edits-to-the-website)
  - [Creating a new post](#creating-a-new-post)
  - [Adding Challenges to the CTF](#adding-challenges-to-the-ctf)
  - [Additional Commands](#additional-commands)
  - [About the Template](#about-the-template)


## Making Edits to the Website 

1) Clone the repository 

```
git clone https://github.com/0x90skids/0x90skids.github2.io.git
```

2) cd into cloned directory 

```
cd 0x90skids.github2.io
```

3) Install dependencies  

Running the development server locally requires ruby and bundle.

On MacOS X these can be installed with brew :

```
brew install ruby 
```

On Ubuntu, this can be installed via apt :
```
sudo apt install ruby ruby-bundler ruby-dev
```

4) Install the required dependencies 

```
bundle install 
```

5) Checkout the dev branch 

```
git checkout dev 
```

6) Launch development server

```
jekyll serve 
```

> You might have to start the development server with bundle exec 

```
bundle exec jekyll serve
```

1) Make edits to the development branch. You can preview changes live by visiting http://127.0.0.1:4000

2) Any pull requests into the master branch will automatically trigger [Netlify](https://app.netlify.com/sites/0x90skids2/deploys) to build the site. Build status will be shown in the pull request, and can be seen with the Netlify build badge. 

[![Netlify Status](https://api.netlify.com/api/v1/badges/01246265-66d4-4aae-bc5f-e78700c6b606/deploy-status)](https://app.netlify.com/sites/0x90skids2/deploys)

## Creating a new post 

1) Posts are held in the _posts directory

2) CTF writeups are held in the _posts/ctf directory

3) To create a new writeup, create a new markdown file in the writeup directory and add the necessary frontmatter content to the top

```html
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
```

4) Update the frontmatter variables with the necessary information and merge to master branch

## Adding Challenges to the CTF 

1) Create a new challenge md file in the _chals directory

2) Edit the necessary frontmatter tags. These are essential since the CTF page uses these tags to properly format and display the challenge. The necessary frontmatter tags are below. 


```html
---
layout: chals
title: Example1 
category: web
author: Jane Doe
date: 2020-06-25 01:00 +0700
modified: 2020-03-07 16:49:47 +07:00
description: A quick overview
link: https://example.com
image: 
---
```

3) If you have an external link, add it to the link. If not, you must put "none" for now until a fix is in place  

```html
link: none
```

4) Ensure that the category is lowercase, i.e web NOT Web

5) The actual content of the challenge, i.e the description, is written in markdown below the frontmatter

## Additional Commands 

Clean the site cache with jekyll clean 

```
jekyll clean
```

## About the Template


Powered by Klisé, a minimalist Jekyll theme for running a personal site and blog running on Jekyll.<br>
For demo <a href="https://klise.now.sh" target="_blank" rel="noopener">klise.now.sh</a>


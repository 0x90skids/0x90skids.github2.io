# 0x90skids 

[![Netlify Status](https://api.netlify.com/api/v1/badges/01246265-66d4-4aae-bc5f-e78700c6b606/deploy-status)](https://app.netlify.com/sites/0x90skids2/deploys) ![](https://img.shields.io/github/issues-pr-closed-raw/0x90skids/0x90skids.github2.io) ![](https://img.shields.io/github/issues-raw/0x90skids/0x90skids.github2.io)

The website for the 0x90skids CTF team.  

## Table of Contents

- [0x90skids](#0x90skids)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Jekyll Structure](#jekyll-structure)
  - [Editting Locally with Jekyll](#editting-locally-with-jekyll)
  - [Creating a new post](#creating-a-new-post)
  - [Adding Challenges to the CTF](#adding-challenges-to-the-ctf)
  - [Link Previews](#link-previews)
  - [Additional Commands](#additional-commands)
  - [About the Template](#about-the-template)


## Requirements
The 0x90skids website is build using [Jekyll]() a static web generator. Jekyll enables you to write site content in markdown and generate static web pages. It also enables you to run a simple local development server to live preview changes. See [Editing Locally with Jekyll](#editting-locally-with-jekyll) for installation instructions. 

## Jekyll Structure  

+  _chals: contains individual markdown ctf challenges, generated on the /ctf past
+  _data: contains the links for the navivation bar
+  _includes: contains the html code for items like headers, footers, navbar, ect
+  _layouts: contains the html for page layouts like post pages, the home page, the ctf page, ect
+  _posts: contains markdown files for blog posts (i.e ctf writeups)
+  _sass: contains custom css files
+  _site: contains the statically generated jekyll content 
+  _assets: contains css, favicons, images, ect
+  nodes_modules: contains bootstrap data


## Editting Locally with Jekyll

1) Clone the repository 

```
git clone https://github.com/0x90skids/0x90skids.github2.io.git
```

2) cd into cloned directory 

```
cd 0x90skids.github2.io
```

3) Install dependencies  

*Running the development server locally requires ruby and bundle.*

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

*You might have to start the development server with bundle exec*

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
layout: 
title: 
date: 
modified:
description: 
tag:
  - ctf
  - writeup
image: 
---
```

4) Update the frontmatter variables with the necessary information and merge to master branch

## Adding Challenges to the CTF 
Markdown files in the _chals directory are statically generated into the custom /ctf page using the ctf html layout located in _layouts/ctf.html. In order to properly render these md files, a series of *{{if}} .... {{else}}* liquid tags in ctf.html are used to categoriese and display the challenges.   

Because of these tags, it's very impoartant to fill out the appropriate frontmatter information on the md file.


**How to add chals to the ctf page**

1) Create a new challenge md file in the _chals directory

2) Edit the necessary frontmatter tags. 


```html
---
layout: default
title: your-title
category: web  
author: your-name
date: 
modified: 
description: your-description
link: 
image: /assets/img/header-image-name
tip: none
popup: true 
popupcontent: your-content
summary: your-summary
---
```

**Frontmatter details**

layout: must be default  
title: can be anything you want
category: must be lowercase, can only be one of the following. Open a feature request for more categories
+  web
+  pwn
+  rev
+  crypto
+  misc     

**Frontmatter options**
| front matter  | content  |
|---|---|
| author  | can be anything you want    |
| date  | takes format 2020-07-14 01:00 +0700   |
| modified  | takes format 2020-07-14 01:00 +0700    |
| description  | can be anything you want  |
link | this is optional, if you do not need a link then use "none"  
| image  |  this is optional, if you do not want to display a header  image then using "none" will create a simple card. Supplying an image path here will result in a header image card being generated. Images here take the path /assets/img/image-name.png |
| tip  | not implemented yet, leave as none  |
| popup  |  optional, if you want a popup modal box, then use "true", if not, leave "false" |
| popupcontent  | if you want a popup, place your popup content here, otherwise, leave blank  |
|  summary | used for twitter card preview. Leave blank if desired  |

## Link Previews
*readme details comming soon*

## Additional Commands 

Clean the site cache with jekyll clean 

```
jekyll clean
```

## About the Template


Powered by Klisé, a minimalist Jekyll theme for running a personal site and blog running on Jekyll.<br>
For demo <a href="https://klise.now.sh" target="_blank" rel="noopener">klise.now.sh</a>


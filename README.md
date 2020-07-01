# 0x90skids 

[![Netlify Status](https://api.netlify.com/api/v1/badges/01246265-66d4-4aae-bc5f-e78700c6b606/deploy-status)](https://app.netlify.com/sites/0x90skids2/deploys)

The website for the 0x90skids CTF team.  


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

Running the development server locally requires ruby and bundle. On mac osx these can be installed with brew 

```
brew install ruby 
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

## Additional Commands 

Clean the site cache with jekyll clean 

```
jekyll clean
```

## About the Template


Powered by Klisé, a minimalist Jekyll theme for running a personal site and blog running on Jekyll.<br>
For demo <a href="https://klise.now.sh" target="_blank" rel="noopener">klise.now.sh</a>


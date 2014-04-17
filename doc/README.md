This folder contains **source** files you can use to generate the project's documentation.

# usr

`usr/` contains the source files we use to generate [Jool's site](www.jool.mx) (**warning**: except the releases in the download/ folder!). It is mostly documentation intended for whoever wants to *use* Jool.

If you're a user, you should just follow that link and don't bother generating these files. But if you disagree, you're supposed to compile them using [Jekyll](http://jekyllrb.com/).

First install Jekyll by following the steps outlined at https://help.github.com/articles/using-jekyll-with-pages:

```bash
$ # YMMV
$ ruby --version
ruby 1.9.3p194 (2012-04-20 revision 35410) [x86_64-linux]
# gem install bundler
$ echo "source 'https://rubygems.org'" > Gemfile
$ echo "gem 'github-pages'" >> Gemfile
# bundle install
```

Then generate using the `jekyll` command:

```bash
$ cd usr
$ jekyll
```

Have a look at your generated files in the newly-generated usr/_site folder.

# dev

`dev/` contains a file you're supposed to run using [Doxygen](http://www.stack.nl/~dimitri/doxygen/). It is documentation indended for developers; Doxygen will extract the header comments from the code and summarize them in HTML form (by default).

Installation:

```bash
$ # YMMV
# apt-get install doxygen
```

Doc generation:

```bash
$ cd dev
$ doxygen
```


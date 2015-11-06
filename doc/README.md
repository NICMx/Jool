This folder contains **source** files you can use to generate the project's documentation.

# usr

`usr/` contains the source files we use to generate [Jool's site](https://nicmx.github.io/jool-doc) (**warning**: except the releases in the download/ folder!). It is mostly documentation intended for whoever wants to *use* Jool.

If you're a user, you should just follow that link and don't bother generating these files. But if you disagree, you're supposed to compile them using [Jekyll](http://jekyllrb.com/).

```bash
$ cd usr
$ jekyll build
```

Have a look at your generated files in the new `usr/_site/` folder (Start at `index.html`).

# dev

`dev/` contains a file you're supposed to run using [Doxygen](http://www.stack.nl/~dimitri/doxygen/). It is documentation indended for developers; Doxygen will extract the header comments from the code and summarize them in HTML form (by default).

```bash
$ cd dev
$ doxygen
```


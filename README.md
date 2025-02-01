# Localtunnel C implementation

Localtunnel is a simple tool, can be used to quickly exposes your localhost to
the world for easy testing and sharing!

The original code is written by nodejs. This is a C implementation of
localtunnel. It uses much less resources, so can be easily runs on
resource-constrained devices (eg, your home router).

See <https://github.com/localtunnel/localtunnel> for more details.

## Difference with the official one

* Doesn't support local https server. Because it looks nonsense.
* Be more stingy with link creation to save server resource.

## How to build (Debian / Ubuntu)

```sh
git clone https://github.com/pjincz/localtunnel-c
cd localtunnel-c

sudo apt-get build-dep .

debuild -us -uc
```

deb file will be generated in parent directory.

## How to build (Common Linux)

Localtunnel-c needs following libraries to build:

* libev
* libcjson
* libcurl

Install those dependencies by `apt` or `yum` or whatever. Then

```sh
git clone https://github.com/pjincz/localtunnel-c

cd localtunnel-c
make

# if you like to, this will install localtunnel to /usr/local/bin
sudo make install
```

## How to use

For example, if you have a local http server listen on :8000, just run:

```sh
./localtunnel -p 8000
```

Then you will get a link like `https://short-taxes-stick.loca.lt`. Just curl it,
that's all.

Run `./localtunnel --help` for more options.

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

## How to build

### Debian, Ubuntu

```sh
git clone https://github.com/pjincz/localtunnel-c
cd localtunnel-c

sudo apt-get build-dep .

debuild -us -uc
```

deb file will be generated in parent directory.

### Common Linux, MacOS, FreeBSD

Install dependencies first.

Ubuntu/Debian:
```sh
sudo apt install git cmake libev-dev libcjson-dev libcurl4-gnutls-dev
```

Mac OS:
```sh
brew install git cmake libev cjson curl
```

FreeBSD:
```sh
sudo pkg install git cmake libev libcjson curl
```

Built it:
```sh
git clone https://github.com/pjincz/localtunnel-c

cd localtunnel-c
cmake .
make
```

### Windows

Download and install msys2: <https://www.msys2.org/>

Launch `msys2 UCRT64`.
(You can also use other one if you prefer, don't forget to change ucrt strings below)

Install dependencies:
```sh
pacman -S git gcc cmake make libcurl-devel libzstd-devel mingw-w64-ucrt-x86_64-cjson
```

Install libev:
```sh
git clone https://github.com/enki/libev
cd libev
./configure
make
make install
cd ..
```

Build localtunnel:
```sh
git clone https://github.com/pjincz/localtunnel-c
cd localtunnel-c
CPATH=/ucrt64/include LIBRARY_PATH=/ucrt64/lib cmake .
make
```

## How to use

For example, if you want to expose local http server `:8000`, just run:

```sh
./localtunnel -p 8000
```

Then you will get a link like `https://short-taxes-stick.loca.lt`. Try curl it,
that's all.

For more usage, try:
```sh
./localtunnel --help
```

CC = cc
LDFLAGS = -lev -lcjson -lcurl
PREFIX = /usr/local

COMMON_CFLAGS = -Wall
ifdef DEBUG
    CFLAGS = $(COMMON_CFLAGS) -O0 -g
else
    CFLAGS = $(COMMON_CFLAGS) -O2
endif

SRC = localtunnel.c
OUT = localtunnel

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $(OUT) $(SRC) $(LDFLAGS)

clean:
	rm -rf $(OUT)

install:
	install -D -m 755 localtunnel $(PREFIX)/bin/localtunnel

run: $(OUT)
	./$(OUT)

.PHONY: clean run

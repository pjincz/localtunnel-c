CC = cc
CLFAGS = -Wall
LDFLAGS = -lev -lcjson -lcurl

SRC = localtunnel.c
OUT = localtunnel

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $(OUT) $(SRC) $(LDFLAGS)

clean:
	rm -rf $(OUT)

run: $(OUT)
	./$(OUT)

.PHONY: clean run

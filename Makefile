lt: localtunnel.c
	cc $< -lcurl -lcjson -lev -o lt -g -fsanitize=address

run: lt
	./lt

.PHONY: run

lt: localtunnel.c
	cc $< -lcurl -lcjson -o lt -g -fsanitize=address

run: lt
	./lt

.PHONY: run

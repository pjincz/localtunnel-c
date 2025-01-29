lt: localtunnel.c
	cc $< -lcurl -lcjson -o lt

run: lt
	./lt

.PHONY: run

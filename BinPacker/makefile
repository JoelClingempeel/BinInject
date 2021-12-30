all: injecter packed payload

injecter: injecter.c
	$(CC) injecter.c -o injecter

packed: packed.c
	$(CC) packed.c -o packed

payload: payload.s
	$(CC) -c payload.s -o payload.o
	ld payload.o -o payload
	rm payload.o

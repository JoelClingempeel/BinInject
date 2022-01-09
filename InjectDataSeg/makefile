all: elfmod hello payload
	rm hello
	$(CC) hello.c -o hello

elfmod: elfmod.c
	$(CC) elfmod.c -o elfmod

hello: hello.c
	$(CC) hello.c -o hello

payload: payload.s
	$(CC) -c payload.s -o payload.o
	ld payload.o -o payload
	rm payload.o

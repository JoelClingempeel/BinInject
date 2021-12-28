#/bin/sh
gcc elfmod.c -o elfmod
gcc hello.c -o hello
gcc -c payload.s -o payload.o
ld payload.o -o payload
rm payload.o
./elfmod hello payload

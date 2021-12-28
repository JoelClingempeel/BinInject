#/bin/sh
gcc injecter.c -o injecter
gcc packed.c -o packed
gcc -c payload.s -o payload.o
ld payload.o -o payload
rm payload.o
./injecter packed payload

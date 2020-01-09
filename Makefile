CC = gcc

CFLAGS=-O3 -fomit-frame-pointer -msse2avx -mavx2 -march=native -std=c99

all :
	$(CC) $(CFLAGS) -c -g Lizard.c main.c randombytes.c sha512.c mat_mul.c
	$(CC) $(CFLAGS) -o Lizard Lizard.o main.o randombytes.o sha512.o mat_mul.o -lkeccak
	
run : all
	./Lizard

clean :
	rm -f *.o
	rm -f Lizard

new :
	make clean
	make all
	./Lizard


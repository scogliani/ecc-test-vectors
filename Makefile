CC=gcc
CFLAGS=-g -ansi -std=c11 -Wall -Wextra -Wpedantic -Wconversion -I. -Iopenssl-1.0.2h/include
LDLIBS=./openssl-1.0.2h/libssl.a ./openssl-1.0.2h/libcrypto.a -ldl
RM=rm -f

ecc_test_vectors: ecc_test_vectors.o create_ecc.o ecc_pointmul.o

clean:
	$(RM) *.o

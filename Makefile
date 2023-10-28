CC=gcc
CFLAGS=-Wall -Werror -Wextra -pedantic -O3 -Wno-unused-function
LDFLAGS=-lcurl -lmagic
SRC=http/*.c http/method.h str.c epoll.c tpool/threadpool.c
TARGET=server

server: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)
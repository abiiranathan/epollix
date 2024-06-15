CC=gcc
CFLAGS=-Wall -Werror -Wextra -pedantic -O3 -DMAX_DIRNAME=255

RUST_FFI_INCLUDES=-I./rust/rcore/
RUST_FFI_LIBS=-L./rust/rcore/target/release/ -lrcore

# Add rust FFI includes
CFLAGS+=$(RUST_FFI_INCLUDES)

LDFLAGS=-lcurl -lmagic -lm -lsolidc

# Add rust FFI libs
LDFLAGS+=$(RUST_FFI_LIBS)

SRC_DIR=src
OBJ_DIR=obj
SRCS=$(wildcard $(SRC_DIR)/*.c) main.c
OBJS=$(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
BIN_DIR=bin
TARGET=$(BIN_DIR)/server

all: RUST_FFI $(TARGET) 

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)
	mkdir -p $(BIN_DIR)

$(TARGET): $(OBJS) | RUST_FFI
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

RUST_FFI: ./rust/rcore/src/lib.rs
	cargo build --release --manifest-path=./rust/rcore/Cargo.toml

check: all
	valgrind -s --leak-check=full --track-origins=yes --show-leak-kinds=all ./$(TARGET) 8080

# Install dependencies
dep:
	sudo apt-get install libcurl4-openssl-dev libmagic-dev

clean:
	rm -f $(OBJ_DIR)/*.o $(TARGET) ./rust/rcore/target/release/librcore.a

.PHONY: all clean RCORE

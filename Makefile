TARGET=btc-wallet

CC=gcc
LINKER=gcc -o 

CFLAGS=-g -Wall -std=gnu99 -D_BSD_SOURCE -D_GNU_SOURCE
LIBS=-lpthread -lm

SRC_DIR=src
OBJ_DIR=obj
BIN_DIR=bin
LOG_DIR=log

CUR_PATH=$(shell pwd)

SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

CFLAGS += -D_CONSOLE_OUTPUT
CFLAGS += -Iinclude -Isrc -Isrc/shell
CFLAGS += $(shell pkg-config --cflags json-c)
CFLAGS += $(shell pkg-config --cflags libsecp256k1)
CFLAGS += $(shell pkg-config --cflags gtk+-3.0)

ifneq ($(wildcard $(SRC_DIR)/shell/shell.h),"")
CFLAGS += -D_HAS_SHELL
endif

LIBS += $(shell pkg-config --libs json-c)
LIBS += $(shell pkg-config --libs libsecp256k1)
LIBS += -lssl -lcrypto
LIBS += $(shell pkg-config --libs gtk+-3.0)



SHELL_SOURCES := $(wildcard $(SRC_DIR)/shell/*.c)
SHELL_OBJECTS := $(SHELL_SOURCES:%.c=%.o)

UTILS_SOURCES := $(wildcard $(SRC_DIR)/utils/*.c)
UTILS_OBJECTS := $(UTILS_SOURCES:%.c=%.o)

CRYPTO_SOURCES := $(wildcard $(SRC_DIR)/crypto/*.c)
CRYPTO_OBJECTS := $(CRYPTO_SOURCES:%.c=%.o)

PROTOCOL_SOURCES := $(wildcard $(SRC_DIR)/protocol/*.c)
PROTOCOL_OBJECTS := $(PROTOCOL_SOURCES:%.c=%.o)

DEP_OBJECTS :=$(UTILS_OBJECTS) $(PROTOCOL_OBJECTS) $(CRYPTO_OBJECTS)


all: do_init $(BIN_DIR)/$(TARGET)

$(BIN_DIR)/$(TARGET): $(OBJECTS)  $(SHELL_OBJECTS) $(DEP_OBJECTS)
	$(LINKER) $@ $(OBJECTS) $(SHELL_OBJECTS) $(DEP_OBJECTS) $(LIBS)
	
$(OBJECTS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)
	
$(SHELL_OBJECTS): $(SRC_DIR)/shell/%.o : $(SRC_DIR)/shell/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

$(UTILS_OBJECTS): $(SRC_DIR)/utils/%.o : $(SRC_DIR)/utils/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

$(CRYPTO_OBJECTS): $(SRC_DIR)/crypto/%.o : $(SRC_DIR)/crypto/%.c
	$(CC) -o $@ -c $< $(CFLAGS)	

$(PROTOCOL_OBJECTS): $(SRC_DIR)/protocol/%.o : $(SRC_DIR)/protocol/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: do_init clean
do_init:
	@echo $(CUR_PATH)
	test -d $(OBJ_DIR) || mkdir -p $(OBJ_DIR)
	test -d $(BIN_DIR) || mkdir -p $(BIN_DIR)
	test -d $(LOG_DIR) || mkdir -p $(LOG_DIR)
	
clean:
	rm $(OBJ_DIR)/*.o $(SRC_DIR)/shell/*.o 
	rm $(SRC_DIR)/utils/*.o $(SRC_DIR)/crypto/*.o $(SRC_DIR)/protocol/*.o
	rm $(BIN_DIR)/$(TARGET)
	

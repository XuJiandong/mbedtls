
CC = riscv64-unknown-elf-gcc
AR = riscv64-unknown-elf-ar
LD = riscv64-unknown-elf-ld
CKBVM = ~/projects/ckb-vm-test-suite/binary/target/release/asm64


CFLAGS	?= -O2
WARNING_CFLAGS ?=  -Wall -Wextra
LDFLAGS ?=

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../../include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS =

ifdef DEBUG
LOCAL_CFLAGS += -g3
endif

.SILENT:

.PHONY: all rsa_verify_no_fs clean

# add --version to dump more information
rsa_verify_no_fs: rsa_verify_no_fs.o
	$(CC) -o $@ $< ../../library/libmbedcrypto.a

run: rsa_verify_no_fs
	$(CKBVM) $<

.c.o:
	echo "  RISCV CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -o $@ -c $<

clean:
	rm -f rsa_verify_no_fs
	rm -f rsa_verify_no_fs.o


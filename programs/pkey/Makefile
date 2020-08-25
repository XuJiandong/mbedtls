

CC = riscv64-unknown-elf-gcc
AR = riscv64-unknown-elf-ar
LD = riscv64-unknown-elf-ld

CKBLIBC ?= ../../../ckb-c-stdlib/libc
CKBVM ?= ~/projects/ckb-vm-test-suite/binary/target/release/asm64
CFLAGS	?= -Os -fPIC -nostdinc -nostdlib -I ${CKBLIBC} -fdata-sections -ffunction-sections
WARNING_CFLAGS ?=  -Wall -Wextra
LDFLAGS ?= -Wl,--gc-sections -Wl,-static

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../../include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS =

.SILENT:

.PHONY: all clean all

all: rsa_verify_no_fs
	echo "Build rsa_verify_no_fs done!"

# add --verbose to dump more information
rsa_verify_no_fs: rsa_verify_no_fs.c ../../library/libmbedcrypto.a
	echo "RISCV ${CFLAGS} $(LDFLAGS) $^"
	$(CC) ${CFLAGS} ${LOCAL_CFLAGS} $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $^

run: rsa_verify_no_fs
	echo running $(CKBVM) rsa_verify_no_fs
	$(CKBVM) rsa_verify_no_fs
	echo "Done. There should be no output(return 0)."

fail: rsa_verify_no_fs
	echo running $(CKBVM) rsa_verify_no_fs
	echo "There will be output like this: Ok(1)"
	$(CKBVM) rsa_verify_no_fs hello,World! 5AC84DEA32E756A5A1C287C5F4F1446F0606ACF8202D419570B2082EB8C439FB2157DF482546487B89FD6A8E00452431E57AD264C9D0B7F71182D250219CFCBA74D61AC01ACE48206DA7D124BE2E1DA77A9E1F4CF34F64CC4085DA79AE406A96C4F15467086839A79EAB691C73D1EE248819479574028389376BD7F9FB4F5C9B || echo "Failed as expected."

dis:
	echo "Disasemble rsa_verify_no_fs to dis.txg"
	riscv64-unknown-elf-objdump -d rsa_verify_no_fs > dis.txt
	echo "done"

clean:
	rm -f rsa_verify_no_fs
	rm -f *.o

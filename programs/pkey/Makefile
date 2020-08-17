

CC = riscv64-unknown-elf-gcc
AR = riscv64-unknown-elf-ar
LD = riscv64-unknown-elf-ld
CKBVM = ~/projects/ckb-vm-test-suite/binary/target/release/asm64


CFLAGS	?= -Os
WARNING_CFLAGS ?=  -Wall -Wextra
LDFLAGS ?=

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../../include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS =

.SILENT:

.PHONY: all rsa_verify_no_fs clean

# add --verbose to dump more information
rsa_verify_no_fs: rsa_verify_no_fs.o
	$(CC) $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $< ../../library/libmbedcrypto.a
	echo "Build rsa_verify_no_fs"

run: rsa_verify_no_fs
	echo running $(CKBVM) rsa_verify_no_fs
	$(CKBVM) rsa_verify_no_fs hello,CKB! 5AC84DEA32E756A5A1C287C5F4F1446F0606ACF8202D419570B2082EB8C439FB2157DF482546487B89FD6A8E00452431E57AD264C9D0B7F71182D250219CFCBA74D61AC01ACE48206DA7D124BE2E1DA77A9E1F4CF34F64CC4085DA79AE406A96C4F15467086839A79EAB691C73D1EE248819479574028389376BD7F9FB4F5C9B
	echo "Done. There should be no output(return 0)."

fail:
	echo running $(CKBVM) rsa_verify_no_fs
	echo "There will be output like this: Ok(1)"
	$(CKBVM) rsa_verify_no_fs hello,World! 5AC84DEA32E756A5A1C287C5F4F1446F0606ACF8202D419570B2082EB8C439FB2157DF482546487B89FD6A8E00452431E57AD264C9D0B7F71182D250219CFCBA74D61AC01ACE48206DA7D124BE2E1DA77A9E1F4CF34F64CC4085DA79AE406A96C4F15467086839A79EAB691C73D1EE248819479574028389376BD7F9FB4F5C9B

dis:
	echo "Disasemble rsa_verify_no_fs to dis.txg"
	riscv64-unknown-elf-objdump -d rsa_verify_no_fs > dis.txt
	echo "done"

.c.o:
	echo "RISCV CC $(CFLAGS) $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -o $@ -c $<

clean:
	rm -f rsa_verify_no_fs
	rm -f *.o


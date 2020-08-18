/*
 * Same as rsa_verify.c without filesystem support.
 */

// uncomment to profile
// #define FOR_PROFILE

#if !defined(MBEDTLS_CONFIG_FILE)

#include "mbedtls/config.h"

#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdlib.h>
#include <string.h>
#define mbedtls_printf(x, ...)  (void)0
// use this on simulator
// #define mbedtls_printf printf
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#define CHECK(n) if ((n) != 0) {mbedtls_printf("mbedtls_mpi_read_string failed"); ret = -2; goto exit;}

// hard coded public key
const char *PRIV_N = "A1D46FBA2318F8DCEF16C280948B1CF27966B9B47225ED2989F8D74B45BD36049C0AAB5AD0FF003553BA843C8E12782FC5873BB89A3DC84B883D25666CD22BF3ACD5B675969F8BEBFBCAC93FDD927C7442B178B10D1DFF9398E52316AAE0AF74E594650BDC3C670241D418684593CDA1A7B9DC4F20D2FDC6F66344074003E211";
const char *PRIV_E = "010001";

int md_string(const mbedtls_md_info_t *md_info, const char *buf, size_t n, unsigned char *output) {
    int ret = -1;
    mbedtls_md_context_t ctx;

    if (md_info == NULL)
        return (MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    mbedtls_md_init(&ctx);

    if ((ret = mbedtls_md_setup(&ctx, md_info, 0)) != 0)
        goto cleanup;

    if ((ret = mbedtls_md_starts(&ctx)) != 0)
        goto cleanup;

    if ((ret = mbedtls_md_update(&ctx, (const unsigned char *) buf, n)) != 0)
        goto cleanup;

    ret = mbedtls_md_finish(&ctx, output);

    cleanup:
    mbedtls_md_free(&ctx);
    return ret;
}

void mbedtls_mpi_dump(const char *prefix, const mbedtls_mpi *X) {
    (void)prefix;
    size_t n;
    /*
     * Buffer should have space for (short) label and decimal formatted MPI,
     * newline characters and '\0'
     */
    char s[MBEDTLS_MPI_RW_BUFFER_SIZE];
    memset(s, 0, sizeof(s));

    mbedtls_mpi_write_string(X, 16, s, sizeof(s) - 2, &n);

    mbedtls_printf("%s%s\n", prefix, s);
}

unsigned char get_hex(unsigned char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    else
        return 0;
    // todo: support assert?
}

int scan_hex(const char* s, unsigned char* value) {
    if (s[0] == '\0' || s[1] == '\0')
        return 0;

    unsigned char high_part = get_hex(s[0]);
    unsigned char low_part = get_hex(s[1]);

    *value =  (high_part << 4) + low_part;
    return 1;
}

int loop_once(int argc, const char* argv[]) {
    int ret = EXIT_FAILURE;
    int exit_code = EXIT_FAILURE;
    size_t i;
    mbedtls_rsa_context rsa;
    unsigned char hash[32];
    unsigned char sig_buf[MBEDTLS_MPI_MAX_SIZE];
    const char *sig = NULL;
    const char *msg = NULL;
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

    sig = "5AC84DEA32E756A5A1C287C5F4F1446F0606ACF8202D419570B2082EB8C439FB2157DF482546487B89FD6A8E00452431E57AD264C9D0B7F71182D250219CFCBA74D61AC01ACE48206DA7D124BE2E1DA77A9E1F4CF34F64CC4085DA79AE406A96C4F15467086839A79EAB691C73D1EE248819479574028389376BD7F9FB4F5C9B";
    msg = "hello,CKB!";
    if (argc == 3) {
        msg = argv[1];
        sig = argv[2];
    }

    CHECK(mbedtls_mpi_read_string(&rsa.N, 16, PRIV_N));
    CHECK(mbedtls_mpi_read_string(&rsa.E, 16, PRIV_E));
    rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

    // convert signature in plain string to binary
    i = 0;
    const char *sig_ptr = sig;
    const char *sig_end = sig + strlen(sig);
    while (1) {
        unsigned char c = 0;
        int consumed = scan_hex(sig_ptr, &c);
        if (consumed == 0)
            break;
        if (i >= (int) sizeof(sig_buf))
            break;
        sig_buf[i++] = (unsigned char) c;
        sig_ptr += consumed * 2;
        if (sig_ptr >= sig_end)
            break;
    }

    mbedtls_printf("\nVerifying the RSA/SHA-256 signature");
    if ((ret = md_string(
            mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
            msg, strlen(msg), hash)) != 0) {
        mbedtls_printf("failed\n  ! md_string failed.");
        goto exit;
    }

    if ((ret = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,
                                        MBEDTLS_MD_SHA256, 20, hash, sig_buf)) != 0) {
        mbedtls_printf("failed\n  ! mbedtls_rsa_pkcs1_verify returned -0x%0x\n\n", (unsigned int) -ret);
        goto exit;
    }

    mbedtls_printf("\nOK (the signature is valid)\n\n");

    exit_code = EXIT_SUCCESS;

exit:
    mbedtls_rsa_free(&rsa);
    return exit_code;
}

#ifdef FOR_PROFILE
#include <stdio.h>

int main(int argc, const char* argv[]) {
    printf("start running, to profile...\n");
    fflush(stdin);
    for (int i = 0; i < 200000; i++) {
        loop_once(argc, argv);
    }
    printf("Done.\n");
    return loop_once(argc, argv);
}
#else
int main(int argc, const char* argv[]) {
    return loop_once(argc, argv);
}
#endif

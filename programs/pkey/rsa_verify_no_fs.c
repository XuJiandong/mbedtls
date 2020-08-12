/*
 * Same as rsa_verify.c without filesystem support.
 */

#if !defined(MBEDTLS_CONFIG_FILE)

#include "mbedtls/config.h"

#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)

#include "mbedtls/platform.h"

#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_snprintf        snprintf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_RSA_C) || \
    !defined(MBEDTLS_SHA256_C) || !defined(MBEDTLS_MD_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_RSA_C and/or "
            "MBEDTLS_MD_C and/or "
            "MBEDTLS_SHA256_C and/or MBEDTLS_FS_IO not defined.\n");
    mbedtls_exit( 0 );
}
#else

#include "mbedtls/rsa.h"
#include "mbedtls/md.h"

#include <stdio.h>
#include <string.h>

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

#define CHECK(n) if ((n) != 0) {mbedtls_printf("mbedtls_mpi_read_string failed"); ret = -2; goto exit;}

int main(int argc, const char *argv[]) {
    int ret = 1;
    unsigned c;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    size_t i;
    mbedtls_rsa_context rsa;
    unsigned char hash[32];
    unsigned char sig_buf[MBEDTLS_MPI_MAX_SIZE];
    const char *sig = NULL;

    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

    if (argc != 3) {
        mbedtls_printf("usage: rsa_verify <string> <signature>\n");
        goto exit;
    }
    sig = argv[2];

    CHECK(mbedtls_mpi_read_string(&rsa.N, 16, PRIV_N));
    CHECK(mbedtls_mpi_read_string(&rsa.E, 16, PRIV_E));
    rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

    // convert signature in plain string to binary
    i = 0;
    const char *sig_ptr = sig;
    const char *sig_end = sig + strlen(sig);
    while (1) {
        int consumed = sscanf(sig_ptr, "%02X", (unsigned int *) &c);
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
            argv[1], strlen(argv[1]), hash)) != 0) {
        mbedtls_printf("failed\n  ! md_string failed.");
        goto exit;
    }

    if ((ret = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,
                                        MBEDTLS_MD_SHA256, 20, hash, sig_buf)) != 0) {
        mbedtls_printf("failed\n  ! mbedtls_rsa_pkcs1_verify returned -0x%0x\n\n", (unsigned int) -ret);
        goto exit;
    }

    mbedtls_printf("\nOK (the signature is valid)\n\n");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    mbedtls_rsa_free(&rsa);
    mbedtls_exit(exit_code);
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_RSA_C && MBEDTLS_SHA256_C &&
          MBEDTLS_FS_IO */

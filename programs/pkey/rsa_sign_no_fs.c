/*
 *  same as rsa_sign.c without filesystem support.
 */

#if !defined(MBEDTLS_CONFIG_FILE)

#include "mbedtls/config.h"

#else
#include MBEDTLS_CONFIG_FILE
#endif

// TODO:
#if defined(MBEDTLS_PLATFORM_C)

#include "mbedtls/platform.h"

#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_fprintf         fprintf
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

// hard coded private key
const char *PRIV_N = "A1D46FBA2318F8DCEF16C280948B1CF27966B9B47225ED2989F8D74B45BD36049C0AAB5AD0FF003553BA843C8E12782FC5873BB89A3DC84B883D25666CD22BF3ACD5B675969F8BEBFBCAC93FDD927C7442B178B10D1DFF9398E52316AAE0AF74E594650BDC3C670241D418684593CDA1A7B9DC4F20D2FDC6F66344074003E211";
const char *PRIV_E = "010001";
const char *PRIV_D = "589552BB4F2F023ADDDD5586D0C8FD857512D82080436678D07F984A29D892D31F1F7000FC5A39A0F73E27D885E47249A4148C8A5653EF69F91F8F736BA9F84841C2D99CD8C24DE8B72B5C9BE0EDBE23F93D731749FEA9CFB4A48DD2B7F35A2703E74AA2D4DB7DE9CEEA7D763AF0ADA7AC176C4E9A22C4CDA65CEC0C65964401";
const char *PRIV_P = "CD083568D2D46C44C40C1FA0101AF2155E59C70B08423112AF0C1202514BBA5210765E29FF13036F56C7495894D80CF8C3BAEE2839BACBB0B86F6A2965F60DB1";
const char *PRIV_Q = "CA0EEEA5E710E8E9811A6B846399420E3AE4A4C16647E426DDF8BBBCB11CD3F35CE2E4B6BCAD07AE2C0EC2ECBFCC601B207CDD77B5673E16382B1130BF465261";
const char *PRIV_DP = "0D0E21C07BF434B4A83B116472C2147A11D8EB98A33CFBBCF1D275EF19D815941622435AAF3839B6C432CA53CE9E772CFBE1923A937A766FD93E96E6EDEC1DF1";
const char *PRIV_DQ = "269CEBE6305DFEE4809377F078C814E37B45AE6677114DFC4F76F5097E1F3031D592567AC55B9B98213B40ECD54A4D2361F5FAACA1B1F51F71E4690893C4F081";
const char *PRIV_QP = "97AC5BB885ABCA314375E9E4DB1BA4B2218C90619F61BD474F5785075ECA81750A735199A8C191FE2D3355E7CF601A70E5CABDE0E02C2538BB9FB4871540B3C1";

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

    if ((ret = mbedtls_md_update(&ctx, (const unsigned char*)buf, n)) != 0)
        goto cleanup;

    ret = mbedtls_md_finish(&ctx, output);

cleanup:
    mbedtls_md_free(&ctx);
    return ret;
}

void mbedtls_mpi_dump(const char* prefix, const mbedtls_mpi *X) {
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
    int exit_code = MBEDTLS_EXIT_FAILURE;
    size_t i;
    mbedtls_rsa_context rsa;
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;

    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ);
    mbedtls_mpi_init(&QP);

    if (argc != 2) {
        mbedtls_printf("usage: rsa_sign <string to sign>\n");
        goto exit;
    } else {
        mbedtls_printf("start to sign string \"%s\"", argv[1]);
    }

    CHECK(mbedtls_mpi_read_string(&N, 16, PRIV_N));
    CHECK(mbedtls_mpi_read_string(&E, 16, PRIV_E));
    CHECK(mbedtls_mpi_read_string(&D, 16, PRIV_D));
    CHECK(mbedtls_mpi_read_string(&P, 16, PRIV_P));
    CHECK(mbedtls_mpi_read_string(&Q, 16, PRIV_Q));
    CHECK(mbedtls_mpi_read_string(&DP, 16, PRIV_DP));
    CHECK(mbedtls_mpi_read_string(&DQ, 16, PRIV_DQ));
    CHECK(mbedtls_mpi_read_string(&QP, 16, PRIV_QP));

#if 0
    mbedtls_printf("\n");
    mbedtls_mpi_dump("N=", &N);
    mbedtls_mpi_dump("E=", &E);
    mbedtls_mpi_dump("D=", &D);
    mbedtls_mpi_dump("P=", &P);
    mbedtls_mpi_dump("Q=", &Q);
    mbedtls_mpi_dump("DP=", &DP);
    mbedtls_mpi_dump("DQ=", &DQ);
    mbedtls_mpi_dump("QP=", &QP);
#endif

    if ((ret = mbedtls_rsa_import(&rsa, &N, &P, &Q, &D, &E)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_import returned %d\n\n",
                       ret);
        goto exit;
    }

    if ((ret = mbedtls_rsa_complete(&rsa)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_complete returned %d\n\n",
                       ret);
        goto exit;
    }

    mbedtls_printf("\nChecking the private key");
    fflush(stdout);
    if ((ret = mbedtls_rsa_check_privkey(&rsa)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_check_privkey failed with -0x%0x\n", (unsigned int) -ret);
        goto exit;
    }

    /*
     * Compute the SHA-256 hash of the input file,
     * then calculate the RSA signature of the hash.
     */
    mbedtls_printf("\nGenerating the RSA/SHA-256 signature\n");

    int length = strlen(argv[1]);
    if ((ret = md_string(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                         argv[1], length, hash)) != 0) {
        mbedtls_printf(" failed\n  ! Could not open or read %s\n\n", argv[1]);
        goto exit;
    }

    if ((ret = mbedtls_rsa_pkcs1_sign(&rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256,
                                      20, hash, buf)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_sign returned -0x%0x\n\n", (unsigned int) -ret);
        goto exit;
    }

    /*
     * Print the signature into <filename>.sig
     */

    for (i = 0; i < rsa.len; i++)
        mbedtls_printf("%02X", buf[i]);

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    mbedtls_rsa_free(&rsa);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ);
    mbedtls_mpi_free(&QP);

    mbedtls_exit(exit_code);
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_RSA_C && MBEDTLS_SHA256_C &&
          MBEDTLS_FS_IO */

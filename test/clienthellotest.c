/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

#include "../ssl/packet_locl.h"

#include "testutil.h"
#include "test_main_custom.h"

#define CLIENT_VERSION_LEN      2

#define TOTAL_NUM_TESTS                         4

/*
 * Test that explicitly setting ticket data results in it appearing in the
 * ClientHello for a negotiated SSL/TLS version
 */
#define TEST_SET_SESSION_TICK_DATA_VER_NEG      0
/* Enable padding and make sure ClientHello is long enough to require it */
#define TEST_ADD_PADDING                        1
/* Enable padding and make sure ClientHello is short enough to not need it */
#define TEST_PADDING_NOT_NEEDED                 2
/*
 * Enable padding and add a PSK to the ClientHello (this will also ensure the
 * ClientHello is long enough to need padding)
 */
#define TEST_ADD_PADDING_AND_PSK                3

#define F5_WORKAROUND_MIN_MSG_LEN   0xff
#define F5_WORKAROUND_MAX_MSG_LEN   0x200

const char *sessionfile = NULL;

static int test_client_hello(int currtest)
{
    SSL_CTX *ctx;
    SSL *con = NULL;
    BIO *rbio;
    BIO *wbio;
    long len;
    unsigned char *data;
    PACKET pkt, pkt2, pkt3;
    char *dummytick = "Hello World!";
    unsigned int type;
    int testresult = 0;
    size_t msglen;
    BIO *sessbio = NULL;
    SSL_SESSION *sess = NULL;

    /*
     * For each test set up an SSL_CTX and SSL and see what ClientHello gets
     * produced when we try to connect
     */
    ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL)
        goto end;

    switch(currtest) {
    case TEST_SET_SESSION_TICK_DATA_VER_NEG:
        /* Testing for session tickets <= TLS1.2; not relevant for 1.3 */
        if (!SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION))
            goto end;
        break;

    case TEST_ADD_PADDING_AND_PSK:
    case TEST_ADD_PADDING:
    case TEST_PADDING_NOT_NEEDED:
        SSL_CTX_set_options(ctx, SSL_OP_TLSEXT_PADDING);
        /*
         * Add lots of ciphersuites so that the ClientHello is at least
         * F5_WORKAROUND_MIN_MSG_LEN bytes long - meaning padding will be
         * needed.
         * In the padding not needed case we assume the test will pass, but then
         * set testresult to 0 if we see the padding extension.
         */
        if (currtest == TEST_ADD_PADDING
                && !SSL_CTX_set_cipher_list(ctx, "ALL"))
            goto end;
        else if (currtest == TEST_PADDING_NOT_NEEDED)
            testresult = 1;
        break;

    default:
        goto end;
    }

    con = SSL_new(ctx);
    if (con == NULL)
        goto end;

    if (currtest == TEST_ADD_PADDING_AND_PSK) {
        sessbio = BIO_new_file(sessionfile, "r");
        if (sessbio == NULL) {
            printf("Unable to open session.pem\n");
            goto end;
        }
        sess = PEM_read_bio_SSL_SESSION(sessbio, NULL, NULL, NULL);
        if (sess == NULL) {
            printf("Unable to load SSL_SESSION\n");
            goto end;
        }
        /*
         * We reset the creation time so that we don't discard the session as
         * too old.
         */
        if (!SSL_SESSION_set_time(sess, time(NULL))) {
            printf("Unable to set creation time on SSL_SESSION\n");
            goto end;
        }
        if (!SSL_set_session(con, sess)) {
            printf("Unable to set the session on the connection\n");
            goto end;
        }
    }

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    if (rbio == NULL || wbio == NULL) {
        BIO_free(rbio);
        BIO_free(wbio);
        goto end;
    }

    SSL_set_bio(con, rbio, wbio);
    SSL_set_connect_state(con);

    if (currtest == TEST_SET_SESSION_TICK_DATA_VER_NEG) {
        if (!SSL_set_session_ticket_ext(con, dummytick, strlen(dummytick)))
            goto end;
    }

    if (SSL_connect(con) > 0) {
        /* This shouldn't succeed because we don't have a server! */
        goto end;
    }

    len = BIO_get_mem_data(wbio, (char **)&data);
    if (!PACKET_buf_init(&pkt, data, len))
        goto end;

    /* Skip the record header */
    if (!PACKET_forward(&pkt, SSL3_RT_HEADER_LENGTH))
        goto end;

    msglen = PACKET_remaining(&pkt);

    /* Skip the handshake message header */
    if (!PACKET_forward(&pkt, SSL3_HM_HEADER_LENGTH))
        goto end;

    /* Skip client version and random */
    if (!PACKET_forward(&pkt, CLIENT_VERSION_LEN + SSL3_RANDOM_SIZE))
        goto end;

    /* Skip session id */
    if (!PACKET_get_length_prefixed_1(&pkt, &pkt2))
        goto end;

    /* Skip ciphers */
    if (!PACKET_get_length_prefixed_2(&pkt, &pkt2))
        goto end;

    /* Skip compression */
    if (!PACKET_get_length_prefixed_1(&pkt, &pkt2))
        goto end;

    /* Extensions len */
    if (!PACKET_as_length_prefixed_2(&pkt, &pkt2))
        goto end;

    /* Loop through all extensions */
    while (PACKET_remaining(&pkt2)) {

        if (!PACKET_get_net_2(&pkt2, &type) ||
            !PACKET_get_length_prefixed_2(&pkt2, &pkt3))
            goto end;

        if (type == TLSEXT_TYPE_session_ticket) {
            if (currtest == TEST_SET_SESSION_TICK_DATA_VER_NEG) {
                if (PACKET_equal(&pkt3, dummytick, strlen(dummytick))) {
                    /* Ticket data is as we expected */
                    testresult = 1;
                } else {
                    printf("Received session ticket is not as expected\n");
                }
                break;
            }
        }
        if (type == TLSEXT_TYPE_padding) {
            if (currtest == TEST_ADD_PADDING
                    || currtest == TEST_ADD_PADDING_AND_PSK)
                testresult = (msglen == F5_WORKAROUND_MAX_MSG_LEN);
            else
                testresult = 0;
        }
    }

end:
    SSL_free(con);
    SSL_CTX_free(ctx);
    SSL_SESSION_free(sess);
    BIO_free(sessbio);
    if (!testresult)
        printf("ClientHello test: FAILED (Test %d)\n", currtest);

    return testresult;
}

int test_main(int argc, char *argv[])
{
    if (argc != 2)
        return 0;

    sessionfile = argv[1];

    ADD_ALL_TESTS(test_client_hello, TOTAL_NUM_TESTS);

    return run_tests(argv[0]);
}

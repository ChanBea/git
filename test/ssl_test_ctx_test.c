/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Ideally, CONF should offer standard parsing methods and cover them
 * in tests. But since we have no CONF tests, we use a custom test for now.
 */

#include <stdio.h>
#include <string.h>

#include "e_os.h"
#include "ssl_test_ctx.h"
#include "testutil.h"
#include "test_main_custom.h"
#include <openssl/e_os2.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>

static CONF *conf = NULL;

typedef struct ssl_test_ctx_test_fixture {
    const char *test_case_name;
    const char *test_section;
    /* Expected parsed configuration. */
    SSL_TEST_CTX *expected_ctx;
} SSL_TEST_CTX_TEST_FIXTURE;


static int SSL_TEST_CLIENT_CONF_equal(SSL_TEST_CLIENT_CONF *client,
                                      SSL_TEST_CLIENT_CONF *client2)
{
    if (!TEST_int_eq(client->verify_callback, client2->verify_callback)) {
        TEST_info("ClientVerifyCallback mismatch: %s vs %s.",
                  ssl_verify_callback_name(client->verify_callback),
                  ssl_verify_callback_name(client2->verify_callback));
        return 0;
    }
    if (!TEST_int_eq(client->servername, client2->servername)) {
        TEST_info("ServerName mismatch: %s vs %s.",
                  ssl_servername_name(client->servername),
                  ssl_servername_name(client2->servername));
        return 0;
    }
    if (!TEST_str_eq(client->npn_protocols, client2->npn_protocols)) {
        TEST_info("Client NPNProtocols");
        return 0;
    }
    if (!TEST_str_eq(client->alpn_protocols, client2->alpn_protocols)) {
        TEST_info("Client ALPNProtocols");
        return 0;
    }
    if (!TEST_int_eq(client->ct_validation, client2->ct_validation)) {
        TEST_info("CTValidation mismatch: %s vs %s.",
                  ssl_ct_validation_name(client->ct_validation),
                  ssl_ct_validation_name(client2->ct_validation));
        return 0;
    }
    return 1;
}

static int SSL_TEST_SERVER_CONF_equal(SSL_TEST_SERVER_CONF *server,
                                      SSL_TEST_SERVER_CONF *server2)
{
    if (!TEST_int_eq(server->servername_callback,
                     server2->servername_callback)) {
        TEST_info("ServerNameCallback mismatch: %s vs %s.",
                  ssl_servername_callback_name(server->servername_callback),
                  ssl_servername_callback_name(server2->servername_callback));
        return 0;
    }
    if (!TEST_str_eq(server->npn_protocols, server2->npn_protocols)) {
        TEST_info("Server NPNProtocols");
        return 0;
    }
    if (!TEST_str_eq(server->alpn_protocols, server2->alpn_protocols)) {
        TEST_info("Server ALPNProtocols");
        return 0;
    }
    if (!TEST_int_eq(server->broken_session_ticket,
                     server2->broken_session_ticket)) {
        TEST_info("Broken session ticket mismatch: %d vs %d.",
                server->broken_session_ticket, server2->broken_session_ticket);
        return 0;
    }
    if (!TEST_int_eq(server->cert_status, server2->cert_status)) {
        TEST_info("CertStatus mismatch: %s vs %s.",
                  ssl_certstatus_name(server->cert_status),
                  ssl_certstatus_name(server2->cert_status));
        return 0;
    }
    return 1;
}

static int SSL_TEST_EXTRA_CONF_equal(SSL_TEST_EXTRA_CONF *extra,
                                     SSL_TEST_EXTRA_CONF *extra2)
{
    return SSL_TEST_CLIENT_CONF_equal(&extra->client, &extra2->client)
        && SSL_TEST_SERVER_CONF_equal(&extra->server, &extra2->server)
        && SSL_TEST_SERVER_CONF_equal(&extra->server2, &extra2->server2);
}

/* Returns 1 if the contexts are equal, 0 otherwise. */
static int SSL_TEST_CTX_equal(SSL_TEST_CTX *ctx, SSL_TEST_CTX *ctx2)
{
    if (!TEST_int_eq(ctx->method, ctx2->method)) {
        TEST_info("Method mismatch: %s vs %s.",
                  ssl_test_method_name(ctx->method),
                  ssl_test_method_name(ctx2->method));
        return 0;
    }
    if (!TEST_int_eq(ctx->handshake_mode, ctx2->handshake_mode)) {
        TEST_info("HandshakeMode mismatch: %s vs %s.",
                  ssl_handshake_mode_name(ctx->handshake_mode),
                  ssl_handshake_mode_name(ctx2->handshake_mode));
        return 0;
    }
    if (!TEST_int_eq(ctx->app_data_size, ctx2->app_data_size)) {
        TEST_info("ApplicationData mismatch: %d vs %d.",
                  ctx->app_data_size, ctx2->app_data_size);
        return 0;
    }

    if (!TEST_int_eq(ctx->max_fragment_size, ctx2->max_fragment_size)) {
        TEST_info("MaxFragmentSize mismatch: %d vs %d.",
                  ctx->max_fragment_size, ctx2->max_fragment_size);
        return 0;
    }

    if (!SSL_TEST_EXTRA_CONF_equal(&ctx->extra, &ctx2->extra)) {
        TEST_info("Extra conf mismatch.");
        return 0;
    }
    if (!SSL_TEST_EXTRA_CONF_equal(&ctx->resume_extra, &ctx2->resume_extra)) {
        TEST_info("Resume extra conf mismatch.");
        return 0;
    }

    if (!TEST_int_eq(ctx->expected_result, ctx2->expected_result)) {
        TEST_info("ExpectedResult mismatch: %s vs %s.",
                  ssl_test_result_name(ctx->expected_result),
                  ssl_test_result_name(ctx2->expected_result));
        return 0;
    }
    if (!TEST_int_eq(ctx->expected_client_alert, ctx2->expected_client_alert)) {
        TEST_info("ClientAlert mismatch: %s vs %s.",
                  ssl_alert_name(ctx->expected_client_alert),
                  ssl_alert_name(ctx2->expected_client_alert));
        return 0;
    }
    if (!TEST_int_eq(ctx->expected_server_alert, ctx2->expected_server_alert)) {
        TEST_info("ServerAlert mismatch: %s vs %s.",
                  ssl_alert_name(ctx->expected_server_alert),
                  ssl_alert_name(ctx2->expected_server_alert));
        return 0;
    }
    if (!TEST_int_eq(ctx->expected_protocol, ctx2->expected_protocol)) {
        TEST_info("ClientAlert mismatch: %s vs %s.",
                  ssl_protocol_name(ctx->expected_protocol),
                  ssl_protocol_name(ctx2->expected_protocol));
        return 0;
    }
    if (!TEST_int_eq(ctx->expected_servername, ctx2->expected_servername)) {
        TEST_info("ExpectedServerName mismatch: %s vs %s.",
                  ssl_servername_name(ctx->expected_servername),
                  ssl_servername_name(ctx2->expected_servername));
        return 0;
    }
    if (!TEST_int_eq(ctx->session_ticket_expected,
                     ctx2->session_ticket_expected)) {
        TEST_info("SessionTicketExpected mismatch: %s vs %s.",
                ssl_session_ticket_name(ctx->session_ticket_expected),
                ssl_session_ticket_name(ctx2->session_ticket_expected));
        return 0;
    }
    if (!TEST_int_eq(ctx->compression_expected, ctx2->compression_expected)) {
        TEST_info("ComrpessionExpected mismatch: %d vs %d.",
                  ctx->compression_expected,
                  ctx2->compression_expected);
        return 0;
    }
    if (!TEST_str_eq(ctx->expected_npn_protocol, ctx2->expected_npn_protocol)) {
        TEST_info("ExpectedNPNProtocol");
        return 0;
    }
    if (!TEST_str_eq(ctx->expected_alpn_protocol, ctx2->expected_alpn_protocol)) {
        TEST_info("ExpectedALPNProtocol");
        return 0;
    }
    if (!TEST_int_eq(ctx->resumption_expected, ctx2->resumption_expected)) {
        TEST_info("ResumptionExpected mismatch: %d vs %d.",
                  ctx->resumption_expected, ctx2->resumption_expected);
        return 0;
    }
    return 1;
}

static SSL_TEST_CTX_TEST_FIXTURE set_up(const char *const test_case_name)
{
    SSL_TEST_CTX_TEST_FIXTURE fixture;
    fixture.test_case_name = test_case_name;
    fixture.expected_ctx = SSL_TEST_CTX_new();
    TEST_check(fixture.expected_ctx != NULL);
    return fixture;
}

static int execute_test(SSL_TEST_CTX_TEST_FIXTURE fixture)
{
    int success = 0;

    SSL_TEST_CTX *ctx = SSL_TEST_CTX_create(conf, fixture.test_section);

    if (!TEST_ptr(ctx)) {
        TEST_info("Failed to parse good configuration %s.",
                  fixture.test_section);
        goto err;
    }

    if (!SSL_TEST_CTX_equal(ctx, fixture.expected_ctx))
        goto err;

    success = 1;
 err:
    SSL_TEST_CTX_free(ctx);
    return success;
}

static void tear_down(SSL_TEST_CTX_TEST_FIXTURE fixture)
{
    SSL_TEST_CTX_free(fixture.expected_ctx);
}

#define SETUP_SSL_TEST_CTX_TEST_FIXTURE()                       \
    SETUP_TEST_FIXTURE(SSL_TEST_CTX_TEST_FIXTURE, set_up)
#define EXECUTE_SSL_TEST_CTX_TEST()             \
    EXECUTE_TEST(execute_test, tear_down)

static int test_empty_configuration()
{
    SETUP_SSL_TEST_CTX_TEST_FIXTURE();
    fixture.test_section = "ssltest_default";
    fixture.expected_ctx->expected_result = SSL_TEST_SUCCESS;
    EXECUTE_SSL_TEST_CTX_TEST();
}

static int test_good_configuration()
{
    SETUP_SSL_TEST_CTX_TEST_FIXTURE();
    fixture.test_section = "ssltest_good";
    fixture.expected_ctx->method = SSL_TEST_METHOD_DTLS;
    fixture.expected_ctx->handshake_mode = SSL_TEST_HANDSHAKE_RESUME;
    fixture.expected_ctx->app_data_size = 1024;
    fixture.expected_ctx->max_fragment_size = 2048;

    fixture.expected_ctx->expected_result = SSL_TEST_SERVER_FAIL;
    fixture.expected_ctx->expected_client_alert = SSL_AD_UNKNOWN_CA;
    fixture.expected_ctx->expected_server_alert = 0;  /* No alert. */
    fixture.expected_ctx->expected_protocol = TLS1_1_VERSION;
    fixture.expected_ctx->expected_servername = SSL_TEST_SERVERNAME_SERVER2;
    fixture.expected_ctx->session_ticket_expected = SSL_TEST_SESSION_TICKET_YES;
    fixture.expected_ctx->compression_expected = SSL_TEST_COMPRESSION_NO;
    fixture.expected_ctx->resumption_expected = 1;

    fixture.expected_ctx->extra.client.verify_callback =
        SSL_TEST_VERIFY_REJECT_ALL;
    fixture.expected_ctx->extra.client.servername = SSL_TEST_SERVERNAME_SERVER2;
    fixture.expected_ctx->extra.client.npn_protocols =
        OPENSSL_strdup("foo,bar");
    TEST_check(fixture.expected_ctx->extra.client.npn_protocols != NULL);

    fixture.expected_ctx->extra.server.servername_callback =
        SSL_TEST_SERVERNAME_IGNORE_MISMATCH;
    fixture.expected_ctx->extra.server.broken_session_ticket = 1;

    fixture.expected_ctx->resume_extra.server2.alpn_protocols =
        OPENSSL_strdup("baz");
    TEST_check(
        fixture.expected_ctx->resume_extra.server2.alpn_protocols != NULL);

    fixture.expected_ctx->resume_extra.client.ct_validation =
        SSL_TEST_CT_VALIDATION_STRICT;

    EXECUTE_SSL_TEST_CTX_TEST();
}

static const char *bad_configurations[] = {
    "ssltest_unknown_option",
    "ssltest_wrong_section",
    "ssltest_unknown_expected_result",
    "ssltest_unknown_alert",
    "ssltest_unknown_protocol",
    "ssltest_unknown_verify_callback",
    "ssltest_unknown_servername",
    "ssltest_unknown_servername_callback",
    "ssltest_unknown_session_ticket_expected",
    "ssltest_unknown_compression_expected",
    "ssltest_unknown_method",
    "ssltest_unknown_handshake_mode",
    "ssltest_unknown_resumption_expected",
    "ssltest_unknown_ct_validation",
};

static int test_bad_configuration(int idx)
{
    SSL_TEST_CTX *ctx = SSL_TEST_CTX_create(conf, bad_configurations[idx]);

    if (!TEST_ptr_null(ctx)) {
        TEST_info("Parsing bad configuration %s succeeded.",
                  bad_configurations[idx]);
        SSL_TEST_CTX_free(ctx);
        return 0;
    }

    return 1;
}

int test_main(int argc, char **argv)
{
    int result = 0;

    if (argc != 2)
        return 1;

    conf = NCONF_new(NULL);
    TEST_check(conf != NULL);

    /* argv[1] should point to test/ssl_test_ctx_test.conf */
    TEST_check(NCONF_load(conf, argv[1], NULL) > 0);

    ADD_TEST(test_empty_configuration);
    ADD_TEST(test_good_configuration);
    ADD_ALL_TESTS(test_bad_configuration, OSSL_NELEM(bad_configurations));

    result = run_tests(argv[0]);

    NCONF_free(conf);

    return result;
}

/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/encoder.h>

/*
 * TODO: This include is to get OSSL_KEYMGMT_SELECT_*, which feels a bit
 * much just for those macros...  they might serve better as EVP macros.
 */
#include <openssl/core_dispatch.h>

#ifndef OPENSSL_NO_RC4
# define DEFAULT_PVK_ENCR_STRENGTH      2
#else
# define DEFAULT_PVK_ENCR_STRENGTH      0
#endif

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_ENGINE, OPT_IN, OPT_OUT,
    OPT_PUBIN, OPT_PUBOUT, OPT_PASSOUT, OPT_PASSIN,
    OPT_RSAPUBKEY_IN, OPT_RSAPUBKEY_OUT,
    /* Do not change the order here; see case statements below */
    OPT_PVK_NONE, OPT_PVK_WEAK, OPT_PVK_STRONG,
    OPT_NOOUT, OPT_TEXT, OPT_MODULUS, OPT_CHECK, OPT_CIPHER,
    OPT_PROV_ENUM, OPT_TRADITIONAL
} OPTION_CHOICE;

const OPTIONS rsa_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"check", OPT_CHECK, '-', "Verify key consistency"},
    {"", OPT_CIPHER, '-', "Any supported cipher"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif

    OPT_SECTION("Input"),
    {"in", OPT_IN, 's', "Input file"},
    {"inform", OPT_INFORM, 'f', "Input format (DER/PEM/P12/ENGINE"},
    {"pubin", OPT_PUBIN, '-', "Expect a public key in input file"},
    {"RSAPublicKey_in", OPT_RSAPUBKEY_IN, '-', "Input is an RSAPublicKey"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output file"},
    {"outform", OPT_OUTFORM, 'f', "Output format, one of DER PEM PVK"},
    {"pubout", OPT_PUBOUT, '-', "Output a public key"},
    {"RSAPublicKey_out", OPT_RSAPUBKEY_OUT, '-', "Output is an RSAPublicKey"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"noout", OPT_NOOUT, '-', "Don't print key out"},
    {"text", OPT_TEXT, '-', "Print the key in text"},
    {"modulus", OPT_MODULUS, '-', "Print the RSA key modulus"},
    {"traditional", OPT_TRADITIONAL, '-',
     "Use traditional format for private keys"},

#ifndef OPENSSL_NO_RC4
    OPT_SECTION("PVK"),
    {"pvk-strong", OPT_PVK_STRONG, '-', "Enable 'Strong' PVK encoding level (default)"},
    {"pvk-weak", OPT_PVK_WEAK, '-', "Enable 'Weak' PVK encoding level"},
    {"pvk-none", OPT_PVK_NONE, '-', "Don't enforce PVK encoding"},
#endif

    OPT_PROV_OPTIONS,
    {NULL}
};

int rsa_main(int argc, char **argv)
{
    ENGINE *e = NULL;
    BIO *out = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx;
    const EVP_CIPHER *enc = NULL;
    char *infile = NULL, *outfile = NULL, *prog;
    char *passin = NULL, *passout = NULL, *passinarg = NULL, *passoutarg = NULL;
    int private = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, text = 0, check = 0;
    int noout = 0, modulus = 0, pubin = 0, pubout = 0, ret = 1;
    int pvk_encr = DEFAULT_PVK_ENCR_STRENGTH;
    OPTION_CHOICE o;
    int traditional = 0;
    const char *output_type = NULL;
    const char *output_structure = NULL;
    int selection = 0;
    OSSL_ENCODER *encoder = NULL;

    prog = opt_init(argc, argv, rsa_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(rsa_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &outformat))
                goto opthelp;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_PASSOUT:
            passoutarg = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_PUBIN:
            pubin = 1;
            break;
        case OPT_PUBOUT:
            pubout = 1;
            break;
        case OPT_RSAPUBKEY_IN:
            pubin = 2;
            break;
        case OPT_RSAPUBKEY_OUT:
            pubout = 2;
            break;
        case OPT_PVK_STRONG:    /* pvk_encr:= 2 */
        case OPT_PVK_WEAK:      /* pvk_encr:= 1 */
        case OPT_PVK_NONE:      /* pvk_encr:= 0 */
            pvk_encr = (o - OPT_PVK_NONE);
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_MODULUS:
            modulus = 1;
            break;
        case OPT_CHECK:
            check = 1;
            break;
        case OPT_CIPHER:
            if (!opt_cipher(opt_unknown(), &enc))
                goto opthelp;
            break;
        case OPT_PROV_CASES:
            if (!opt_provider(o))
                goto end;
            break;
        case OPT_TRADITIONAL:
            traditional = 1;
            break;
        }
    }

    /* No extra arguments. */
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    private = (text && !pubin) || (!pubout && !noout) ? 1 : 0;

    if (!app_passwd(passinarg, passoutarg, &passin, &passout)) {
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }
    if (check && pubin) {
        BIO_printf(bio_err, "Only private keys can be checked\n");
        goto end;
    }

    if (pubin) {
        int tmpformat = -1;

        if (pubin == 2) {
            if (informat == FORMAT_PEM)
                tmpformat = FORMAT_PEMRSA;
            else if (informat == FORMAT_ASN1)
                tmpformat = FORMAT_ASN1RSA;
        } else {
            tmpformat = informat;
        }

        pkey = load_pubkey(infile, tmpformat, 1, passin, e, "public key");
    } else {
        pkey = load_key(infile, informat, 1, passin, e, "private key");
    }

    if (pkey == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }
    if (!EVP_PKEY_is_a(pkey, "RSA")) {
        BIO_printf(bio_err, "Not an RSA key\n");
        goto end;
    }

    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL)
        goto end;

    if (text) {
        assert(pubin || private);
        if ((pubin && EVP_PKEY_print_public(out, pkey, 0, NULL) <= 0)
            || (!pubin && EVP_PKEY_print_private(out, pkey, 0, NULL) <= 0)) {
            perror(outfile);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (modulus) {
        BIGNUM *n = NULL;

        /* Every RSA key has an 'n' */
        EVP_PKEY_get_bn_param(pkey, "n", &n);
        BIO_printf(out, "Modulus=");
        BN_print(out, n);
        BIO_printf(out, "\n");
        BN_free(n);
    }

    if (check) {
        int r;

        pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (pctx == NULL) {
            BIO_printf(out, "RSA unable to create PKEY context\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        r = EVP_PKEY_check(pctx);
        EVP_PKEY_CTX_free(pctx);

        if (r == 1) {
            BIO_printf(out, "RSA key ok\n");
        } else if (r == 0) {
            unsigned long err;

            while ((err = ERR_peek_error()) != 0 &&
                   ERR_GET_LIB(err) == ERR_LIB_RSA &&
                   ERR_GET_REASON(err) != ERR_R_MALLOC_FAILURE) {
                BIO_printf(out, "RSA key error: %s\n",
                           ERR_reason_error_string(err));
                ERR_get_error(); /* remove err from error stack */
            }
        } else if (r == -1) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (noout) {
        ret = 0;
        goto end;
    }
    BIO_printf(bio_err, "writing RSA key\n");

    /* Choose output type for the format */
    if (outformat == FORMAT_ASN1) {
        output_type = "DER";
    } else if (outformat == FORMAT_PEM) {
        output_type = "PEM";
    } else if (outformat == FORMAT_MSBLOB) {
        output_type = "MSBLOB";
    } else if (outformat == FORMAT_PVK) {
        if (pubin) {
            BIO_printf(bio_err, "PVK form impossible with public key input\n");
            goto end;
        }
        output_type = "PVK";
    } else {
        BIO_printf(bio_err, "bad output format specified for outfile\n");
        goto end;
    }

    /* Select what you want in the output */
    if (pubout || pubin) {
        selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    } else {
        assert(private);
        selection = (OSSL_KEYMGMT_SELECT_KEYPAIR
                     | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS);
    }

    /* For DER based output, select the desired output structure */
    if (outformat == FORMAT_ASN1 || outformat == FORMAT_PEM) {
        if (pubout || pubin) {
            if (pubout == 2)
                output_structure = "pkcs1"; /* "type-specific" would work too */
            else
                output_structure = "SubjectPublicKeyInfo";
        } else {
            assert(private);
            if (traditional)
                output_structure = "pkcs1"; /* "type-specific" would work too */
            else
                output_structure = "pkcs8";
        }
    }

    /* Now, perform the encoding */
    encoder = OSSL_ENCODER_new_by_EVP_PKEY(pkey, selection, output_type,
                                           output_structure, NULL);
    if (OSSL_ENCODER_get_num_methods(encoder) == 0) {
        BIO_printf(bio_err, "%s format not supported\n", output_type);
        goto end;
    }

    /* PVK is a bit special... */
    if (outformat == FORMAT_PVK) {
        OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

        params[0] = OSSL_PARAM_construct_int("encrypt-level", &pvk_encr);
        if (!OSSL_ENCODER_set_params(encoder, params)) {
            BIO_printf(bio_err, "invalid PVK encryption level\n");
            goto end;
        }
    }

    if (!OSSL_ENCODER_to_bio(encoder, out)) {
        BIO_printf(bio_err, "unable to write key\n");
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
 end:
    OSSL_ENCODER_free(encoder);
    release_engine(e);
    BIO_free_all(out);
    EVP_PKEY_free(pkey);
    OPENSSL_free(passin);
    OPENSSL_free(passout);
    return ret;
}

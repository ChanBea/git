/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/lhash.h>
#include <openssl/rsa.h>
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif

#define BITS               "default_bits"
#define KEYFILE            "default_keyfile"
#define PROMPT             "prompt"
#define DISTINGUISHED_NAME "distinguished_name"
#define ATTRIBUTES         "attributes"
#define V3_EXTENSIONS      "x509_extensions"
#define REQ_EXTENSIONS     "req_extensions"
#define STRING_MASK        "string_mask"
#define UTF8_IN            "utf8"

#define DEFAULT_KEY_LENGTH 2048
#define MIN_KEY_LENGTH     512
#define DEFAULT_DAYS       30 /* default cert validity period in days */
#define UNSET_DAYS         -2 /* -1 may be used for testing expiration checks */
#define EXT_COPY_UNSET     -1

static int make_REQ(X509_REQ *req, EVP_PKEY *pkey, X509_NAME *fsubj,
                    int mutlirdn, int attribs, unsigned long chtype);
static int prompt_info(X509_REQ *req,
                       STACK_OF(CONF_VALUE) *dn_sk, const char *dn_sect,
                       STACK_OF(CONF_VALUE) *attr_sk, const char *attr_sect,
                       int attribs, unsigned long chtype);
static int auto_info(X509_REQ *req, STACK_OF(CONF_VALUE) *sk,
                     STACK_OF(CONF_VALUE) *attr, int attribs,
                     unsigned long chtype);
static int add_attribute_object(X509_REQ *req, char *text, const char *def,
                                char *value, int nid, int n_min, int n_max,
                                unsigned long chtype);
static int add_DN_object(X509_NAME *n, char *text, const char *def,
                         char *value, int nid, int n_min, int n_max,
                         unsigned long chtype, int mval);
static int genpkey_cb(EVP_PKEY_CTX *ctx);
static int build_data(char *text, const char *def, char *value,
                      int n_min, int n_max, char *buf, const int buf_size,
                      const char *desc1, const char *desc2);
static int req_check_len(int len, int n_min, int n_max);
static int check_end(const char *str, const char *end);
static int join(char buf[], size_t buf_size, const char *name,
                const char *tail, const char *desc);
static EVP_PKEY_CTX *set_keygen_ctx(const char *gstr,
                                    int *pkey_type, long *pkeylen,
                                    char **palgnam, ENGINE *keygen_engine);

static const char *section = "req";
static CONF *req_conf = NULL;
static CONF *addext_conf = NULL;
static int batch = 0;

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_ENGINE, OPT_KEYGEN_ENGINE, OPT_KEY,
    OPT_PUBKEY, OPT_NEW, OPT_CONFIG, OPT_KEYFORM, OPT_IN, OPT_OUT,
    OPT_KEYOUT, OPT_PASSIN, OPT_PASSOUT, OPT_NEWKEY,
    OPT_PKEYOPT, OPT_SIGOPT, OPT_VFYOPT, OPT_BATCH, OPT_NEWHDR, OPT_MODULUS,
    OPT_VERIFY, OPT_NOENC, OPT_NODES, OPT_NOOUT, OPT_VERBOSE, OPT_UTF8,
    OPT_NAMEOPT, OPT_REQOPT, OPT_SUBJ, OPT_SUBJECT, OPT_TEXT, OPT_X509,
    OPT_CA, OPT_CAKEY,
    OPT_MULTIVALUE_RDN, OPT_DAYS, OPT_SET_SERIAL,
    OPT_COPY_EXTENSIONS, OPT_ADDEXT, OPT_EXTENSIONS,
    OPT_REQEXTS, OPT_PRECERT, OPT_MD,
    OPT_SECTION,
    OPT_R_ENUM, OPT_PROV_ENUM
} OPTION_CHOICE;

const OPTIONS req_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
    {"keygen_engine", OPT_KEYGEN_ENGINE, 's',
     "Specify engine to be used for key generation operations"},
#endif
    {"in", OPT_IN, '<', "X.509 request input file"},
    {"inform", OPT_INFORM, 'F', "Input format - DER or PEM"},
    {"verify", OPT_VERIFY, '-', "Verify self-signature on the request"},

    OPT_SECTION("Certificate"),
    {"new", OPT_NEW, '-', "New request"},
    {"config", OPT_CONFIG, '<', "Request template file"},
    {"section", OPT_SECTION, 's', "Config section to use (default \"req\")"},
    {"utf8", OPT_UTF8, '-', "Input characters are UTF8 (default ASCII)"},
    {"nameopt", OPT_NAMEOPT, 's', "Certificate subject/issuer name printing options"},
    {"reqopt", OPT_REQOPT, 's', "Various request text options"},
    {"text", OPT_TEXT, '-', "Text form of request"},
    {"x509", OPT_X509, '-',
     "Output an x509 structure instead of a cert request"},
    {"CA", OPT_CA, '<', "Issuer certificate to use with -x509"},
    {"CAkey", OPT_CAKEY, 's',
     "Issuer private key to use with -x509; default is -CA arg"},
    {OPT_MORE_STR, 1, 1, "(Required by some CA's)"},
    {"subj", OPT_SUBJ, 's', "Set or modify subject of request or cert"},
    {"subject", OPT_SUBJECT, '-',
     "Print the subject of the output request or cert"},
    {"multivalue-rdn", OPT_MULTIVALUE_RDN, '-',
     "Deprecated; multi-valued RDNs support is always on."},
    {"days", OPT_DAYS, 'p', "Number of days cert is valid for"},
    {"set_serial", OPT_SET_SERIAL, 's', "Serial number to use"},
    {"copy_extensions", OPT_COPY_EXTENSIONS, 's',
     "copy extensions from request when using -x509"},
    {"addext", OPT_ADDEXT, 's',
     "Additional cert extension key=value pair (may be given more than once)"},
    {"extensions", OPT_EXTENSIONS, 's',
     "Cert extension section (override value in config file)"},
    {"reqexts", OPT_REQEXTS, 's',
     "Request extension section (override value in config file)"},
    {"precert", OPT_PRECERT, '-', "Add a poison extension (implies -new)"},

    OPT_SECTION("Keys and Signing"),
    {"key", OPT_KEY, 's', "Private key to use"},
    {"keyform", OPT_KEYFORM, 'f', "Key file format (ENGINE, other values ignored)"},
    {"pubkey", OPT_PUBKEY, '-', "Output public key"},
    {"keyout", OPT_KEYOUT, '>', "File to save newly created private key"},
    {"passin", OPT_PASSIN, 's', "Private key and certificate password source"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"newkey", OPT_NEWKEY, 's', "Specify as type:bits"},
    {"pkeyopt", OPT_PKEYOPT, 's', "Public key options as opt:value"},
    {"sigopt", OPT_SIGOPT, 's', "Signature parameter in n:v form"},
    {"vfyopt", OPT_VFYOPT, 's', "Verification parameter in n:v form"},
    {"", OPT_MD, '-', "Any supported digest"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output file"},
    {"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
    {"batch", OPT_BATCH, '-',
     "Do not ask anything during request generation"},
    {"verbose", OPT_VERBOSE, '-', "Verbose output"},
    {"noenc", OPT_NOENC, '-', "Don't encrypt private keys"},
    {"nodes", OPT_NODES, '-', "Don't encrypt private keys; deprecated"},
    {"noout", OPT_NOOUT, '-', "Do not output REQ"},
    {"newhdr", OPT_NEWHDR, '-', "Output \"NEW\" in the header lines"},
    {"modulus", OPT_MODULUS, '-', "RSA modulus"},

    OPT_R_OPTIONS,
    OPT_PROV_OPTIONS,
    {NULL}
};

/*
 * An LHASH of strings, where each string is an extension name.
 */
static unsigned long ext_name_hash(const OPENSSL_STRING *a)
{
    return OPENSSL_LH_strhash((const char *)a);
}

static int ext_name_cmp(const OPENSSL_STRING *a, const OPENSSL_STRING *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static void exts_cleanup(OPENSSL_STRING *x)
{
    OPENSSL_free((char *)x);
}

/*
 * Is the |kv| key already duplicated? This is remarkably tricky to get right.
 * Return 0 if unique, -1 on runtime error; 1 if found or a syntax error.
 */
static int duplicated(LHASH_OF(OPENSSL_STRING) *addexts, char *kv)
{
    char *p;
    size_t off;

    /* Check syntax. */
    /* Skip leading whitespace, make a copy. */
    while (*kv && isspace(*kv))
        if (*++kv == '\0')
            return 1;
    if ((p = strchr(kv, '=')) == NULL)
        return 1;
    off = p - kv;
    if ((kv = OPENSSL_strdup(kv)) == NULL)
        return -1;

    /* Skip trailing space before the equal sign. */
    for (p = kv + off; p > kv; --p)
        if (!isspace(p[-1]))
            break;
    if (p == kv) {
        OPENSSL_free(kv);
        return 1;
    }
    *p = '\0';

    /* Finally have a clean "key"; see if it's there [by attempt to add it]. */
    p = (char *)lh_OPENSSL_STRING_insert(addexts, (OPENSSL_STRING *)kv);
    if (p != NULL) {
        OPENSSL_free(p);
        return 1;
    } else if (lh_OPENSSL_STRING_error(addexts)) {
        OPENSSL_free(kv);
        return -1;
    }

    return 0;
}

int req_main(int argc, char **argv)
{
    ASN1_INTEGER *serial = NULL;
    BIO *out = NULL;
    ENGINE *e = NULL, *gen_eng = NULL;
    EVP_PKEY *pkey = NULL, *CAkey = NULL;
    EVP_PKEY_CTX *genctx = NULL;
    STACK_OF(OPENSSL_STRING) *pkeyopts = NULL, *sigopts = NULL, *vfyopts = NULL;
    LHASH_OF(OPENSSL_STRING) *addexts = NULL;
    X509 *new_x509 = NULL, *CAcert = NULL;
    X509_REQ *req = NULL;
    const EVP_CIPHER *cipher = NULL;
    const EVP_MD *md_alg = NULL, *digest = NULL;
    int ext_copy = EXT_COPY_UNSET;
    BIO *addext_bio = NULL;
    char *extensions = NULL;
    const char *infile = NULL, *CAfile = NULL, *CAkeyfile = NULL;
    char *outfile = NULL, *keyfile = NULL;
    char *keyalgstr = NULL, *p, *prog, *passargin = NULL, *passargout = NULL;
    char *passin = NULL, *passout = NULL;
    char *nofree_passin = NULL, *nofree_passout = NULL;
    char *req_exts = NULL, *subj = NULL;
    X509_NAME *fsubj = NULL;
    char *template = default_config_file, *keyout = NULL;
    const char *keyalg = NULL;
    OPTION_CHOICE o;
    int days = UNSET_DAYS;
    int ret = 1, gen_x509 = 0, i = 0, newreq = 0, verbose = 0;
    int pkey_type = -1;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, keyform = FORMAT_PEM;
    int modulus = 0, multirdn = 1, verify = 0, noout = 0, text = 0;
    int noenc = 0, newhdr = 0, subject = 0, pubkey = 0, precert = 0;
    long newkey_len = -1;
    unsigned long chtype = MBSTRING_ASC, reqflag = 0;

#ifndef OPENSSL_NO_DES
    cipher = EVP_des_ede3_cbc();
#endif

    prog = opt_init(argc, argv, req_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(req_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
                goto opthelp;
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_KEYGEN_ENGINE:
#ifndef OPENSSL_NO_ENGINE
            gen_eng = setup_engine(opt_arg(), 0);
            if (gen_eng == NULL) {
                BIO_printf(bio_err, "Can't find keygen engine %s\n", *argv);
                goto opthelp;
            }
#endif
            break;
        case OPT_KEY:
            keyfile = opt_arg();
            break;
        case OPT_PUBKEY:
            pubkey = 1;
            break;
        case OPT_NEW:
            newreq = 1;
            break;
        case OPT_CONFIG:
            template = opt_arg();
            break;
        case OPT_SECTION:
            section = opt_arg();
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyform))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_KEYOUT:
            keyout = opt_arg();
            break;
        case OPT_PASSIN:
            passargin = opt_arg();
            break;
        case OPT_PASSOUT:
            passargout = opt_arg();
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        case OPT_PROV_CASES:
            if (!opt_provider(o))
                goto end;
            break;
        case OPT_NEWKEY:
            keyalg = opt_arg();
            newreq = 1;
            break;
        case OPT_PKEYOPT:
            if (pkeyopts == NULL)
                pkeyopts = sk_OPENSSL_STRING_new_null();
            if (pkeyopts == NULL
                    || !sk_OPENSSL_STRING_push(pkeyopts, opt_arg()))
                goto opthelp;
            break;
        case OPT_SIGOPT:
            if (!sigopts)
                sigopts = sk_OPENSSL_STRING_new_null();
            if (!sigopts || !sk_OPENSSL_STRING_push(sigopts, opt_arg()))
                goto opthelp;
            break;
        case OPT_VFYOPT:
            if (!vfyopts)
                vfyopts = sk_OPENSSL_STRING_new_null();
            if (!vfyopts || !sk_OPENSSL_STRING_push(vfyopts, opt_arg()))
                goto opthelp;
            break;
        case OPT_BATCH:
            batch = 1;
            break;
        case OPT_NEWHDR:
            newhdr = 1;
            break;
        case OPT_MODULUS:
            modulus = 1;
            break;
        case OPT_VERIFY:
            verify = 1;
            break;
        case OPT_NODES:
        case OPT_NOENC:
            noenc = 1;
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_UTF8:
            chtype = MBSTRING_UTF8;
            break;
        case OPT_NAMEOPT:
            if (!set_nameopt(opt_arg()))
                goto opthelp;
            break;
        case OPT_REQOPT:
            if (!set_cert_ex(&reqflag, opt_arg()))
                goto opthelp;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_X509:
            gen_x509 = 1;
            break;
        case OPT_CA:
            CAfile = opt_arg();
            break;
        case OPT_CAKEY:
            CAkeyfile = opt_arg();
            break;
        case OPT_DAYS:
            days = atoi(opt_arg());
            if (days < -1) {
                BIO_printf(bio_err, "%s: -days parameter arg must be >= -1\n",
                           prog);
                goto end;
            }
            break;
        case OPT_SET_SERIAL:
            if (serial != NULL) {
                BIO_printf(bio_err, "Serial number supplied twice\n");
                goto opthelp;
            }
            serial = s2i_ASN1_INTEGER(NULL, opt_arg());
            if (serial == NULL)
                goto opthelp;
            break;
        case OPT_SUBJECT:
            subject = 1;
            break;
        case OPT_SUBJ:
            subj = opt_arg();
            break;
        case OPT_MULTIVALUE_RDN:
            /* obsolete */
            break;
        case OPT_COPY_EXTENSIONS:
            if (!set_ext_copy(&ext_copy, opt_arg())) {
                BIO_printf(bio_err, "Invalid extension copy option: \"%s\"\n",
                           opt_arg());
                goto end;
            }
            break;
        case OPT_ADDEXT:
            p = opt_arg();
            if (addexts == NULL) {
                addexts = lh_OPENSSL_STRING_new(ext_name_hash, ext_name_cmp);
                addext_bio = BIO_new(BIO_s_mem());
                if (addexts == NULL || addext_bio == NULL)
                    goto end;
            }
            i = duplicated(addexts, p);
            if (i == 1) {
                BIO_printf(bio_err, "Duplicate extension: %s\n", p);
                goto opthelp;
            }
            if (i < 0 || BIO_printf(addext_bio, "%s\n", p) < 0)
                goto end;
            break;
        case OPT_EXTENSIONS:
            extensions = opt_arg();
            break;
        case OPT_REQEXTS:
            req_exts = opt_arg();
            break;
        case OPT_PRECERT:
            newreq = precert = 1;
            break;
        case OPT_MD:
            if (!opt_md(opt_unknown(), &md_alg))
                goto opthelp;
            digest = md_alg;
            break;
        }
    }

    /* No extra arguments. */
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (!gen_x509) {
        if (days != UNSET_DAYS)
            BIO_printf(bio_err, "Ignoring -days without -x509; not generating a certificate\n");
        if (ext_copy == EXT_COPY_NONE)
            BIO_printf(bio_err, "Ignoring -copy_extensions 'none' when -x509 is not given\n");
    }
    if (gen_x509 && infile == NULL)
        newreq = 1;

    if (!app_passwd(passargin, passargout, &passin, &passout)) {
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }

    if ((req_conf = app_load_config_verbose(template, verbose)) == NULL)
        goto end;
    if (addext_bio != NULL) {
        if (verbose)
            BIO_printf(bio_err,
                       "Using additional configuration from -addext options\n");
        if ((addext_conf = app_load_config_bio(addext_bio, NULL)) == NULL)
            goto end;
    }
    if (template != default_config_file && !app_load_modules(req_conf))
        goto end;

    if (req_conf != NULL) {
        p = NCONF_get_string(req_conf, NULL, "oid_file");
        if (p == NULL)
            ERR_clear_error();
        if (p != NULL) {
            BIO *oid_bio;

            oid_bio = BIO_new_file(p, "r");
            if (oid_bio == NULL) {
                if (verbose) {
                    BIO_printf(bio_err,
                               "Problems opening '%s' for extra OIDs\n", p);
                    ERR_print_errors(bio_err);
                }
            } else {
                OBJ_create_objects(oid_bio);
                BIO_free(oid_bio);
            }
        }
    }
    if (!add_oid_section(req_conf))
        goto end;

    if (md_alg == NULL) {
        p = NCONF_get_string(req_conf, section, "default_md");
        if (p == NULL) {
            ERR_clear_error();
        } else {
            if (!opt_md(p, &md_alg))
                goto opthelp;
            digest = md_alg;
        }
    }

    if (extensions == NULL) {
        extensions = NCONF_get_string(req_conf, section, V3_EXTENSIONS);
        if (extensions == NULL)
            ERR_clear_error();
    }
    if (extensions != NULL) {
        /* Check syntax of file */
        X509V3_CTX ctx;

        X509V3_set_ctx_test(&ctx);
        X509V3_set_nconf(&ctx, req_conf);
        if (!X509V3_EXT_add_nconf(req_conf, &ctx, extensions, NULL)) {
            BIO_printf(bio_err,
                       "Error checking x509 extension section %s\n",
                       extensions);
            goto end;
        }
    }
    if (addext_conf != NULL) {
        /* Check syntax of command line extensions */
        X509V3_CTX ctx;

        X509V3_set_ctx_test(&ctx);
        X509V3_set_nconf(&ctx, addext_conf);
        if (!X509V3_EXT_add_nconf(addext_conf, &ctx, "default", NULL)) {
            BIO_printf(bio_err, "Error checking extensions defined using -addext\n");
            goto end;
        }
    }

    if (passin == NULL) {
        passin = nofree_passin =
            NCONF_get_string(req_conf, section, "input_password");
        if (passin == NULL)
            ERR_clear_error();
    }

    if (passout == NULL) {
        passout = nofree_passout =
            NCONF_get_string(req_conf, section, "output_password");
        if (passout == NULL)
            ERR_clear_error();
    }

    p = NCONF_get_string(req_conf, section, STRING_MASK);
    if (p == NULL)
        ERR_clear_error();

    if (p != NULL && !ASN1_STRING_set_default_mask_asc(p)) {
        BIO_printf(bio_err, "Invalid global string mask setting %s\n", p);
        goto end;
    }

    if (chtype != MBSTRING_UTF8) {
        p = NCONF_get_string(req_conf, section, UTF8_IN);
        if (p == NULL)
            ERR_clear_error();
        else if (strcmp(p, "yes") == 0)
            chtype = MBSTRING_UTF8;
    }

    if (req_exts == NULL) {
        req_exts = NCONF_get_string(req_conf, section, REQ_EXTENSIONS);
        if (req_exts == NULL)
            ERR_clear_error();
    }
    if (req_exts != NULL) {
        /* Check syntax of file */
        X509V3_CTX ctx;

        X509V3_set_ctx_test(&ctx);
        X509V3_set_nconf(&ctx, req_conf);
        if (!X509V3_EXT_add_nconf(req_conf, &ctx, req_exts, NULL)) {
            BIO_printf(bio_err,
                       "Error checking request extension section %s\n",
                       req_exts);
            goto end;
        }
    }

    if (keyfile != NULL) {
        pkey = load_key(keyfile, keyform, 0, passin, e, "private key");
        if (pkey == NULL)
            goto end;
        app_RAND_load_conf(req_conf, section);
    }

    if (newreq && pkey == NULL) {
        app_RAND_load_conf(req_conf, section);

        if (!NCONF_get_number(req_conf, section, BITS, &newkey_len)) {
            newkey_len = DEFAULT_KEY_LENGTH;
        }

        if (keyalg != NULL) {
            genctx = set_keygen_ctx(keyalg, &pkey_type, &newkey_len,
                                    &keyalgstr, gen_eng);
            if (genctx == NULL)
                goto end;
        }

        if (newkey_len < MIN_KEY_LENGTH
            && (pkey_type == EVP_PKEY_RSA || pkey_type == EVP_PKEY_DSA)) {
            BIO_printf(bio_err, "Private key length is too short,\n");
            BIO_printf(bio_err, "it needs to be at least %d bits, not %ld.\n",
                       MIN_KEY_LENGTH, newkey_len);
            goto end;
        }

        if (pkey_type == EVP_PKEY_RSA
                && newkey_len > OPENSSL_RSA_MAX_MODULUS_BITS)
            BIO_printf(bio_err,
                       "Warning: It is not recommended to use more than %d bit for RSA keys.\n"
                       "         Your key size is %ld! Larger key size may behave not as expected.\n",
                       OPENSSL_RSA_MAX_MODULUS_BITS, newkey_len);

#ifndef OPENSSL_NO_DSA
        if (pkey_type == EVP_PKEY_DSA
                && newkey_len > OPENSSL_DSA_MAX_MODULUS_BITS)
            BIO_printf(bio_err,
                       "Warning: It is not recommended to use more than %d bit for DSA keys.\n"
                       "         Your key size is %ld! Larger key size may behave not as expected.\n",
                       OPENSSL_DSA_MAX_MODULUS_BITS, newkey_len);
#endif

        if (genctx == NULL) {
            genctx = set_keygen_ctx(NULL, &pkey_type, &newkey_len,
                                    &keyalgstr, gen_eng);
            if (genctx == NULL)
                goto end;
        }

        if (pkeyopts != NULL) {
            char *genopt;
            for (i = 0; i < sk_OPENSSL_STRING_num(pkeyopts); i++) {
                genopt = sk_OPENSSL_STRING_value(pkeyopts, i);
                if (pkey_ctrl_string(genctx, genopt) <= 0) {
                    BIO_printf(bio_err, "Key parameter error \"%s\"\n", genopt);
                    goto end;
                }
            }
        }

        if (pkey_type == EVP_PKEY_EC) {
            BIO_printf(bio_err, "Generating an EC private key\n");
        } else {
            BIO_printf(bio_err, "Generating a %s private key\n", keyalgstr);
        }

        EVP_PKEY_CTX_set_cb(genctx, genpkey_cb);
        EVP_PKEY_CTX_set_app_data(genctx, bio_err);

        if (EVP_PKEY_keygen(genctx, &pkey) <= 0) {
            BIO_puts(bio_err, "Error generating key\n");
            goto end;
        }

        EVP_PKEY_CTX_free(genctx);
        genctx = NULL;

        if (keyout == NULL) {
            keyout = NCONF_get_string(req_conf, section, KEYFILE);
            if (keyout == NULL)
                ERR_clear_error();
        }

        if (keyout == NULL)
            BIO_printf(bio_err, "Writing new private key to stdout\n");
        else
            BIO_printf(bio_err, "Writing new private key to '%s'\n", keyout);
        out = bio_open_owner(keyout, outformat, newreq);
        if (out == NULL)
            goto end;

        p = NCONF_get_string(req_conf, section, "encrypt_rsa_key");
        if (p == NULL) {
            ERR_clear_error();
            p = NCONF_get_string(req_conf, section, "encrypt_key");
            if (p == NULL)
                ERR_clear_error();
        }
        if ((p != NULL) && (strcmp(p, "no") == 0))
            cipher = NULL;
        if (noenc)
            cipher = NULL;

        i = 0;
 loop:
        assert(newreq);
        if (!PEM_write_bio_PrivateKey(out, pkey, cipher,
                                      NULL, 0, NULL, passout)) {
            if ((ERR_GET_REASON(ERR_peek_error()) ==
                 PEM_R_PROBLEMS_GETTING_PASSWORD) && (i < 3)) {
                ERR_clear_error();
                i++;
                goto loop;
            }
            goto end;
        }
        BIO_free(out);
        out = NULL;
        BIO_printf(bio_err, "-----\n");
    }

    /*
     * subj is expected to be in the format /type0=value0/type1=value1/type2=...
     * where characters may be escaped by \
     */
    if (subj != NULL
            && (fsubj = parse_name(subj, chtype, multirdn, "subject")) == NULL)
        goto end;

    if (!newreq) {
        req = load_csr(infile, informat, "X509 request");
        if (req == NULL)
            goto end;
    }

    if (CAkeyfile == NULL)
        CAkeyfile = CAfile;
    if (CAkeyfile != NULL) {
        if (CAfile == NULL) {
            BIO_printf(bio_err,
                       "Ignoring -CAkey option since no -CA option is given\n");
        } else {
            if ((CAkey = load_key(CAkeyfile, FORMAT_PEM,
                                  0, passin, e, "issuer private key")) == NULL)
                goto end;
        }
    }
    if (CAfile != NULL) {
        if (!gen_x509) {
            BIO_printf(bio_err,
                       "Warning: Ignoring -CA option without -x509\n");
        } else {
            if (CAkeyfile == NULL) {
                BIO_printf(bio_err,
                           "Need to give the -CAkey option if using -CA\n");
                goto end;
            }
            if ((CAcert = load_cert_pass(CAfile, 1, passin,
                                         "issuer certificate")) == NULL)
                goto end;
            if (!X509_check_private_key(CAcert, CAkey)) {
                BIO_printf(bio_err,
                           "Issuer certificate and key do not match\n");
                goto end;
            }
        }
    }
    if (newreq || gen_x509) {
        if (pkey == NULL /* can happen only if !newreq */) {
            BIO_printf(bio_err, "Must provide a signature key using -key\n");
            goto end;
        }

        if (req == NULL) {
            req = X509_REQ_new();
            if (req == NULL) {
                goto end;
            }

            if (!make_REQ(req, pkey, fsubj, multirdn, !gen_x509, chtype)){
                BIO_printf(bio_err, "Error making certificate request\n");
                goto end;
            }
        }
        if (gen_x509) {
            EVP_PKEY *pub_key = X509_REQ_get0_pubkey(req);
            X509V3_CTX ext_ctx;
            X509_NAME *issuer = CAcert != NULL ? X509_get_subject_name(CAcert) :
                X509_REQ_get_subject_name(req);
            X509_NAME *n_subj = fsubj != NULL ? fsubj :
                X509_REQ_get_subject_name(req);

            if ((new_x509 = X509_new_ex(app_get0_libctx(),
                                        app_get0_propq())) == NULL)
                goto end;

            if (serial != NULL) {
                if (!X509_set_serialNumber(new_x509, serial))
                    goto end;
            } else {
                if (!rand_serial(NULL, X509_get_serialNumber(new_x509)))
                    goto end;
            }

            if (!X509_set_issuer_name(new_x509, issuer))
                goto end;
            if (days == UNSET_DAYS) {
                days = DEFAULT_DAYS;
            }
            if (!set_cert_times(new_x509, NULL, NULL, days))
                goto end;
            if (!X509_set_subject_name(new_x509, n_subj))
                goto end;
            if (!pub_key || !X509_set_pubkey(new_x509, pub_key))
                goto end;
            if (ext_copy == EXT_COPY_UNSET) {
                BIO_printf(bio_err, "Warning: No -copy_extensions given; ignoring any extensions in the request\n");
            } else if (!copy_extensions(new_x509, req, ext_copy)) {
                BIO_printf(bio_err, "Error copying extensions from request\n");
                goto end;
            }

            /* Set up V3 context struct */
            X509V3_set_ctx(&ext_ctx, CAcert != NULL ? CAcert : new_x509,
                           new_x509, NULL, NULL, X509V3_CTX_REPLACE);
            if (CAcert == NULL) { /* self-issued, possibly self-signed */
                if (!X509V3_set_issuer_pkey(&ext_ctx, pkey)) /* prepare right AKID */
                    goto end;
                ERR_set_mark();
                if (!X509_check_private_key(new_x509, pkey))
                    BIO_printf(bio_err,
                               "Warning: Signature key and public key of cert do not match\n");
                ERR_pop_to_mark();
            }
            X509V3_set_nconf(&ext_ctx, req_conf);

            /* Add extensions */
            if (extensions != NULL
                    && !X509V3_EXT_add_nconf(req_conf, &ext_ctx, extensions,
                                             new_x509)) {
                BIO_printf(bio_err, "Error adding x509 extensions from section %s\n",
                           extensions);
                goto end;
            }
            if (addext_conf != NULL
                && !X509V3_EXT_add_nconf(addext_conf, &ext_ctx, "default",
                                         new_x509)) {
                BIO_printf(bio_err, "Error adding extensions defined via -addext\n");
                goto end;
            }

            /* If a pre-cert was requested, we need to add a poison extension */
            if (precert) {
                if (X509_add1_ext_i2d(new_x509, NID_ct_precert_poison,
                                      NULL, 1, 0) != 1) {
                    BIO_printf(bio_err, "Error adding poison extension\n");
                    goto end;
                }
            }

            i = do_X509_sign(new_x509, CAcert != NULL ? CAkey : pkey,
                             digest, sigopts, &ext_ctx);
            if (!i)
                goto end;
        } else {
            X509V3_CTX ext_ctx;

            /* Set up V3 context struct */
            X509V3_set_ctx(&ext_ctx, NULL, NULL, req, NULL, 0);
            X509V3_set_nconf(&ext_ctx, req_conf);

            /* Add extensions */
            if (req_exts != NULL
                && !X509V3_EXT_REQ_add_nconf(req_conf, &ext_ctx,
                                             req_exts, req)) {
                BIO_printf(bio_err, "Error adding request extensions from section %s\n",
                           req_exts);
                goto end;
            }
            if (addext_conf != NULL
                && !X509V3_EXT_REQ_add_nconf(addext_conf, &ext_ctx, "default",
                                             req)) {
                BIO_printf(bio_err, "Error adding extensions defined via -addext\n");
                goto end;
            }
            i = do_X509_REQ_sign(req, pkey, digest, sigopts);
            if (!i)
                goto end;
        }
    }

    if (subj != NULL && !newreq && !gen_x509) {
        if (verbose) {
            BIO_printf(bio_err, "Modifying subject of certificate request\n");
            print_name(bio_err, "Old subject=",
                       X509_REQ_get_subject_name(req), get_nameopt());
        }

        if (!X509_REQ_set_subject_name(req, fsubj)) {
            BIO_printf(bio_err, "Error modifying subject of certificate request\n");
            goto end;
        }

        if (verbose) {
            print_name(bio_err, "New subject=",
                       X509_REQ_get_subject_name(req), get_nameopt());
        }
    }

    if (verify) {
        EVP_PKEY *tpubkey = pkey;

        if (tpubkey == NULL) {
            tpubkey = X509_REQ_get0_pubkey(req);
            if (tpubkey == NULL)
                goto end;
        }

        i = do_X509_REQ_verify(req, tpubkey, vfyopts);

        if (i < 0) {
            goto end;
        } else if (i == 0) {
            BIO_printf(bio_err, "Certificate request self-signature verify failure\n");
            ERR_print_errors(bio_err);
        } else { /* i > 0 */
            BIO_printf(bio_err, "Certificate request self-signature verify OK\n");
        }
    }

    if (noout && !text && !modulus && !subject && !pubkey) {
        ret = 0;
        goto end;
    }

    out = bio_open_default(outfile,
                           keyout != NULL && outfile != NULL &&
                           strcmp(keyout, outfile) == 0 ? 'a' : 'w',
                           outformat);
    if (out == NULL)
        goto end;

    if (pubkey) {
        EVP_PKEY *tpubkey = X509_REQ_get0_pubkey(req);

        if (tpubkey == NULL) {
            BIO_printf(bio_err, "Error getting public key\n");
            goto end;
        }
        PEM_write_bio_PUBKEY(out, tpubkey);
    }

    if (text) {
        if (gen_x509)
            ret = X509_print_ex(out, new_x509, get_nameopt(), reqflag);
        else
            ret = X509_REQ_print_ex(out, req, get_nameopt(), reqflag);

        if (ret == 0) {
            if (gen_x509)
                BIO_printf(bio_err, "Error printing certificate\n");
            else
                BIO_printf(bio_err, "Error printing certificate request\n");
            goto end;
        }
    }

    if (subject) {
        if (gen_x509)
            print_name(out, "subject=", X509_get_subject_name(new_x509),
                       get_nameopt());
        else
            print_name(out, "subject=", X509_REQ_get_subject_name(req),
                       get_nameopt());
    }

    if (modulus) {
        EVP_PKEY *tpubkey;

        if (gen_x509)
            tpubkey = X509_get0_pubkey(new_x509);
        else
            tpubkey = X509_REQ_get0_pubkey(req);
        if (tpubkey == NULL) {
            fprintf(stdout, "Modulus is unavailable\n");
            goto end;
        }
        fprintf(stdout, "Modulus=");
        if (EVP_PKEY_is_a(tpubkey, "RSA")) {
            BIGNUM *n;

            /* Every RSA key has an 'n' */
            EVP_PKEY_get_bn_param(pkey, "n", &n);
            BN_print(out, n);
            BN_free(n);
        } else {
            fprintf(stdout, "Wrong Algorithm type");
        }
        fprintf(stdout, "\n");
    }

    if (!noout && !gen_x509) {
        if (outformat == FORMAT_ASN1)
            i = i2d_X509_REQ_bio(out, req);
        else if (newhdr)
            i = PEM_write_bio_X509_REQ_NEW(out, req);
        else
            i = PEM_write_bio_X509_REQ(out, req);
        if (!i) {
            BIO_printf(bio_err, "Unable to write certificate request\n");
            goto end;
        }
    }
    if (!noout && gen_x509 && new_x509 != NULL) {
        if (outformat == FORMAT_ASN1)
            i = i2d_X509_bio(out, new_x509);
        else
            i = PEM_write_bio_X509(out, new_x509);
        if (!i) {
            BIO_printf(bio_err, "Unable to write X509 certificate\n");
            goto end;
        }
    }
    ret = 0;
 end:
    if (ret) {
        ERR_print_errors(bio_err);
    }
    NCONF_free(req_conf);
    NCONF_free(addext_conf);
    BIO_free(addext_bio);
    BIO_free_all(out);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(genctx);
    sk_OPENSSL_STRING_free(pkeyopts);
    sk_OPENSSL_STRING_free(sigopts);
    sk_OPENSSL_STRING_free(vfyopts);
    lh_OPENSSL_STRING_doall(addexts, exts_cleanup);
    lh_OPENSSL_STRING_free(addexts);
#ifndef OPENSSL_NO_ENGINE
    release_engine(gen_eng);
#endif
    OPENSSL_free(keyalgstr);
    X509_REQ_free(req);
    X509_NAME_free(fsubj);
    X509_free(new_x509);
    X509_free(CAcert);
    EVP_PKEY_free(CAkey);
    ASN1_INTEGER_free(serial);
    release_engine(e);
    if (passin != nofree_passin)
        OPENSSL_free(passin);
    if (passout != nofree_passout)
        OPENSSL_free(passout);
    return ret;
}

static int make_REQ(X509_REQ *req, EVP_PKEY *pkey, X509_NAME *fsubj,
                    int multirdn, int attribs, unsigned long chtype)
{
    int ret = 0, i;
    char no_prompt = 0;
    STACK_OF(CONF_VALUE) *dn_sk = NULL, *attr_sk = NULL;
    char *tmp, *dn_sect, *attr_sect;

    tmp = NCONF_get_string(req_conf, section, PROMPT);
    if (tmp == NULL)
        ERR_clear_error();
    if ((tmp != NULL) && strcmp(tmp, "no") == 0)
        no_prompt = 1;

    dn_sect = NCONF_get_string(req_conf, section, DISTINGUISHED_NAME);
    if (dn_sect == NULL) {
        ERR_clear_error();
    } else {
        dn_sk = NCONF_get_section(req_conf, dn_sect);
        if (dn_sk == NULL) {
            BIO_printf(bio_err, "Unable to get '%s' section\n", dn_sect);
            goto err;
        }
    }

    attr_sect = NCONF_get_string(req_conf, section, ATTRIBUTES);
    if (attr_sect == NULL) {
        ERR_clear_error();
    } else {
        attr_sk = NCONF_get_section(req_conf, attr_sect);
        if (attr_sk == NULL) {
            BIO_printf(bio_err, "Unable to get '%s' section\n", attr_sect);
            goto err;
        }
    }

    if (!X509_REQ_set_version(req, 0L)) /* so far there is only version 1 */
        goto err;

    if (fsubj != NULL)
        i = X509_REQ_set_subject_name(req, fsubj);
    else if (no_prompt)
        i = auto_info(req, dn_sk, attr_sk, attribs, chtype);
    else
        i = prompt_info(req, dn_sk, dn_sect, attr_sk, attr_sect, attribs,
                        chtype);
    if (!i)
        goto err;

    if (!X509_REQ_set_pubkey(req, pkey))
        goto err;

    ret = 1;
 err:
    return ret;
}

static int prompt_info(X509_REQ *req,
                       STACK_OF(CONF_VALUE) *dn_sk, const char *dn_sect,
                       STACK_OF(CONF_VALUE) *attr_sk, const char *attr_sect,
                       int attribs, unsigned long chtype)
{
    int i;
    char *p, *q;
    char buf[100];
    int nid, mval;
    long n_min, n_max;
    char *type, *value;
    const char *def;
    CONF_VALUE *v;
    X509_NAME *subj = X509_REQ_get_subject_name(req);

    if (!batch) {
        BIO_printf(bio_err,
                   "You are about to be asked to enter information that will be incorporated\n");
        BIO_printf(bio_err, "into your certificate request.\n");
        BIO_printf(bio_err,
                   "What you are about to enter is what is called a Distinguished Name or a DN.\n");
        BIO_printf(bio_err,
                   "There are quite a few fields but you can leave some blank\n");
        BIO_printf(bio_err,
                   "For some fields there will be a default value,\n");
        BIO_printf(bio_err,
                   "If you enter '.', the field will be left blank.\n");
        BIO_printf(bio_err, "-----\n");
    }

    if (sk_CONF_VALUE_num(dn_sk)) {
        i = -1;
 start:
        for (;;) {
            i++;
            if (sk_CONF_VALUE_num(dn_sk) <= i)
                break;

            v = sk_CONF_VALUE_value(dn_sk, i);
            p = q = NULL;
            type = v->name;
            if (!check_end(type, "_min") || !check_end(type, "_max") ||
                !check_end(type, "_default") || !check_end(type, "_value"))
                continue;
            /*
             * Skip past any leading X. X: X, etc to allow for multiple
             * instances
             */
            for (p = v->name; *p; p++)
                if ((*p == ':') || (*p == ',') || (*p == '.')) {
                    p++;
                    if (*p)
                        type = p;
                    break;
                }
            if (*type == '+') {
                mval = -1;
                type++;
            } else {
                mval = 0;
            }
            /* If OBJ not recognised ignore it */
            if ((nid = OBJ_txt2nid(type)) == NID_undef)
                goto start;
            if (!join(buf, sizeof(buf), v->name, "_default", "Name"))
                return 0;
            if ((def = NCONF_get_string(req_conf, dn_sect, buf)) == NULL) {
                ERR_clear_error();
                def = "";
            }

            if (!join(buf, sizeof(buf), v->name, "_value", "Name"))
                return 0;
            if ((value = NCONF_get_string(req_conf, dn_sect, buf)) == NULL) {
                ERR_clear_error();
                value = NULL;
            }

            if (!join(buf, sizeof(buf), v->name, "_min", "Name"))
                return 0;
            if (!NCONF_get_number(req_conf, dn_sect, buf, &n_min)) {
                ERR_clear_error();
                n_min = -1;
            }

            if (!join(buf, sizeof(buf), v->name, "_max", "Name"))
                return 0;
            if (!NCONF_get_number(req_conf, dn_sect, buf, &n_max)) {
                ERR_clear_error();
                n_max = -1;
            }

            if (!add_DN_object(subj, v->value, def, value, nid,
                               n_min, n_max, chtype, mval))
                return 0;
        }
        if (X509_NAME_entry_count(subj) == 0) {
            BIO_printf(bio_err, "Error: No objects specified in config file\n");
            return 0;
        }

        if (attribs) {
            if ((attr_sk != NULL) && (sk_CONF_VALUE_num(attr_sk) > 0)
                && (!batch)) {
                BIO_printf(bio_err,
                           "\nPlease enter the following 'extra' attributes\n");
                BIO_printf(bio_err,
                           "to be sent with your certificate request\n");
            }

            i = -1;
 start2:
            for (;;) {
                i++;
                if ((attr_sk == NULL) || (sk_CONF_VALUE_num(attr_sk) <= i))
                    break;

                v = sk_CONF_VALUE_value(attr_sk, i);
                type = v->name;
                if ((nid = OBJ_txt2nid(type)) == NID_undef)
                    goto start2;

                if (!join(buf, sizeof(buf), type, "_default", "Name"))
                    return 0;
                if ((def = NCONF_get_string(req_conf, attr_sect, buf))
                    == NULL) {
                    ERR_clear_error();
                    def = "";
                }

                if (!join(buf, sizeof(buf), type, "_value", "Name"))
                    return 0;
                if ((value = NCONF_get_string(req_conf, attr_sect, buf))
                    == NULL) {
                    ERR_clear_error();
                    value = NULL;
                }

                if (!join(buf, sizeof(buf), type, "_min", "Name"))
                    return 0;
                if (!NCONF_get_number(req_conf, attr_sect, buf, &n_min)) {
                    ERR_clear_error();
                    n_min = -1;
                }

                if (!join(buf, sizeof(buf), type, "_max", "Name"))
                    return 0;
                if (!NCONF_get_number(req_conf, attr_sect, buf, &n_max)) {
                    ERR_clear_error();
                    n_max = -1;
                }

                if (!add_attribute_object(req,
                                          v->value, def, value, nid, n_min,
                                          n_max, chtype))
                    return 0;
            }
        }
    } else {
        BIO_printf(bio_err, "No template, please set one up.\n");
        return 0;
    }

    return 1;

}

static int auto_info(X509_REQ *req, STACK_OF(CONF_VALUE) *dn_sk,
                     STACK_OF(CONF_VALUE) *attr_sk, int attribs,
                     unsigned long chtype)
{
    int i, spec_char, plus_char;
    char *p, *q;
    char *type;
    CONF_VALUE *v;
    X509_NAME *subj;

    subj = X509_REQ_get_subject_name(req);

    for (i = 0; i < sk_CONF_VALUE_num(dn_sk); i++) {
        int mval;
        v = sk_CONF_VALUE_value(dn_sk, i);
        p = q = NULL;
        type = v->name;
        /*
         * Skip past any leading X. X: X, etc to allow for multiple instances
         */
        for (p = v->name; *p; p++) {
#ifndef CHARSET_EBCDIC
            spec_char = (*p == ':' || *p == ',' || *p == '.');
#else
            spec_char = (*p == os_toascii[':'] || *p == os_toascii[',']
                         || *p == os_toascii['.']);
#endif
            if (spec_char) {
                p++;
                if (*p)
                    type = p;
                break;
            }
        }
#ifndef CHARSET_EBCDIC
        plus_char = (*type == '+');
#else
        plus_char = (*type == os_toascii['+']);
#endif
        if (plus_char) {
            type++;
            mval = -1;
        } else {
            mval = 0;
        }
        if (!X509_NAME_add_entry_by_txt(subj, type, chtype,
                                        (unsigned char *)v->value, -1, -1,
                                        mval))
            return 0;

    }

    if (!X509_NAME_entry_count(subj)) {
        BIO_printf(bio_err, "Error: No objects specified in config file\n");
        return 0;
    }
    if (attribs) {
        for (i = 0; i < sk_CONF_VALUE_num(attr_sk); i++) {
            v = sk_CONF_VALUE_value(attr_sk, i);
            if (!X509_REQ_add1_attr_by_txt(req, v->name, chtype,
                                           (unsigned char *)v->value, -1))
                return 0;
        }
    }
    return 1;
}

static int add_DN_object(X509_NAME *n, char *text, const char *def,
                         char *value, int nid, int n_min, int n_max,
                         unsigned long chtype, int mval)
{
    int ret = 0;
    char buf[1024];

    ret = build_data(text, def, value, n_min, n_max, buf, sizeof(buf),
                     "DN value", "DN default");
    if ((ret == 0) || (ret == 1))
        return ret;
    ret = 1;

    if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
                                    (unsigned char *)buf, -1, -1, mval))
        ret = 0;

    return ret;
}

static int add_attribute_object(X509_REQ *req, char *text, const char *def,
                                char *value, int nid, int n_min,
                                int n_max, unsigned long chtype)
{
    int ret = 0;
    char buf[1024];

    ret = build_data(text, def, value, n_min, n_max, buf, sizeof(buf),
                     "Attribute value", "Attribute default");
    if ((ret == 0) || (ret == 1))
        return ret;
    ret = 1;

    if (!X509_REQ_add1_attr_by_NID(req, nid, chtype,
                                   (unsigned char *)buf, -1)) {
        BIO_printf(bio_err, "Error adding attribute\n");
        ERR_print_errors(bio_err);
        ret = 0;
    }

    return ret;
}

static int build_data(char *text, const char *def, char *value,
                      int n_min, int n_max, char *buf, const int buf_size,
                      const char *desc1, const char *desc2)
{
    int i;
 start:
    if (!batch)
        BIO_printf(bio_err, "%s [%s]:", text, def);
    (void)BIO_flush(bio_err);
    if (value != NULL) {
        if (!join(buf, buf_size, value, "\n", desc1))
            return 0;
        BIO_printf(bio_err, "%s\n", value);
    } else {
        buf[0] = '\0';
        if (!batch) {
            if (!fgets(buf, buf_size, stdin))
                return 0;
        } else {
            buf[0] = '\n';
            buf[1] = '\0';
        }
    }

    if (buf[0] == '\0')
        return 0;
    if (buf[0] == '\n') {
        if ((def == NULL) || (def[0] == '\0'))
            return 1;
        if (!join(buf, buf_size, def, "\n", desc2))
            return 0;
    } else if ((buf[0] == '.') && (buf[1] == '\n')) {
        return 1;
    }

    i = strlen(buf);
    if (buf[i - 1] != '\n') {
        BIO_printf(bio_err, "Missing newline at end of input\n");
        return 0;
    }
    buf[--i] = '\0';
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(buf, buf, i);
#endif
    if (!req_check_len(i, n_min, n_max)) {
        if (batch || value)
            return 0;
        goto start;
    }
    return 2;
}

static int req_check_len(int len, int n_min, int n_max)
{
    if (n_min > 0 && len < n_min) {
        BIO_printf(bio_err,
                   "String too short, must be at least %d bytes long\n", n_min);
        return 0;
    }
    if (n_max >= 0 && len > n_max) {
        BIO_printf(bio_err,
                   "String too long, must be at most %d bytes long\n", n_max);
        return 0;
    }
    return 1;
}

/* Check if the end of a string matches 'end' */
static int check_end(const char *str, const char *end)
{
    size_t elen, slen;
    const char *tmp;

    elen = strlen(end);
    slen = strlen(str);
    if (elen > slen)
        return 1;
    tmp = str + slen - elen;
    return strcmp(tmp, end);
}

/*
 * Merge the two strings together into the result buffer checking for
 * overflow and producing an error message if there is.
 */
static int join(char buf[], size_t buf_size, const char *name,
                const char *tail, const char *desc)
{
    const size_t name_len = strlen(name), tail_len = strlen(tail);

    if (name_len + tail_len + 1 > buf_size) {
        BIO_printf(bio_err, "%s '%s' too long\n", desc, name);
        return 0;
    }
    memcpy(buf, name, name_len);
    memcpy(buf + name_len, tail, tail_len + 1);
    return 1;
}

static EVP_PKEY_CTX *set_keygen_ctx(const char *gstr,
                                    int *pkey_type, long *pkeylen,
                                    char **palgnam, ENGINE *keygen_engine)
{
    EVP_PKEY_CTX *gctx = NULL;
    EVP_PKEY *param = NULL;
    long keylen = -1;
    BIO *pbio = NULL;
    const char *paramfile = NULL;

    if (gstr == NULL) {
        *pkey_type = EVP_PKEY_RSA;
        keylen = *pkeylen;
    } else if (gstr[0] >= '0' && gstr[0] <= '9') {
        *pkey_type = EVP_PKEY_RSA;
        keylen = atol(gstr);
        *pkeylen = keylen;
    } else if (strncmp(gstr, "param:", 6) == 0) {
        paramfile = gstr + 6;
    } else {
        const char *p = strchr(gstr, ':');
        int len;
        ENGINE *tmpeng;
        const EVP_PKEY_ASN1_METHOD *ameth;

        if (p != NULL)
            len = p - gstr;
        else
            len = strlen(gstr);
        /*
         * The lookup of a the string will cover all engines so keep a note
         * of the implementation.
         */

        ameth = EVP_PKEY_asn1_find_str(&tmpeng, gstr, len);

        if (ameth == NULL) {
            BIO_printf(bio_err, "Unknown algorithm %.*s\n", len, gstr);
            return NULL;
        }

        EVP_PKEY_asn1_get0_info(NULL, pkey_type, NULL, NULL, NULL, ameth);
#ifndef OPENSSL_NO_ENGINE
        finish_engine(tmpeng);
#endif
        if (*pkey_type == EVP_PKEY_RSA) {
            if (p != NULL) {
                keylen = atol(p + 1);
                *pkeylen = keylen;
            } else {
                keylen = *pkeylen;
            }
        } else if (p != NULL) {
            paramfile = p + 1;
        }
    }

    if (paramfile != NULL) {
        pbio = BIO_new_file(paramfile, "r");
        if (pbio == NULL) {
            BIO_printf(bio_err, "Cannot open parameter file %s\n", paramfile);
            return NULL;
        }
        param = PEM_read_bio_Parameters(pbio, NULL);

        if (param == NULL) {
            X509 *x;

            (void)BIO_reset(pbio);
            x = PEM_read_bio_X509(pbio, NULL, NULL, NULL);
            if (x != NULL) {
                param = X509_get_pubkey(x);
                X509_free(x);
            }
        }

        BIO_free(pbio);

        if (param == NULL) {
            BIO_printf(bio_err, "Error reading parameter file %s\n", paramfile);
            return NULL;
        }
        if (*pkey_type == -1) {
            *pkey_type = EVP_PKEY_id(param);
        } else if (*pkey_type != EVP_PKEY_base_id(param)) {
            BIO_printf(bio_err, "Key type does not match parameters\n");
            EVP_PKEY_free(param);
            return NULL;
        }
    }

    if (palgnam != NULL) {
        const EVP_PKEY_ASN1_METHOD *ameth;
        ENGINE *tmpeng;
        const char *anam;

        ameth = EVP_PKEY_asn1_find(&tmpeng, *pkey_type);
        if (ameth == NULL) {
            BIO_puts(bio_err, "Internal error: can't find key algorithm\n");
            return NULL;
        }
        EVP_PKEY_asn1_get0_info(NULL, NULL, NULL, NULL, &anam, ameth);
        *palgnam = OPENSSL_strdup(anam);
#ifndef OPENSSL_NO_ENGINE
        finish_engine(tmpeng);
#endif
    }

    if (param != NULL) {
        gctx = EVP_PKEY_CTX_new(param, keygen_engine);
        *pkeylen = EVP_PKEY_bits(param);
        EVP_PKEY_free(param);
    } else {
        gctx = EVP_PKEY_CTX_new_id(*pkey_type, keygen_engine);
    }

    if (gctx == NULL) {
        BIO_puts(bio_err, "Error allocating keygen context\n");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(gctx) <= 0) {
        BIO_puts(bio_err, "Error initializing keygen context\n");
        EVP_PKEY_CTX_free(gctx);
        return NULL;
    }
    if ((*pkey_type == EVP_PKEY_RSA) && (keylen != -1)) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(gctx, keylen) <= 0) {
            BIO_puts(bio_err, "Error setting RSA keysize\n");
            EVP_PKEY_CTX_free(gctx);
            return NULL;
        }
    }

    return gctx;
}

static int genpkey_cb(EVP_PKEY_CTX *ctx)
{
    char c = '*';
    BIO *b = EVP_PKEY_CTX_get_app_data(ctx);
    int p;
    p = EVP_PKEY_CTX_get_keygen_info(ctx, 0);
    if (p == 0)
        c = '.';
    if (p == 1)
        c = '+';
    if (p == 2)
        c = '*';
    if (p == 3)
        c = '\n';
    BIO_write(b, &c, 1);
    (void)BIO_flush(b);
    return 1;
}

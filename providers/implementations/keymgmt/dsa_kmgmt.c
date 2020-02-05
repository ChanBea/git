/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/params.h>
#include "internal/param_build.h"
#include "crypto/dsa.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "crypto/dsa.h"

static OSSL_OP_keymgmt_new_fn dsa_newdata;
static OSSL_OP_keymgmt_free_fn dsa_freedata;
static OSSL_OP_keymgmt_has_domparams_fn dsa_has_domparams;
static OSSL_OP_keymgmt_has_public_key_fn dsa_has_public;
static OSSL_OP_keymgmt_has_public_key_fn dsa_has_private;
static OSSL_OP_keymgmt_import_fn dsa_import;
static OSSL_OP_keymgmt_export_fn dsa_export;
static OSSL_OP_keymgmt_get_params_fn dsa_get_params;

#define DSA_DEFAULT_MD "SHA256"

static int params_to_domparams(DSA *dsa, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_p, *param_q, *param_g;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;

    if (dsa == NULL)
        return 0;

    param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_P);
    param_q = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_Q);
    param_g = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_G);

    if ((param_p != NULL && !OSSL_PARAM_get_BN(param_p, &p))
        || (param_q != NULL && !OSSL_PARAM_get_BN(param_q, &q))
        || (param_g != NULL && !OSSL_PARAM_get_BN(param_g, &g)))
        goto err;

    if (!DSA_set0_pqg(dsa, p, q, g))
        goto err;

    return 1;

 err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    return 0;
}

static int domparams_to_params(DSA *dsa, OSSL_PARAM_BLD *tmpl)
{
    const BIGNUM *dsa_p = NULL, *dsa_q = NULL, *dsa_g = NULL;

    if (dsa == NULL)
        return 0;

    DSA_get0_pqg(dsa, &dsa_p, &dsa_q, &dsa_g);
    if (dsa_p != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, dsa_p))
        return 0;
    if (dsa_q != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_Q, dsa_q))
        return 0;
    if (dsa_g != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, dsa_g))
        return 0;

    return 1;
}

static int params_to_key(DSA *dsa, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_priv_key, *param_pub_key;
    BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dsa == NULL)
        return 0;

    if (!params_to_domparams(dsa, params))
        return 0;

    param_priv_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DSA_PRIV_KEY);
    param_pub_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DSA_PUB_KEY);

    /*
     * DSA documentation says that a public key must be present if a private key
     * is.
     */
    if (param_priv_key != NULL && param_pub_key == NULL)
        return 0;

    if ((param_priv_key != NULL
         && !OSSL_PARAM_get_BN(param_priv_key, &priv_key))
        || (param_pub_key != NULL
            && !OSSL_PARAM_get_BN(param_pub_key, &pub_key)))
        goto err;

    if (pub_key != NULL && !DSA_set0_key(dsa, pub_key, priv_key))
        goto err;

    return 1;

 err:
    BN_free(priv_key);
    BN_free(pub_key);
    return 0;
}

static int key_to_params(DSA *dsa, OSSL_PARAM_BLD *tmpl)
{
    const BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dsa == NULL)
        return 0;
    if (!domparams_to_params(dsa, tmpl))
        return 0;

    DSA_get0_key(dsa, &pub_key, &priv_key);
    if (priv_key != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_DSA_PRIV_KEY, priv_key))
        return 0;
    if (pub_key != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_DSA_PUB_KEY, pub_key))
        return 0;

    return 1;
}

static void *dsa_newdata(void *provctx)
{
    return DSA_new();
}

static void dsa_freedata(void *keydata)
{
    DSA_free(keydata);
}

static int dsa_has_domparams(void *keydata)
{
    DSA *dsa = keydata;

    return (DSA_get0_p(dsa) != NULL && DSA_get0_g(dsa) != NULL);
}

static int dsa_has_public(void *keydata)
 {
    DSA *dsa = keydata;

    return (DSA_get0_pub_key(dsa) != NULL);
}

static int dsa_has_private(void *keydata)
{
    DSA *dsa = keydata;

    return (DSA_get0_priv_key(dsa) != NULL);
}

static int dsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    DSA *dsa = keydata;

    if (dsa == NULL)
        return 0;

    if (selection != OSSL_KEYMGMT_WANT_KEY
        && !params_to_domparams(dsa, params))
        return 0;
    if (selection != OSSL_KEYMGMT_WANT_DOMPARAMS
        && !params_to_key(dsa, params))
        return 0;

    return 1;
}

static int dsa_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                      void *cbarg)
{
    DSA *dsa = keydata;
    OSSL_PARAM_BLD tmpl;
    OSSL_PARAM *params = NULL;
    int ret;

    if (dsa == NULL)
        return 0;

    ossl_param_bld_init(&tmpl);

    if (selection != OSSL_KEYMGMT_WANT_KEY
        && !domparams_to_params(dsa, &tmpl))
        return 0;
    if (selection != OSSL_KEYMGMT_WANT_DOMPARAMS
        && !key_to_params(dsa, &tmpl))
        return 0;

    if ((params = ossl_param_bld_to_param(&tmpl)) == NULL)
        return 0;

    ret = param_cb(params, cbarg);
    ossl_param_bld_free(params);
    return ret;
}

static ossl_inline int dsa_get_params(void *key, OSSL_PARAM params[])
{
    DSA *dsa = key;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, DSA_bits(dsa)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, DSA_security_bits(dsa)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, DSA_size(dsa)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL
        && !OSSL_PARAM_set_utf8_string(p, DSA_DEFAULT_MD))
        return 0;
    return 1;
}

const OSSL_DISPATCH dsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))dsa_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))dsa_freedata },
    { OSSL_FUNC_KEYMGMT_HAS_DOMPARAMS, (void (*)(void))dsa_has_domparams },
    { OSSL_FUNC_KEYMGMT_HAS_PUBLIC_KEY, (void (*)(void))dsa_has_public },
    { OSSL_FUNC_KEYMGMT_HAS_PRIVATE_KEY, (void (*)(void))dsa_has_private },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))dsa_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))dsa_export },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))dsa_get_params },
    { 0, NULL }
};

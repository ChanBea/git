/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include "internal/cryptlib.h"
#include "internal/numbers.h"
#include "crypto/evp.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/provider_util.h"

/* See RFC 3414, Appendix A.2.2 */
/* See NIST SP800-135 Section 6.8 */
static OSSL_FUNC_kdf_newctx_fn kdf_snmpkdf_new;
static OSSL_FUNC_kdf_dupctx_fn kdf_snmpkdf_dup;
static OSSL_FUNC_kdf_freectx_fn kdf_snmpkdf_free;
static OSSL_FUNC_kdf_reset_fn kdf_snmpkdf_reset;
static OSSL_FUNC_kdf_derive_fn kdf_snmpkdf_derive;
static OSSL_FUNC_kdf_settable_ctx_params_fn kdf_snmpkdf_settable_ctx_params;
static OSSL_FUNC_kdf_set_ctx_params_fn kdf_snmpkdf_set_ctx_params;
static OSSL_FUNC_kdf_gettable_ctx_params_fn kdf_snmpkdf_gettable_ctx_params;
static OSSL_FUNC_kdf_get_ctx_params_fn kdf_snmpkdf_get_ctx_params;

#define KDF_SNMP_PASSWORD_HASH_AMOUNT (1024 * 1024)

static int SNMPKDF(const EVP_MD *evp_md,
                   const unsigned char *eid, size_t eid_len,
                   unsigned char *password, size_t password_len,
                   unsigned char *okey, size_t okeylen);

typedef struct {
    void *provctx;
    PROV_DIGEST digest;
    unsigned char *eid;
    size_t eid_len;
    unsigned char *password;
    size_t password_len;
} KDF_SNMPKDF;

static void *kdf_snmpkdf_new(void *provctx)
{
    KDF_SNMPKDF *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) != NULL)
        ctx->provctx = provctx;
    return ctx;
}

static void kdf_snmpkdf_free(void *vctx)
{
    KDF_SNMPKDF *ctx = (KDF_SNMPKDF *)vctx;

    if (ctx != NULL) {
        kdf_snmpkdf_reset(ctx);
        OPENSSL_free(ctx);
    }
}

static void kdf_snmpkdf_reset(void *vctx)
{
    KDF_SNMPKDF *ctx = (KDF_SNMPKDF *)vctx;
    void *provctx = ctx->provctx;

    ossl_prov_digest_reset(&ctx->digest);
    OPENSSL_clear_free(ctx->eid, ctx->eid_len);
    OPENSSL_clear_free(ctx->password, ctx->password_len);
    memset(ctx, 0, sizeof(*ctx));
    ctx->provctx = provctx;
}

static void *kdf_snmpkdf_dup(void *vctx)
{
    const KDF_SNMPKDF *src = (const KDF_SNMPKDF *)vctx;
    KDF_SNMPKDF *dest;

    dest = kdf_snmpkdf_new(src->provctx);
    if (dest != NULL) {
        if (!ossl_prov_memdup(src->eid, src->eid_len,
                              &dest->eid, &dest->eid_len)
                || !ossl_prov_memdup(src->password, src->password_len,
                                     &dest->password , &dest->password_len)
                || !ossl_prov_digest_copy(&dest->digest, &src->digest))
            goto err;
    }
    return dest;

 err:
    kdf_snmpkdf_free(dest);
    return NULL;
}

static int snmpkdf_set_membuf(unsigned char **dst, size_t *dst_len,
                             const OSSL_PARAM *p)
{
    OPENSSL_clear_free(*dst, *dst_len);
    *dst = NULL;
    *dst_len = 0;
    return OSSL_PARAM_get_octet_string(p, (void **)dst, 0, dst_len);
}

static int kdf_snmpkdf_derive(void *vctx, unsigned char *key, size_t keylen,
                             const OSSL_PARAM params[])
{
    KDF_SNMPKDF *ctx = (KDF_SNMPKDF *)vctx;
    const EVP_MD *md;

    if (!ossl_prov_is_running() || !kdf_snmpkdf_set_ctx_params(ctx, params))
        return 0;

    md = ossl_prov_digest_md(&ctx->digest);
    if (md == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    if (ctx->eid == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_EID);
        return 0;
    }
    if (ctx->password == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_PASS);
        return 0;
    }

    return SNMPKDF(md, ctx->eid, ctx->eid_len,
                  ctx->password, ctx->password_len,
                  key, keylen);
}

static int kdf_snmpkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    KDF_SNMPKDF *ctx = vctx;
    OSSL_LIB_CTX *provctx = PROV_LIBCTX_OF(ctx->provctx);

    if (params == NULL)
        return 1;

    if (!ossl_prov_digest_load_from_params(&ctx->digest, params, provctx))
        return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SNMPKDF_EID)) != NULL)
        if (!snmpkdf_set_membuf(&ctx->eid, &ctx->eid_len, p))
            return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PASSWORD))  != NULL) {
        if (ctx->password_len > KDF_SNMP_PASSWORD_HASH_AMOUNT ||
           !snmpkdf_set_membuf(&ctx->password, &ctx->password_len, p))
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *kdf_snmpkdf_settable_ctx_params(ossl_unused void *ctx,
                                                        ossl_unused void *p_ctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SNMPKDF_EID, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int kdf_snmpkdf_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL)
        return OSSL_PARAM_set_size_t(p, SIZE_MAX);
    return -2;
}

static const OSSL_PARAM *kdf_snmpkdf_gettable_ctx_params(ossl_unused void *ctx,
                                                        ossl_unused void *p_ctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

const OSSL_DISPATCH ossl_kdf_snmpkdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void(*)(void))kdf_snmpkdf_new },
    { OSSL_FUNC_KDF_DUPCTX, (void(*)(void))kdf_snmpkdf_dup },
    { OSSL_FUNC_KDF_FREECTX, (void(*)(void))kdf_snmpkdf_free },
    { OSSL_FUNC_KDF_RESET, (void(*)(void))kdf_snmpkdf_reset },
    { OSSL_FUNC_KDF_DERIVE, (void(*)(void))kdf_snmpkdf_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_snmpkdf_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void(*)(void))kdf_snmpkdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_snmpkdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void(*)(void))kdf_snmpkdf_get_ctx_params },
    { 0, NULL }
};




/*
  SNMPKDF - In compliance with SP800-135 and RFC 7860, calculate
             a master key using the engine ID and password.

  Denote engineLength and passwordlen to be the lengths (in bytes) of an
  snmpEngineID and a password, respectively.

  Let N = (1024*1024)/passwordlen

  Expanded_password = the leftmost 1048576 bytes of the string of N
  repetitions of the password.

  Derived_password = SHA-1 (Expanded_password). The Derived_password
  is the output of hashing the Expanded_password by SHA-1.

  Let Shared_key to be the key that the user shares with the authoritative
  SNMP engine with ID snmpEngineID. The Shared_key is generated as follows:

  Shared_key = SHA-1(Derived_password || snmpEngineID || Derived_password).

      e_id -         engine ID(eid)
      e_len -        engineID length
      password -     password
      password_len - password length
      okey -         pointer to key output, FIPS testing limited to SHA-1.
      return -       1 pass 0 for error
 */
static int SNMPKDF(const EVP_MD *evp_md,
                   const unsigned char *e_id, size_t e_len,
                   unsigned char *password, size_t password_len,
                   unsigned char *okey, size_t okeylen)
{
    EVP_MD_CTX *md = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t mdsize = 0, len = 0;
    unsigned int md_len = 0;
    int ret = 0;

    /* Limited to SHA-1 and SHA-2 hashes presently */
    if (okey == NULL || okeylen == 0)
        return 0;

    md = EVP_MD_CTX_new();
    if (md == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        goto err;
    }

    mdsize = EVP_MD_size(evp_md);
    if (mdsize <= 0 || mdsize < okeylen)
        goto err;

    if (!EVP_DigestInit_ex(md, evp_md, NULL))
        goto err;

    for (len = 0; len < KDF_SNMP_PASSWORD_HASH_AMOUNT - password_len; len += password_len ) {
        if (!EVP_DigestUpdate(md, password, password_len)) {
            goto err;
        }
    }

    if (!EVP_DigestUpdate(md, password, KDF_SNMP_PASSWORD_HASH_AMOUNT - len))
        goto err;

    if (!EVP_DigestFinal_ex(md, digest, &md_len))
        goto err;

    if (!EVP_DigestInit_ex(md, evp_md, NULL))
        goto err;

    if (!EVP_DigestUpdate(md, digest, mdsize))
        goto err;

    if (!EVP_DigestUpdate(md, e_id, e_len))
        goto err;

    if (!EVP_DigestUpdate(md, digest, mdsize))
        goto err;

    if (!EVP_DigestFinal_ex(md, digest, &md_len))
        goto err;

    memcpy(okey, digest, okeylen);

    ret = 1;

err:
    EVP_MD_CTX_free(md);
    OPENSSL_cleanse(digest, EVP_MAX_MD_SIZE);
    return ret;
}


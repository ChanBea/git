/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "internal/nelem.h"
#include "internal/evp_int.h"
#include "internal/asn1_int.h"
#include "internal/provider.h"
#include "evp_locl.h"

static OSSL_PARAM *paramdefs_to_params(const OSSL_PARAM *paramdefs)
{
    size_t cnt;
    const OSSL_PARAM *p;
    OSSL_PARAM *params, *q;

    for (cnt = 1, p = paramdefs; p->key != NULL; p++, cnt++)
        continue;

    params = OPENSSL_zalloc(cnt * sizeof(*params));

    for (p = paramdefs, q = params; ; p++, q++) {
        *q = *p;
        if (p->key == NULL)
            break;

        q->data = NULL;          /* In case the provider used it */
        q->return_size = 0;
    }

    return params;
}

typedef union align_block_un {
    OSSL_UNION_ALIGN;
} ALIGN_BLOCK;

#define ALIGN_SIZE  sizeof(ALIGN_BLOCK)

static void *allocate_params_space(OSSL_PARAM *params)
{
    unsigned char *data = NULL;
    size_t space;
    OSSL_PARAM *p;

    for (space = 0, p = params; p->key != NULL; p++)
        space += ((p->return_size + ALIGN_SIZE - 1) / ALIGN_SIZE) * ALIGN_SIZE;

    data = OPENSSL_zalloc(space);

    for (space = 0, p = params; p->key != NULL; p++) {
        p->data = data + space;
        space += ((p->return_size + ALIGN_SIZE - 1) / ALIGN_SIZE) * ALIGN_SIZE;
    }

    return data;
}

void *evp_keymgmt_export_to_provider(EVP_PKEY *pk, EVP_KEYMGMT *keymgmt)
{
    void *provkey = NULL;
    size_t i, j;

    /*
     * If there is an underlying legacy key and it has changed, invalidate
     * the cache of provider keys.
     */
    if (pk->pkey.ptr != NULL) {
        /*
         * If there is no dirty checker or dirty clearer, this key can't be
         * used with providers
         */
        if (pk->ameth->is_dirty == NULL
            || pk->ameth->clear_dirty == NULL)
            return NULL;

        if (pk->ameth->is_dirty(pk))
            evp_keymgmt_clear_pkey_cache(pk);
    }

    /*
     * See if we have exported to this provider already.
     * If we have, return immediately.
     */
    for (i = 0;
         i < OSSL_NELEM(pk->pkeys) && pk->pkeys[i].keymgmt != NULL;
         i++) {
        if (keymgmt == pk->pkeys[i].keymgmt)
            return pk->pkeys[i].provkey;
    }

    if (pk->pkey.ptr != NULL) {
        /* There is a legacy key, try to export that one to the provider */

        /* If the legacy key doesn't have an export function, give up */
        if (pk->ameth->export_to == NULL)
            return NULL;

        /* Otherwise, simply use it */
        provkey = pk->ameth->export_to(pk, keymgmt);

        /* Make it clean, but only if we exported successfully */
        if (provkey != NULL)
            pk->ameth->clear_dirty(pk);

    } else {
        /*
         * Here, there is no legacy key, so we look at the already
         * cached but there are cached provider keys, and import from
         * the first that supports it (i.e. use its export function),
         * and export the imported data to the new provider.
         */

        /*
         * If the given keymgmt doesn't have an import function, give up
         */
        if (keymgmt->importkey_priv == NULL)
            return NULL;

        for (j = 0; j < i && pk->pkeys[j].keymgmt != NULL; j++) {
            if (pk->pkeys[j].keymgmt->exportkey_priv != NULL) {
                const OSSL_PARAM *paramdefs = NULL;
                OSSL_PARAM *params = NULL;
                void *data = NULL;
                void *provctx =
                    ossl_provider_ctx(EVP_KEYMGMT_provider(keymgmt));

                paramdefs = pk->pkeys[j].keymgmt->exportkey_priv_types();
                /*
                 * All params have 'data' set to NULL.  In that case,
                 * the exportkey call should just fill in 'return_size'
                 * in all applicable params.
                 */
                params = paramdefs_to_params(paramdefs);
                /* Get 'return_size' filled */
                pk->pkeys[j].keymgmt->exportkey_priv(pk->pkeys[j].provkey,
                                                     params);

                /*
                 * Allocate space and assign 'data' to point into the
                 * data block
                 */
                data = allocate_params_space(params);

                /*
                 * Call the exportkey function a second time, to get
                 * the data filled
                 */
                pk->pkeys[j].keymgmt->exportkey_priv(pk->pkeys[j].provkey,
                                                     params);

                /*
                 * We should have all the data at this point, so import
                 * into the new provider and hope to get a key back.
                 */
                provkey = keymgmt->importkey_priv(provctx, params);
                OPENSSL_free(params);
                OPENSSL_free(data);

                if (provkey != NULL)
                    break;
            }
        }
    }

    /*
     * TODO(3.0) Right now, we assume we have ample space.  We will
     * have to think about a cache aging scheme, though, if |i| indexes
     * outside the array.
     */
    j = ossl_assert(i < OSSL_NELEM(pk->pkeys));

    if (provkey != NULL) {
        EVP_KEYMGMT_up_ref(keymgmt);
        pk->pkeys[i].keymgmt = keymgmt;
        pk->pkeys[i].provkey = provkey;
    }
    return provkey;
}

void evp_keymgmt_clear_pkey_cache(EVP_PKEY *pk)
{
    size_t i;

    if (pk != NULL) {
        for (i = 0;
             i < OSSL_NELEM(pk->pkeys) && pk->pkeys[i].keymgmt != NULL;
             i++) {
            pk->pkeys[i].keymgmt->freekey(pk->pkeys[i].provkey);
            EVP_KEYMGMT_free(pk->pkeys[i].keymgmt);
            pk->pkeys[i].keymgmt = NULL;
            pk->pkeys[i].provkey = NULL;
        }
    }
}

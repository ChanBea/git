/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CORE_H
# define OSSL_CORE_H

# include <stddef.h>
# include <openssl/ossl_typ.h>

# ifdef __cplusplus
extern "C" {
# endif

/*-
 * Base types
 * ----------
 *
 * These are the types that the OpenSSL core and providers have in common
 * to communicate data between them.
 */

/*
 * Dispatch table element.  function_id numbers are defined further down,
 * see macros with '_FUNC' in their names.
 *
 * An array of these is always terminated by function_id == 0
 */
struct ossl_dispatch_st {
    int function_id;
    void (*function)(void);
};

/*
 * Other items, essentially an int<->pointer map element.
 *
 * We make this type distinct from OSSL_DISPATCH to ensure that dispatch
 * tables remain tables with function pointers only.
 *
 * This is used whenever we need to pass things like a table of error reason
 * codes <-> reason string maps, parameter name <-> parameter type maps, ...
 *
 * Usage determines which field works as key if any, rather than field order.
 *
 * An array of these is always terminated by id == 0 && ptr == NULL
 */
struct ossl_item_st {
    unsigned int id;
    void *ptr;
};

/*
 * Type to tie together algorithm name, property definition string and
 * the algorithm implementation in the form of a dispatch table.
 *
 * An array of these is always terminated by algorithm_name == NULL
 */
struct ossl_algorithm_st {
    const char *algorithm_name;      /* key */
    const char *property_definition; /* key */
    const OSSL_DISPATCH *implementation;
};

/*
 * Type to pass object data in a uniform way, without exposing the object
 * structure.
 *
 * An array of these is always terminated by key == NULL
 */
struct ossl_param_st {
    const char *key;             /* the name of the parameter */
    unsigned int data_type;      /* declare what kind of content is in buffer */
    void *buffer;                /* value being passed */
    size_t size;                 /* buffer size */
    size_t used;                 /* amount used (if not implied by data_type) */
};

/* Currently supported OSSL_PARAM data types */
/*
 * Numbers are stored in native form.  Leaving space for more numbers
 * later without breaking API/ABI.
 */
# define OSSL_PARAM_INT                 0x01
# define OSSL_PARAM_UINT                0x02
# define OSSL_PARAM_INT64               0x03
# define OSSL_PARAM_UINT64              0x04
# define OSSL_PARAM_LONG                0x05
# define OSSL_PARAM_ULONG               0x06
# define OSSL_PARAM_SIZET               0x07
# define OSSL_PARAM_DOUBLE              0x08

/*
 * A pointer; interpretation is up to the sender/caller.
 */
# define OSSL_PARAM_POINTER             0x09

/*
 * OSSL_PARAM_BIGNUM is an OpenSSL BIGNUM; stored in native-endian format.
 */
# define OSSL_PARAM_BIGNUM              0x10

/*
 * A buffer of max fixed size.
 */
# define OSSL_PARAM_BUFFER              0x11

/*-
 * Provider entry point
 * --------------------
 *
 * This function is expected to be present in any dynamically loadable
 * provider module.  By definition, if this function doesn't exist in a
 * module, that module is not an OpenSSL provider module.
 */
/*-
 * |provider|   pointer to opaque type OSSL_PROVIDER.  This can be used
 *              together with some functions passed via |in| to query data.
 * |in|         is the array of functions that the Core passes to the provider.
 * |out|        will be the array of base functions that the provider passes
 *              back to the Core.
 */
typedef int (OSSL_provider_init_fn)(const OSSL_PROVIDER *provider,
                                    const OSSL_DISPATCH *in,
                                    const OSSL_DISPATCH **out);
extern OSSL_provider_init_fn OSSL_provider_init;

# ifdef __cplusplus
}
# endif

#endif

/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/tserr.h>
#include "crypto/tserr.h"

#ifndef OPENSSL_NO_TS

# ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA TS_str_reasons[] = {
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_BAD_PKCS7_TYPE), "bad pkcs7 type"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_BAD_TYPE), "bad type"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_CANNOT_LOAD_CERT), "cannot load certificate"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_CANNOT_LOAD_KEY), "cannot load private key"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_CERTIFICATE_VERIFY_ERROR),
    "certificate verify error"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_COULD_NOT_SET_ENGINE),
    "could not set engine"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_COULD_NOT_SET_TIME), "could not set time"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_DETACHED_CONTENT), "detached content"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_ESS_ADD_SIGNING_CERT_ERROR),
    "ess add signing cert error"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_ESS_ADD_SIGNING_CERT_V2_ERROR),
    "ess add signing cert v2 error"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_ESS_SIGNING_CERTIFICATE_ERROR),
    "ess signing certificate error"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_INVALID_NULL_POINTER),
    "invalid null pointer"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE),
    "invalid signer certificate purpose"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_MESSAGE_IMPRINT_MISMATCH),
    "message imprint mismatch"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_NONCE_MISMATCH), "nonce mismatch"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_NONCE_NOT_RETURNED), "nonce not returned"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_NO_CONTENT), "no content"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_NO_TIMESTAMP_TOKEN), "no timestamp token"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_PKCS7_ADD_SIGNATURE_ERROR),
    "pkcs7 add signature error"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_PKCS7_ADD_SIGNED_ATTR_ERROR),
    "pkcs7 add signed attr error"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_PKCS7_TO_TS_TST_INFO_FAILED),
    "pkcs7 to ts tst info failed"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_POLICY_MISMATCH), "policy mismatch"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE),
    "private key does not match certificate"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_RESPONSE_SETUP_ERROR),
    "response setup error"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_SIGNATURE_FAILURE), "signature failure"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_THERE_MUST_BE_ONE_SIGNER),
    "there must be one signer"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_TIME_SYSCALL_ERROR), "time syscall error"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_TOKEN_NOT_PRESENT), "token not present"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_TOKEN_PRESENT), "token present"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_TSA_NAME_MISMATCH), "tsa name mismatch"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_TSA_UNTRUSTED), "tsa untrusted"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_TST_INFO_SETUP_ERROR),
    "tst info setup error"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_TS_DATASIGN), "ts datasign"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_UNACCEPTABLE_POLICY), "unacceptable policy"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_UNSUPPORTED_MD_ALGORITHM),
    "unsupported md algorithm"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_UNSUPPORTED_VERSION), "unsupported version"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_VAR_BAD_VALUE), "var bad value"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_VAR_LOOKUP_FAILURE),
    "cannot find config variable"},
    {ERR_PACK(ERR_LIB_TS, 0, TS_R_WRONG_CONTENT_TYPE), "wrong content type"},
    {0, NULL}
};

# endif

int ossl_err_load_TS_strings(void)
{
# ifndef OPENSSL_NO_ERR
    if (ERR_reason_error_string(TS_str_reasons[0].error) == NULL)
        ERR_load_strings_const(TS_str_reasons);
# endif
    return 1;
}
#else
NON_EMPTY_TRANSLATION_UNIT
#endif

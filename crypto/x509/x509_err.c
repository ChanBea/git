/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/x509err.h>

#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA X509_str_functs[] = {
    {ERR_PACK(ERR_LIB_X509, X509_F_ADD_CERT_DIR, 0), "add_cert_dir"},
    {ERR_PACK(ERR_LIB_X509, X509_F_ADD_LOCATIONS, 0), "add_locations"},
    {ERR_PACK(ERR_LIB_X509, X509_F_BUILD_CHAIN, 0), "build_chain"},
    {ERR_PACK(ERR_LIB_X509, X509_F_BY_FILE_CTRL, 0), "by_file_ctrl"},
    {ERR_PACK(ERR_LIB_X509, X509_F_CHECK_NAME_CONSTRAINTS, 0),
     "check_name_constraints"},
    {ERR_PACK(ERR_LIB_X509, X509_F_CHECK_POLICY, 0), "check_policy"},
    {ERR_PACK(ERR_LIB_X509, X509_F_DANE_I2D, 0), "dane_i2d"},
    {ERR_PACK(ERR_LIB_X509, X509_F_DIR_CTRL, 0), "dir_ctrl"},
    {ERR_PACK(ERR_LIB_X509, X509_F_GET_CERT_BY_SUBJECT, 0),
     "get_cert_by_subject"},
    {ERR_PACK(ERR_LIB_X509, X509_F_I2D_X509_AUX, 0), "i2d_X509_AUX"},
    {ERR_PACK(ERR_LIB_X509, X509_F_LOOKUP_CERTS_SK, 0), "lookup_certs_sk"},
    {ERR_PACK(ERR_LIB_X509, X509_F_LOOKUP_INT, 0), "lookup_int"},
    {ERR_PACK(ERR_LIB_X509, X509_F_NETSCAPE_SPKI_B64_DECODE, 0),
     "NETSCAPE_SPKI_b64_decode"},
    {ERR_PACK(ERR_LIB_X509, X509_F_NETSCAPE_SPKI_B64_ENCODE, 0),
     "NETSCAPE_SPKI_b64_encode"},
    {ERR_PACK(ERR_LIB_X509, X509_F_NEW_DIR, 0), "new_dir"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509AT_ADD1_ATTR, 0), "X509at_add1_attr"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509V3_ADD_EXT, 0), "X509v3_add_ext"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_ATTRIBUTE_CREATE_BY_NID, 0),
     "X509_ATTRIBUTE_create_by_NID"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ, 0),
     "X509_ATTRIBUTE_create_by_OBJ"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_ATTRIBUTE_CREATE_BY_TXT, 0),
     "X509_ATTRIBUTE_create_by_txt"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_ATTRIBUTE_GET0_DATA, 0),
     "X509_ATTRIBUTE_get0_data"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_ATTRIBUTE_SET1_DATA, 0),
     "X509_ATTRIBUTE_set1_data"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_CHECK_PRIVATE_KEY, 0),
     "X509_check_private_key"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_CRL_DIFF, 0), "X509_CRL_diff"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_CRL_METHOD_NEW, 0),
     "X509_CRL_METHOD_new"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_CRL_PRINT_FP, 0), "X509_CRL_print_fp"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_EXTENSION_CREATE_BY_NID, 0),
     "X509_EXTENSION_create_by_NID"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_EXTENSION_CREATE_BY_OBJ, 0),
     "X509_EXTENSION_create_by_OBJ"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_GET_PUBKEY_PARAMETERS, 0),
     "X509_get_pubkey_parameters"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_LOAD_CERT_CRL_FILE, 0),
     "X509_load_cert_crl_file"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_LOAD_CERT_CRL_FILE_INT, 0),
     "x509_load_cert_crl_file_int"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_LOAD_CERT_FILE, 0),
     "X509_load_cert_file"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_LOAD_CRL_FILE, 0),
     "X509_load_crl_file"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_LOOKUP_BY_ALIAS, 0),
     "X509_LOOKUP_by_alias"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_LOOKUP_BY_FINGERPRINT, 0),
     "X509_LOOKUP_by_fingerprint"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_LOOKUP_BY_ISSUER_SERIAL, 0),
     "X509_LOOKUP_by_issuer_serial"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_LOOKUP_BY_SUBJECT, 0),
     "X509_LOOKUP_by_subject"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_LOOKUP_CTRL, 0), "X509_LOOKUP_ctrl"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_LOOKUP_METH_NEW, 0),
     "X509_LOOKUP_meth_new"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_LOOKUP_NEW, 0), "X509_LOOKUP_new"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_NAME_ADD_ENTRY, 0),
     "X509_NAME_add_entry"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_NAME_CANON, 0), "x509_name_canon"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_NAME_ENTRY_CREATE_BY_NID, 0),
     "X509_NAME_ENTRY_create_by_NID"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_NAME_ENTRY_CREATE_BY_TXT, 0),
     "X509_NAME_ENTRY_create_by_txt"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_NAME_ENTRY_SET_OBJECT, 0),
     "X509_NAME_ENTRY_set_object"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_NAME_ONELINE, 0), "X509_NAME_oneline"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_NAME_PRINT, 0), "X509_NAME_print"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_OBJECT_NEW, 0), "X509_OBJECT_new"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_PRINT_EX_FP, 0), "X509_print_ex_fp"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_PUBKEY_DECODE, 0),
     "x509_pubkey_decode"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_PUBKEY_GET0, 0), "X509_PUBKEY_get0"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_PUBKEY_SET, 0), "X509_PUBKEY_set"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_REQ_CHECK_PRIVATE_KEY, 0),
     "X509_REQ_check_private_key"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_REQ_PRINT_EX, 0), "X509_REQ_print_ex"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_REQ_PRINT_FP, 0), "X509_REQ_print_fp"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_REQ_TO_X509, 0), "X509_REQ_to_X509"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_STORE_ADD_CERT, 0),
     "X509_STORE_add_cert"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_STORE_ADD_CRL, 0),
     "X509_STORE_add_crl"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_STORE_ADD_LOOKUP, 0),
     "X509_STORE_add_lookup"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_STORE_CTX_GET1_ISSUER, 0),
     "X509_STORE_CTX_get1_issuer"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_STORE_CTX_INIT, 0),
     "X509_STORE_CTX_init"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_STORE_CTX_NEW, 0),
     "X509_STORE_CTX_new"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_STORE_CTX_PURPOSE_INHERIT, 0),
     "X509_STORE_CTX_purpose_inherit"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_STORE_NEW, 0), "X509_STORE_new"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_TO_X509_REQ, 0), "X509_to_X509_REQ"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_TRUST_ADD, 0), "X509_TRUST_add"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_TRUST_SET, 0), "X509_TRUST_set"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_VERIFY_CERT, 0), "X509_verify_cert"},
    {ERR_PACK(ERR_LIB_X509, X509_F_X509_VERIFY_PARAM_NEW, 0),
     "X509_VERIFY_PARAM_new"},
    {0, NULL}
};

static const ERR_STRING_DATA X509_str_reasons[] = {
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_AKID_MISMATCH), "akid mismatch"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_BAD_SELECTOR), "bad selector"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_BAD_X509_FILETYPE), "bad x509 filetype"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_BASE64_DECODE_ERROR),
    "base64 decode error"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_CANT_CHECK_DH_KEY), "cant check dh key"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_CERT_ALREADY_IN_HASH_TABLE),
    "cert already in hash table"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_CRL_ALREADY_DELTA), "crl already delta"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_CRL_VERIFY_FAILURE),
    "crl verify failure"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_IDP_MISMATCH), "idp mismatch"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_INVALID_DIRECTORY), "invalid directory"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_INVALID_FIELD_NAME),
    "invalid field name"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_INVALID_LOCATIONS), "invalid locations"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_INVALID_TRUST), "invalid trust"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_ISSUER_MISMATCH), "issuer mismatch"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_KEY_TYPE_MISMATCH), "key type mismatch"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_KEY_VALUES_MISMATCH),
    "key values mismatch"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_LOADING_CERT_DIR), "loading cert dir"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_LOADING_DEFAULTS), "loading defaults"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_METHOD_NOT_SUPPORTED),
    "method not supported"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_NAME_TOO_LONG), "name too long"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_NEWER_CRL_NOT_NEWER),
    "newer crl not newer"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CERTIFICATE_FOUND),
    "no certificate found"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CERTIFICATE_OR_CRL_FOUND),
    "no certificate or crl found"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CERT_SET_FOR_US_TO_VERIFY),
    "no cert set for us to verify"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CRL_FOUND), "no crl found"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CRL_NUMBER), "no crl number"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_PUBLIC_KEY_DECODE_ERROR),
    "public key decode error"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_PUBLIC_KEY_ENCODE_ERROR),
    "public key encode error"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_SHOULD_RETRY), "should retry"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN),
    "unable to find parameters in chain"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY),
    "unable to get certs public key"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNKNOWN_KEY_TYPE), "unknown key type"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNKNOWN_NID), "unknown nid"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNKNOWN_PURPOSE_ID),
    "unknown purpose id"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNKNOWN_TRUST_ID), "unknown trust id"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNSUPPORTED_ALGORITHM),
    "unsupported algorithm"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_WRONG_LOOKUP_TYPE), "wrong lookup type"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_WRONG_TYPE), "wrong type"},
    {0, NULL}
};

#endif

int ERR_load_X509_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_func_error_string(X509_str_functs[0].error) == NULL) {
        ERR_load_strings_const(X509_str_functs);
        ERR_load_strings_const(X509_str_reasons);
    }
#endif
    return 1;
}

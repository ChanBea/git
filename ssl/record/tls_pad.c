/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/rand.h>
#include "internal/constant_time.h"
#include "internal/cryptlib.h"
#include "../ssl_local.h"
#include "record_local.h"

static int ssl3_cbc_copy_mac(const SSL *s,
                             SSL3_RECORD *rec,
                             unsigned char **mac,
                             int *alloced,
                             size_t block_size,
                             size_t mac_size,
                             size_t good);

/*-
 * ssl3_cbc_remove_padding removes padding from the decrypted, SSLv3, CBC
 * record in |rec| by updating |rec->length| in constant time. It also extracts
 * the MAC from the underlying record.
 *
 * block_size: the block size of the cipher used to encrypt the record.
 * returns:
 *   0: if the record is publicly invalid.
 *   1: if the record is publicly valid. If the padding removal fails then the
 *      MAC returned is random.
 */
int ssl3_cbc_remove_padding_and_mac(SSL *s,
                                    SSL3_RECORD *rec,
                                    unsigned char **mac,
                                    int *alloced,
                                    size_t block_size, size_t mac_size)
{
    size_t padding_length;
    size_t good;
    const size_t overhead = 1 /* padding length byte */  + mac_size;

    /*
     * These lengths are all public so we can test them in non-constant time.
     */
    if (overhead > rec->length)
        return 0;

    padding_length = rec->data[rec->length - 1];
    good = constant_time_ge_s(rec->length, padding_length + overhead);
    /* SSLv3 requires that the padding is minimal. */
    good &= constant_time_ge_s(block_size, padding_length + 1);
    rec->length -= good & (padding_length + 1);

    return ssl3_cbc_copy_mac(s, rec, mac, alloced, block_size, mac_size, good);
}

/*-
 * tls1_cbc_remove_padding removes the CBC padding from the decrypted, TLS, CBC
 * record in |rec| in constant time. It also removes any explicit IV from the
 * start of the record without leaking any timing about whether there was enough
 * space after the padding was removed, as well as extracting the embedded MAC
 * (also in constant time). For Mac-then-encrypt, if the padding is invalid then
 * a success result will occur and a randomised MAC will be returned.
 *
 * block_size: the block size of the cipher used to encrypt the record.
 * returns:
 *    0: if the record is publicly invalid, or an internal error
 *    1: Success or Mac-then-encrypt decryption failed (MAC will be randomised)
 */
int tls1_cbc_remove_padding_and_mac(const SSL *s,
                                    SSL3_RECORD *rec,
                                    unsigned char **mac,
                                    int *alloced,
                                    size_t block_size, size_t mac_size)
{
    size_t good;
    size_t padding_length, to_check, i;
    size_t overhead = ((block_size == 1) ? 0 : 1) /* padding length byte */
                      + (SSL_USE_EXPLICIT_IV(s) ? block_size : 0)
                      + mac_size;

    /*
     * These lengths are all public so we can test them in non-constant
     * time.
     */
    if (overhead > rec->length)
        return 0;

    if (block_size != 1) {
        if (SSL_USE_EXPLICIT_IV(s)) {
            rec->data += block_size;
            rec->input += block_size;
            rec->length -= block_size;
            rec->orig_len -= block_size;
            overhead -= block_size;
        }

        padding_length = rec->data[rec->length - 1];

        if (EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(s->enc_read_ctx)) &
            EVP_CIPH_FLAG_AEAD_CIPHER) {
            /* padding is already verified and we don't need to check the MAC */
            rec->length -= padding_length + 1 + mac_size;
            *mac = NULL;
            *alloced = 0;
            return 1;
        }

        good = constant_time_ge_s(rec->length, overhead + padding_length);
        /*
         * The padding consists of a length byte at the end of the record and
         * then that many bytes of padding, all with the same value as the
         * length byte. Thus, with the length byte included, there are i+1 bytes
         * of padding. We can't check just |padding_length+1| bytes because that
         * leaks decrypted information. Therefore we always have to check the
         * maximum amount of padding possible. (Again, the length of the record
         * is public information so we can use it.)
         */
        to_check = 256;        /* maximum amount of padding, inc length byte. */
        if (to_check > rec->length)
            to_check = rec->length;

        for (i = 0; i < to_check; i++) {
            unsigned char mask = constant_time_ge_8_s(padding_length, i);
            unsigned char b = rec->data[rec->length - 1 - i];
            /*
             * The final |padding_length+1| bytes should all have the value
             * |padding_length|. Therefore the XOR should be zero.
             */
            good &= ~(mask & (padding_length ^ b));
        }

        /*
         * If any of the final |padding_length+1| bytes had the wrong value, one
         * or more of the lower eight bits of |good| will be cleared.
         */
        good = constant_time_eq_s(0xff, good & 0xff);
        rec->length -= good & (padding_length + 1);
    }

    return ssl3_cbc_copy_mac(s, rec, mac, alloced, block_size, mac_size, good);
}

/*-
 * ssl3_cbc_copy_mac copies |md_size| bytes from the end of |rec| to |out| in
 * constant time (independent of the concrete value of rec->length, which may
 * vary within a 256-byte window).
 *
 * On entry:
 *   rec->orig_len >= md_size
 *   md_size <= EVP_MAX_MD_SIZE
 *
 * If CBC_MAC_ROTATE_IN_PLACE is defined then the rotation is performed with
 * variable accesses in a 64-byte-aligned buffer. Assuming that this fits into
 * a single or pair of cache-lines, then the variable memory accesses don't
 * actually affect the timing. CPUs with smaller cache-lines [if any] are
 * not multi-core and are not considered vulnerable to cache-timing attacks.
 */
#define CBC_MAC_ROTATE_IN_PLACE

static int ssl3_cbc_copy_mac(const SSL *s,
                             SSL3_RECORD *rec,
                             unsigned char **mac,
                             int *alloced,
                             size_t block_size,
                             size_t mac_size,
                             size_t good)
{
#if defined(CBC_MAC_ROTATE_IN_PLACE)
    unsigned char rotated_mac_buf[64 + EVP_MAX_MD_SIZE];
    unsigned char *rotated_mac;
#else
    unsigned char rotated_mac[EVP_MAX_MD_SIZE];
#endif
    unsigned char randmac[EVP_MAX_MD_SIZE];
    unsigned char *out;

    /*
     * mac_end is the index of |rec->data| just after the end of the MAC.
     */
    size_t mac_end = rec->length;
    size_t mac_start = mac_end - mac_size;
    size_t in_mac;
    /*
     * scan_start contains the number of bytes that we can ignore because the
     * MAC's position can only vary by 255 bytes.
     */
    size_t scan_start = 0;
    size_t i, j;
    size_t rotate_offset;

    if (!ossl_assert(rec->orig_len >= mac_size
                     && mac_size <= EVP_MAX_MD_SIZE))
        return 0;

    /* If no MAC then nothing to be done */
    if (mac_size == 0) {
        /* No MAC so we can do this in non-constant time */
        if (good == 0)
            return 0;
        return 1;
    }

    rec->length -= mac_size;

    if (block_size == 1) {
        /* There's no padding so the position of the MAC is fixed */
        if (mac != NULL)
            *mac = &rec->data[rec->length];
        if (alloced != NULL)
            *alloced = 0;
        return 1;
    }

    /* Create the random MAC we will emit if padding is bad */
    if (!RAND_bytes_ex(s->ctx->libctx, randmac, mac_size))
        return 0;

    if (!ossl_assert(mac != NULL && alloced != NULL))
        return 0;
    *mac = out = OPENSSL_malloc(mac_size);
    if (*mac == NULL)
        return 0;
    *alloced = 1;

#if defined(CBC_MAC_ROTATE_IN_PLACE)
    rotated_mac = rotated_mac_buf + ((0 - (size_t)rotated_mac_buf) & 63);
#endif

    /* This information is public so it's safe to branch based on it. */
    if (rec->orig_len > mac_size + 255 + 1)
        scan_start = rec->orig_len - (mac_size + 255 + 1);

    in_mac = 0;
    rotate_offset = 0;
    memset(rotated_mac, 0, mac_size);
    for (i = scan_start, j = 0; i < rec->orig_len; i++) {
        size_t mac_started = constant_time_eq_s(i, mac_start);
        size_t mac_ended = constant_time_lt_s(i, mac_end);
        unsigned char b = rec->data[i];

        in_mac |= mac_started;
        in_mac &= mac_ended;
        rotate_offset |= j & mac_started;
        rotated_mac[j++] |= b & in_mac;
        j &= constant_time_lt_s(j, mac_size);
    }

    /* Now rotate the MAC */
#if defined(CBC_MAC_ROTATE_IN_PLACE)
    j = 0;
    for (i = 0; i < mac_size; i++) {
        /* in case cache-line is 32 bytes, touch second line */
        ((volatile unsigned char *)rotated_mac)[rotate_offset ^ 32];

        /* If the padding wasn't good we emit a random MAC */
        out[j++] = constant_time_select_8((unsigned char)(good & 0xff),
                                          rotated_mac[rotate_offset++],
                                          randmac[i]);
        rotate_offset &= constant_time_lt_s(rotate_offset, mac_size);
    }
#else
    memset(out, 0, mac_size);
    rotate_offset = mac_size - rotate_offset;
    rotate_offset &= constant_time_lt_s(rotate_offset, mac_size);
    for (i = 0; i < mac_size; i++) {
        for (j = 0; j < mac_size; j++)
            out[j] |= rotated_mac[i] & constant_time_eq_8_s(j, rotate_offset);
        rotate_offset++;
        rotate_offset &= constant_time_lt_s(rotate_offset, mac_size);

        /* If the padding wasn't good we emit a random MAC */
        out[i] = constant_time_select_8((unsigned char)(good & 0xff), out[i],
                                        randmac[i]);
    }
#endif

    return 1;
}

/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <internal/quic_tserver.h>

/* Type to represent the Fault Injector */
typedef struct ossl_quic_fault OSSL_QUIC_FAULT;

/*
 * Structure representing a parse EncryptedExtension message. Listeners can
 * make changes to the contents of structure objects as required and the fault
 * injector will reconstruct the message to be sent on
 */
typedef struct ossl_qf_encrypted_extensions {
    /* EncryptedExtension messages just have an extensions block */
    unsigned char *extensions;
    size_t extensionslen;
} OSSL_QF_ENCRYPTED_EXTENSIONS;

/*
 * Given an SSL_CTX for the client and filenames for the server certificate and
 * keyfile, create a server and client instances as well as a fault injector
 * instance
 */
int qtest_create_quic_objects(SSL_CTX *clientctx, char *certfile, char *keyfile,
                              QUIC_TSERVER **qtserv, SSL **cssl,
                              OSSL_QUIC_FAULT **fault);

/*
 * Free up a Fault Injector instance
 */
void ossl_quic_fault_free(OSSL_QUIC_FAULT *fault);

/*
 * Run the TLS handshake to create a QUIC connection between the client and
 * server.
 */
int qtest_create_quic_connection(QUIC_TSERVER *qtserv, SSL *clientssl);

/*
 * Confirm the server has received a protocol error
 */
int qtest_check_server_protocol_err(QUIC_TSERVER *qtserv);

/*
 * Enable tests to listen for pre-encryption QUIC packets being sent
 */
typedef int (*ossl_quic_fault_on_packet_plain_cb)(OSSL_QUIC_FAULT *fault,
                                                  QUIC_PKT_HDR *hdr,
                                                  unsigned char *buf,
                                                  size_t len,
                                                  void *cbarg);

int ossl_quic_fault_set_packet_plain_listener(OSSL_QUIC_FAULT *fault,
                                              ossl_quic_fault_on_packet_plain_cb pplaincb,
                                              void *pplaincbarg);

/*
 * Helper function to be called from a packet_plain_listener callback if it
 * wants to resize the packet (either to add new data to it, or to truncate it)
 */
int ossl_quic_fault_resize_plain_packet(OSSL_QUIC_FAULT *fault, size_t newlen);

/*
 * The general handshake message listener is sent the entire handshake message
 * data block, including the handshake header itself
 */
typedef int (*ossl_quic_fault_on_handshake_cb)(OSSL_QUIC_FAULT *fault,
                                               unsigned char *msg,
                                               size_t msglen,
                                               void *handshakecbarg);

int ossl_quic_fault_set_handshake_listener(OSSL_QUIC_FAULT *fault,
                                           ossl_quic_fault_on_handshake_cb handshakecb,
                                           void *handshakecbarg);

/*
 * Helper function to be called from a handshake_listener callback if it wants
 * to rezie the handshake message (either to add new data to it, or to truncate
 * it). newlen must include the length of the handshake message header.
 */
int ossl_quic_fault_resize_handshake(OSSL_QUIC_FAULT *fault, size_t newlen);

/*
 * TODO(QUIC): Add listeners for specifc types of frame here. E.g. we might
 * expect to see an "ACK" frame listener which will be passed pre-parsed ack
 * data that can be modified as required.
 */

/*
 * Handshake message specific listeners. Unlike the general handshake message
 * listener these messages are pre-parsed and supplied with message specific
 * data and exclude the handshake header
 */
typedef int (*ossl_quic_fault_on_enc_ext_cb)(OSSL_QUIC_FAULT *fault,
                                             OSSL_QF_ENCRYPTED_EXTENSIONS *ee,
                                             size_t eelen,
                                             void *encextcbarg);

int ossl_quic_fault_set_hand_enc_ext_listener(OSSL_QUIC_FAULT *fault,
                                              ossl_quic_fault_on_enc_ext_cb encextcb,
                                              void *encextcbarg);

/* TODO(QUIC): Add listeners for other types of handshake message here */


/*
 * Helper function to be called from message specific listener callbacks. newlen
 * is the new length of the specific message excluding the handshake message
 * header.
 */
int ossl_quic_fault_resize_message(OSSL_QUIC_FAULT *fault, size_t newlen);

/*
 * Helper function to delete an extension from an extension block. |exttype| is
 * the type of the extension to be deleted. |ext| points to the extension block.
 * On entry |*extlen| contains the length of the extension block. It is updated
 * with the new length on exit.
 */
int ossl_quic_fault_delete_extension(OSSL_QUIC_FAULT *fault,
                                     unsigned int exttype, unsigned char *ext,
                                     size_t *extlen);

/*
 * TODO(QUIC): Add additional helper functions for quering extensions here (e.g.
 * finding or adding them). We could also provide a "listener" API for listening
 * for specific extension types
 */

/* TODO(QUIC): Add a listener for a datagram here */
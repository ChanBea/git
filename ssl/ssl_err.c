/* ssl/ssl_err.c */
/* ====================================================================
 * Copyright (c) 1999-2014 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* NOTE: this file was auto generated by the mkerr.pl script: any changes
 * made to it will be overwritten when the script next updates this file,
 * only reason strings will be preserved.
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

#define ERR_FUNC(func) ERR_PACK(ERR_LIB_SSL,func,0)
#define ERR_REASON(reason) ERR_PACK(ERR_LIB_SSL,0,reason)

static ERR_STRING_DATA SSL_str_functs[]=
	{
{ERR_FUNC(SSL_F_CHECK_SUITEB_CIPHER_LIST),	"CHECK_SUITEB_CIPHER_LIST"},
{ERR_FUNC(SSL_F_D2I_SSL_SESSION),	"d2i_SSL_SESSION"},
{ERR_FUNC(SSL_F_DO_DTLS1_WRITE),	"do_dtls1_write"},
{ERR_FUNC(SSL_F_DO_SSL3_WRITE),	"DO_SSL3_WRITE"},
{ERR_FUNC(SSL_F_DTLS1_ACCEPT),	"dtls1_accept"},
{ERR_FUNC(SSL_F_DTLS1_ADD_CERT_TO_BUF),	"DTLS1_ADD_CERT_TO_BUF"},
{ERR_FUNC(SSL_F_DTLS1_BUFFER_RECORD),	"DTLS1_BUFFER_RECORD"},
{ERR_FUNC(SSL_F_DTLS1_CHECK_TIMEOUT_NUM),	"dtls1_check_timeout_num"},
{ERR_FUNC(SSL_F_DTLS1_CLIENT_HELLO),	"dtls1_client_hello"},
{ERR_FUNC(SSL_F_DTLS1_CONNECT),	"dtls1_connect"},
{ERR_FUNC(SSL_F_DTLS1_GET_HELLO_VERIFY),	"DTLS1_GET_HELLO_VERIFY"},
{ERR_FUNC(SSL_F_DTLS1_GET_MESSAGE),	"dtls1_get_message"},
{ERR_FUNC(SSL_F_DTLS1_GET_MESSAGE_FRAGMENT),	"DTLS1_GET_MESSAGE_FRAGMENT"},
{ERR_FUNC(SSL_F_DTLS1_GET_RECORD),	"dtls1_get_record"},
{ERR_FUNC(SSL_F_DTLS1_HANDLE_TIMEOUT),	"dtls1_handle_timeout"},
{ERR_FUNC(SSL_F_DTLS1_HEARTBEAT),	"dtls1_heartbeat"},
{ERR_FUNC(SSL_F_DTLS1_OUTPUT_CERT_CHAIN),	"dtls1_output_cert_chain"},
{ERR_FUNC(SSL_F_DTLS1_PREPROCESS_FRAGMENT),	"DTLS1_PREPROCESS_FRAGMENT"},
{ERR_FUNC(SSL_F_DTLS1_PROCESS_OUT_OF_SEQ_MESSAGE),	"DTLS1_PROCESS_OUT_OF_SEQ_MESSAGE"},
{ERR_FUNC(SSL_F_DTLS1_PROCESS_RECORD),	"DTLS1_PROCESS_RECORD"},
{ERR_FUNC(SSL_F_DTLS1_READ_BYTES),	"dtls1_read_bytes"},
{ERR_FUNC(SSL_F_DTLS1_READ_FAILED),	"dtls1_read_failed"},
{ERR_FUNC(SSL_F_DTLS1_SEND_CERTIFICATE_REQUEST),	"dtls1_send_certificate_request"},
{ERR_FUNC(SSL_F_DTLS1_SEND_CLIENT_CERTIFICATE),	"dtls1_send_client_certificate"},
{ERR_FUNC(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE),	"dtls1_send_client_key_exchange"},
{ERR_FUNC(SSL_F_DTLS1_SEND_CLIENT_VERIFY),	"dtls1_send_client_verify"},
{ERR_FUNC(SSL_F_DTLS1_SEND_HELLO_VERIFY_REQUEST),	"DTLS1_SEND_HELLO_VERIFY_REQUEST"},
{ERR_FUNC(SSL_F_DTLS1_SEND_SERVER_CERTIFICATE),	"dtls1_send_server_certificate"},
{ERR_FUNC(SSL_F_DTLS1_SEND_SERVER_HELLO),	"dtls1_send_server_hello"},
{ERR_FUNC(SSL_F_DTLS1_SEND_SERVER_KEY_EXCHANGE),	"dtls1_send_server_key_exchange"},
{ERR_FUNC(SSL_F_DTLS1_WRITE_APP_DATA_BYTES),	"dtls1_write_app_data_bytes"},
{ERR_FUNC(SSL_F_SSL23_ACCEPT),	"ssl23_accept"},
{ERR_FUNC(SSL_F_SSL23_CLIENT_HELLO),	"SSL23_CLIENT_HELLO"},
{ERR_FUNC(SSL_F_SSL23_CONNECT),	"ssl23_connect"},
{ERR_FUNC(SSL_F_SSL23_GET_CLIENT_HELLO),	"SSL23_GET_CLIENT_HELLO"},
{ERR_FUNC(SSL_F_SSL23_GET_SERVER_HELLO),	"SSL23_GET_SERVER_HELLO"},
{ERR_FUNC(SSL_F_SSL23_PEEK),	"ssl23_peek"},
{ERR_FUNC(SSL_F_SSL23_READ),	"ssl23_read"},
{ERR_FUNC(SSL_F_SSL23_WRITE),	"ssl23_write"},
{ERR_FUNC(SSL_F_SSL3_ACCEPT),	"ssl3_accept"},
{ERR_FUNC(SSL_F_SSL3_ADD_CERT_TO_BUF),	"SSL3_ADD_CERT_TO_BUF"},
{ERR_FUNC(SSL_F_SSL3_CALLBACK_CTRL),	"ssl3_callback_ctrl"},
{ERR_FUNC(SSL_F_SSL3_CHANGE_CIPHER_STATE),	"ssl3_change_cipher_state"},
{ERR_FUNC(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM),	"ssl3_check_cert_and_algorithm"},
{ERR_FUNC(SSL_F_SSL3_CHECK_CLIENT_HELLO),	"ssl3_check_client_hello"},
{ERR_FUNC(SSL_F_SSL3_CLIENT_HELLO),	"ssl3_client_hello"},
{ERR_FUNC(SSL_F_SSL3_CONNECT),	"ssl3_connect"},
{ERR_FUNC(SSL_F_SSL3_CTRL),	"ssl3_ctrl"},
{ERR_FUNC(SSL_F_SSL3_CTX_CTRL),	"ssl3_ctx_ctrl"},
{ERR_FUNC(SSL_F_SSL3_DIGEST_CACHED_RECORDS),	"ssl3_digest_cached_records"},
{ERR_FUNC(SSL_F_SSL3_DO_CHANGE_CIPHER_SPEC),	"ssl3_do_change_cipher_spec"},
{ERR_FUNC(SSL_F_SSL3_ENC),	"ssl3_enc"},
{ERR_FUNC(SSL_F_SSL3_GENERATE_KEY_BLOCK),	"SSL3_GENERATE_KEY_BLOCK"},
{ERR_FUNC(SSL_F_SSL3_GET_CERTIFICATE_REQUEST),	"ssl3_get_certificate_request"},
{ERR_FUNC(SSL_F_SSL3_GET_CERT_STATUS),	"ssl3_get_cert_status"},
{ERR_FUNC(SSL_F_SSL3_GET_CERT_VERIFY),	"ssl3_get_cert_verify"},
{ERR_FUNC(SSL_F_SSL3_GET_CLIENT_CERTIFICATE),	"ssl3_get_client_certificate"},
{ERR_FUNC(SSL_F_SSL3_GET_CLIENT_HELLO),	"ssl3_get_client_hello"},
{ERR_FUNC(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE),	"ssl3_get_client_key_exchange"},
{ERR_FUNC(SSL_F_SSL3_GET_FINISHED),	"ssl3_get_finished"},
{ERR_FUNC(SSL_F_SSL3_GET_KEY_EXCHANGE),	"ssl3_get_key_exchange"},
{ERR_FUNC(SSL_F_SSL3_GET_MESSAGE),	"ssl3_get_message"},
{ERR_FUNC(SSL_F_SSL3_GET_NEW_SESSION_TICKET),	"ssl3_get_new_session_ticket"},
{ERR_FUNC(SSL_F_SSL3_GET_NEXT_PROTO),	"ssl3_get_next_proto"},
{ERR_FUNC(SSL_F_SSL3_GET_RECORD),	"SSL3_GET_RECORD"},
{ERR_FUNC(SSL_F_SSL3_GET_SERVER_CERTIFICATE),	"ssl3_get_server_certificate"},
{ERR_FUNC(SSL_F_SSL3_GET_SERVER_DONE),	"ssl3_get_server_done"},
{ERR_FUNC(SSL_F_SSL3_GET_SERVER_HELLO),	"ssl3_get_server_hello"},
{ERR_FUNC(SSL_F_SSL3_HANDSHAKE_MAC),	"ssl3_handshake_mac"},
{ERR_FUNC(SSL_F_SSL3_NEW_SESSION_TICKET),	"SSL3_NEW_SESSION_TICKET"},
{ERR_FUNC(SSL_F_SSL3_OUTPUT_CERT_CHAIN),	"ssl3_output_cert_chain"},
{ERR_FUNC(SSL_F_SSL3_PEEK),	"ssl3_peek"},
{ERR_FUNC(SSL_F_SSL3_READ_BYTES),	"ssl3_read_bytes"},
{ERR_FUNC(SSL_F_SSL3_READ_N),	"ssl3_read_n"},
{ERR_FUNC(SSL_F_SSL3_SEND_CERTIFICATE_REQUEST),	"ssl3_send_certificate_request"},
{ERR_FUNC(SSL_F_SSL3_SEND_CLIENT_CERTIFICATE),	"ssl3_send_client_certificate"},
{ERR_FUNC(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE),	"ssl3_send_client_key_exchange"},
{ERR_FUNC(SSL_F_SSL3_SEND_CLIENT_VERIFY),	"ssl3_send_client_verify"},
{ERR_FUNC(SSL_F_SSL3_SEND_SERVER_CERTIFICATE),	"ssl3_send_server_certificate"},
{ERR_FUNC(SSL_F_SSL3_SEND_SERVER_HELLO),	"ssl3_send_server_hello"},
{ERR_FUNC(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE),	"ssl3_send_server_key_exchange"},
{ERR_FUNC(SSL_F_SSL3_SETUP_KEY_BLOCK),	"ssl3_setup_key_block"},
{ERR_FUNC(SSL_F_SSL3_SETUP_READ_BUFFER),	"ssl3_setup_read_buffer"},
{ERR_FUNC(SSL_F_SSL3_SETUP_WRITE_BUFFER),	"ssl3_setup_write_buffer"},
{ERR_FUNC(SSL_F_SSL3_WRITE_BYTES),	"ssl3_write_bytes"},
{ERR_FUNC(SSL_F_SSL3_WRITE_PENDING),	"ssl3_write_pending"},
{ERR_FUNC(SSL_F_SSL_ADD_CERT_CHAIN),	"ssl_add_cert_chain"},
{ERR_FUNC(SSL_F_SSL_ADD_CERT_TO_BUF),	"SSL_ADD_CERT_TO_BUF"},
{ERR_FUNC(SSL_F_SSL_ADD_CLIENTHELLO_RENEGOTIATE_EXT),	"ssl_add_clienthello_renegotiate_ext"},
{ERR_FUNC(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT),	"ssl_add_clienthello_tlsext"},
{ERR_FUNC(SSL_F_SSL_ADD_CLIENTHELLO_USE_SRTP_EXT),	"ssl_add_clienthello_use_srtp_ext"},
{ERR_FUNC(SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK),	"SSL_add_dir_cert_subjects_to_stack"},
{ERR_FUNC(SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK),	"SSL_add_file_cert_subjects_to_stack"},
{ERR_FUNC(SSL_F_SSL_ADD_SERVERHELLO_RENEGOTIATE_EXT),	"ssl_add_serverhello_renegotiate_ext"},
{ERR_FUNC(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT),	"ssl_add_serverhello_tlsext"},
{ERR_FUNC(SSL_F_SSL_ADD_SERVERHELLO_USE_SRTP_EXT),	"ssl_add_serverhello_use_srtp_ext"},
{ERR_FUNC(SSL_F_SSL_BAD_METHOD),	"ssl_bad_method"},
{ERR_FUNC(SSL_F_SSL_BUILD_CERT_CHAIN),	"ssl_build_cert_chain"},
{ERR_FUNC(SSL_F_SSL_BYTES_TO_CIPHER_LIST),	"ssl_bytes_to_cipher_list"},
{ERR_FUNC(SSL_F_SSL_CERT_ADD0_CHAIN_CERT),	"ssl_cert_add0_chain_cert"},
{ERR_FUNC(SSL_F_SSL_CERT_DUP),	"ssl_cert_dup"},
{ERR_FUNC(SSL_F_SSL_CERT_INST),	"ssl_cert_inst"},
{ERR_FUNC(SSL_F_SSL_CERT_INSTANTIATE),	"SSL_CERT_INSTANTIATE"},
{ERR_FUNC(SSL_F_SSL_CERT_NEW),	"ssl_cert_new"},
{ERR_FUNC(SSL_F_SSL_CERT_SET0_CHAIN),	"ssl_cert_set0_chain"},
{ERR_FUNC(SSL_F_SSL_CHECK_PRIVATE_KEY),	"SSL_check_private_key"},
{ERR_FUNC(SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT),	"SSL_CHECK_SERVERHELLO_TLSEXT"},
{ERR_FUNC(SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG),	"ssl_check_srvr_ecc_cert_and_alg"},
{ERR_FUNC(SSL_F_SSL_CIPHER_PROCESS_RULESTR),	"SSL_CIPHER_PROCESS_RULESTR"},
{ERR_FUNC(SSL_F_SSL_CIPHER_STRENGTH_SORT),	"SSL_CIPHER_STRENGTH_SORT"},
{ERR_FUNC(SSL_F_SSL_CLEAR),	"SSL_clear"},
{ERR_FUNC(SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD),	"SSL_COMP_add_compression_method"},
{ERR_FUNC(SSL_F_SSL_CONF_CMD),	"SSL_CONF_cmd"},
{ERR_FUNC(SSL_F_SSL_CREATE_CIPHER_LIST),	"ssl_create_cipher_list"},
{ERR_FUNC(SSL_F_SSL_CTRL),	"SSL_ctrl"},
{ERR_FUNC(SSL_F_SSL_CTX_CHECK_PRIVATE_KEY),	"SSL_CTX_check_private_key"},
{ERR_FUNC(SSL_F_SSL_CTX_MAKE_PROFILES),	"SSL_CTX_MAKE_PROFILES"},
{ERR_FUNC(SSL_F_SSL_CTX_NEW),	"SSL_CTX_new"},
{ERR_FUNC(SSL_F_SSL_CTX_SET_CIPHER_LIST),	"SSL_CTX_set_cipher_list"},
{ERR_FUNC(SSL_F_SSL_CTX_SET_CLIENT_CERT_ENGINE),	"SSL_CTX_set_client_cert_engine"},
{ERR_FUNC(SSL_F_SSL_CTX_SET_PURPOSE),	"SSL_CTX_set_purpose"},
{ERR_FUNC(SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT),	"SSL_CTX_set_session_id_context"},
{ERR_FUNC(SSL_F_SSL_CTX_SET_SSL_VERSION),	"SSL_CTX_set_ssl_version"},
{ERR_FUNC(SSL_F_SSL_CTX_SET_TRUST),	"SSL_CTX_set_trust"},
{ERR_FUNC(SSL_F_SSL_CTX_USE_CERTIFICATE),	"SSL_CTX_use_certificate"},
{ERR_FUNC(SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1),	"SSL_CTX_use_certificate_ASN1"},
{ERR_FUNC(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE),	"SSL_CTX_use_certificate_chain_file"},
{ERR_FUNC(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE),	"SSL_CTX_use_certificate_file"},
{ERR_FUNC(SSL_F_SSL_CTX_USE_PRIVATEKEY),	"SSL_CTX_use_PrivateKey"},
{ERR_FUNC(SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1),	"SSL_CTX_use_PrivateKey_ASN1"},
{ERR_FUNC(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE),	"SSL_CTX_use_PrivateKey_file"},
{ERR_FUNC(SSL_F_SSL_CTX_USE_PSK_IDENTITY_HINT),	"SSL_CTX_use_psk_identity_hint"},
{ERR_FUNC(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY),	"SSL_CTX_use_RSAPrivateKey"},
{ERR_FUNC(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1),	"SSL_CTX_use_RSAPrivateKey_ASN1"},
{ERR_FUNC(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE),	"SSL_CTX_use_RSAPrivateKey_file"},
{ERR_FUNC(SSL_F_SSL_CTX_USE_SERVERINFO),	"SSL_CTX_use_serverinfo"},
{ERR_FUNC(SSL_F_SSL_CTX_USE_SERVERINFO_FILE),	"SSL_CTX_use_serverinfo_file"},
{ERR_FUNC(SSL_F_SSL_DO_HANDSHAKE),	"SSL_do_handshake"},
{ERR_FUNC(SSL_F_SSL_GET_NEW_SESSION),	"ssl_get_new_session"},
{ERR_FUNC(SSL_F_SSL_GET_PREV_SESSION),	"ssl_get_prev_session"},
{ERR_FUNC(SSL_F_SSL_GET_SERVER_CERT_INDEX),	"SSL_GET_SERVER_CERT_INDEX"},
{ERR_FUNC(SSL_F_SSL_GET_SERVER_SEND_CERT),	"SSL_GET_SERVER_SEND_CERT"},
{ERR_FUNC(SSL_F_SSL_GET_SERVER_SEND_PKEY),	"ssl_get_server_send_pkey"},
{ERR_FUNC(SSL_F_SSL_GET_SIGN_PKEY),	"ssl_get_sign_pkey"},
{ERR_FUNC(SSL_F_SSL_INIT_WBIO_BUFFER),	"ssl_init_wbio_buffer"},
{ERR_FUNC(SSL_F_SSL_LOAD_CLIENT_CA_FILE),	"SSL_load_client_CA_file"},
{ERR_FUNC(SSL_F_SSL_NEW),	"SSL_new"},
{ERR_FUNC(SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT),	"ssl_parse_clienthello_renegotiate_ext"},
{ERR_FUNC(SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT),	"ssl_parse_clienthello_tlsext"},
{ERR_FUNC(SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT),	"ssl_parse_clienthello_use_srtp_ext"},
{ERR_FUNC(SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT),	"ssl_parse_serverhello_renegotiate_ext"},
{ERR_FUNC(SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT),	"ssl_parse_serverhello_tlsext"},
{ERR_FUNC(SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT),	"ssl_parse_serverhello_use_srtp_ext"},
{ERR_FUNC(SSL_F_SSL_PEEK),	"SSL_peek"},
{ERR_FUNC(SSL_F_SSL_PREPARE_CLIENTHELLO_TLSEXT),	"ssl_prepare_clienthello_tlsext"},
{ERR_FUNC(SSL_F_SSL_PREPARE_SERVERHELLO_TLSEXT),	"ssl_prepare_serverhello_tlsext"},
{ERR_FUNC(SSL_F_SSL_READ),	"SSL_read"},
{ERR_FUNC(SSL_F_SSL_SCAN_CLIENTHELLO_TLSEXT),	"SSL_SCAN_CLIENTHELLO_TLSEXT"},
{ERR_FUNC(SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT),	"SSL_SCAN_SERVERHELLO_TLSEXT"},
{ERR_FUNC(SSL_F_SSL_SESSION_NEW),	"SSL_SESSION_new"},
{ERR_FUNC(SSL_F_SSL_SESSION_PRINT_FP),	"SSL_SESSION_print_fp"},
{ERR_FUNC(SSL_F_SSL_SESSION_SET1_ID_CONTEXT),	"SSL_SESSION_set1_id_context"},
{ERR_FUNC(SSL_F_SSL_SESS_CERT_NEW),	"ssl_sess_cert_new"},
{ERR_FUNC(SSL_F_SSL_SET_CERT),	"SSL_SET_CERT"},
{ERR_FUNC(SSL_F_SSL_SET_CIPHER_LIST),	"SSL_set_cipher_list"},
{ERR_FUNC(SSL_F_SSL_SET_FD),	"SSL_set_fd"},
{ERR_FUNC(SSL_F_SSL_SET_PKEY),	"SSL_SET_PKEY"},
{ERR_FUNC(SSL_F_SSL_SET_PURPOSE),	"SSL_set_purpose"},
{ERR_FUNC(SSL_F_SSL_SET_RFD),	"SSL_set_rfd"},
{ERR_FUNC(SSL_F_SSL_SET_SESSION),	"SSL_set_session"},
{ERR_FUNC(SSL_F_SSL_SET_SESSION_ID_CONTEXT),	"SSL_set_session_id_context"},
{ERR_FUNC(SSL_F_SSL_SET_SESSION_TICKET_EXT),	"SSL_set_session_ticket_ext"},
{ERR_FUNC(SSL_F_SSL_SET_TRUST),	"SSL_set_trust"},
{ERR_FUNC(SSL_F_SSL_SET_WFD),	"SSL_set_wfd"},
{ERR_FUNC(SSL_F_SSL_SHUTDOWN),	"SSL_shutdown"},
{ERR_FUNC(SSL_F_SSL_SRP_CTX_INIT),	"SSL_SRP_CTX_init"},
{ERR_FUNC(SSL_F_SSL_UNDEFINED_CONST_FUNCTION),	"ssl_undefined_const_function"},
{ERR_FUNC(SSL_F_SSL_UNDEFINED_FUNCTION),	"ssl_undefined_function"},
{ERR_FUNC(SSL_F_SSL_UNDEFINED_VOID_FUNCTION),	"ssl_undefined_void_function"},
{ERR_FUNC(SSL_F_SSL_USE_CERTIFICATE),	"SSL_use_certificate"},
{ERR_FUNC(SSL_F_SSL_USE_CERTIFICATE_ASN1),	"SSL_use_certificate_ASN1"},
{ERR_FUNC(SSL_F_SSL_USE_CERTIFICATE_FILE),	"SSL_use_certificate_file"},
{ERR_FUNC(SSL_F_SSL_USE_PRIVATEKEY),	"SSL_use_PrivateKey"},
{ERR_FUNC(SSL_F_SSL_USE_PRIVATEKEY_ASN1),	"SSL_use_PrivateKey_ASN1"},
{ERR_FUNC(SSL_F_SSL_USE_PRIVATEKEY_FILE),	"SSL_use_PrivateKey_file"},
{ERR_FUNC(SSL_F_SSL_USE_PSK_IDENTITY_HINT),	"SSL_use_psk_identity_hint"},
{ERR_FUNC(SSL_F_SSL_USE_RSAPRIVATEKEY),	"SSL_use_RSAPrivateKey"},
{ERR_FUNC(SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1),	"SSL_use_RSAPrivateKey_ASN1"},
{ERR_FUNC(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE),	"SSL_use_RSAPrivateKey_file"},
{ERR_FUNC(SSL_F_SSL_VERIFY_CERT_CHAIN),	"ssl_verify_cert_chain"},
{ERR_FUNC(SSL_F_SSL_WRITE),	"SSL_write"},
{ERR_FUNC(SSL_F_TLS12_CHECK_PEER_SIGALG),	"tls12_check_peer_sigalg"},
{ERR_FUNC(SSL_F_TLS1_CERT_VERIFY_MAC),	"tls1_cert_verify_mac"},
{ERR_FUNC(SSL_F_TLS1_CHANGE_CIPHER_STATE),	"tls1_change_cipher_state"},
{ERR_FUNC(SSL_F_TLS1_CHECK_SERVERHELLO_TLSEXT),	"TLS1_CHECK_SERVERHELLO_TLSEXT"},
{ERR_FUNC(SSL_F_TLS1_ENC),	"tls1_enc"},
{ERR_FUNC(SSL_F_TLS1_EXPORT_KEYING_MATERIAL),	"tls1_export_keying_material"},
{ERR_FUNC(SSL_F_TLS1_HEARTBEAT),	"tls1_heartbeat"},
{ERR_FUNC(SSL_F_TLS1_PREPARE_CLIENTHELLO_TLSEXT),	"TLS1_PREPARE_CLIENTHELLO_TLSEXT"},
{ERR_FUNC(SSL_F_TLS1_PREPARE_SERVERHELLO_TLSEXT),	"TLS1_PREPARE_SERVERHELLO_TLSEXT"},
{ERR_FUNC(SSL_F_TLS1_PRF),	"tls1_prf"},
{ERR_FUNC(SSL_F_TLS1_SETUP_KEY_BLOCK),	"tls1_setup_key_block"},
{ERR_FUNC(SSL_F_TLS1_SET_SERVER_SIGALGS),	"tls1_set_server_sigalgs"},
{0,NULL}
	};

static ERR_STRING_DATA SSL_str_reasons[]=
	{
{ERR_REASON(SSL_R_APP_DATA_IN_HANDSHAKE) ,"app data in handshake"},
{ERR_REASON(SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT),"attempt to reuse session in different context"},
{ERR_REASON(SSL_R_BAD_ALERT_RECORD)      ,"bad alert record"},
{ERR_REASON(SSL_R_BAD_CHANGE_CIPHER_SPEC),"bad change cipher spec"},
{ERR_REASON(SSL_R_BAD_DATA)              ,"bad data"},
{ERR_REASON(SSL_R_BAD_DATA_RETURNED_BY_CALLBACK),"bad data returned by callback"},
{ERR_REASON(SSL_R_BAD_DECOMPRESSION)     ,"bad decompression"},
{ERR_REASON(SSL_R_BAD_DH_G_LENGTH)       ,"bad dh g length"},
{ERR_REASON(SSL_R_BAD_DH_PUB_KEY_LENGTH) ,"bad dh pub key length"},
{ERR_REASON(SSL_R_BAD_DH_P_LENGTH)       ,"bad dh p length"},
{ERR_REASON(SSL_R_BAD_DIGEST_LENGTH)     ,"bad digest length"},
{ERR_REASON(SSL_R_BAD_DSA_SIGNATURE)     ,"bad dsa signature"},
{ERR_REASON(SSL_R_BAD_ECC_CERT)          ,"bad ecc cert"},
{ERR_REASON(SSL_R_BAD_ECDSA_SIGNATURE)   ,"bad ecdsa signature"},
{ERR_REASON(SSL_R_BAD_ECPOINT)           ,"bad ecpoint"},
{ERR_REASON(SSL_R_BAD_HANDSHAKE_LENGTH)  ,"bad handshake length"},
{ERR_REASON(SSL_R_BAD_HELLO_REQUEST)     ,"bad hello request"},
{ERR_REASON(SSL_R_BAD_LENGTH)            ,"bad length"},
{ERR_REASON(SSL_R_BAD_MAC_LENGTH)        ,"bad mac length"},
{ERR_REASON(SSL_R_BAD_MESSAGE_TYPE)      ,"bad message type"},
{ERR_REASON(SSL_R_BAD_PACKET_LENGTH)     ,"bad packet length"},
{ERR_REASON(SSL_R_BAD_PROTOCOL_VERSION_NUMBER),"bad protocol version number"},
{ERR_REASON(SSL_R_BAD_PSK_IDENTITY_HINT_LENGTH),"bad psk identity hint length"},
{ERR_REASON(SSL_R_BAD_RSA_DECRYPT)       ,"bad rsa decrypt"},
{ERR_REASON(SSL_R_BAD_RSA_ENCRYPT)       ,"bad rsa encrypt"},
{ERR_REASON(SSL_R_BAD_RSA_E_LENGTH)      ,"bad rsa e length"},
{ERR_REASON(SSL_R_BAD_RSA_MODULUS_LENGTH),"bad rsa modulus length"},
{ERR_REASON(SSL_R_BAD_RSA_SIGNATURE)     ,"bad rsa signature"},
{ERR_REASON(SSL_R_BAD_SIGNATURE)         ,"bad signature"},
{ERR_REASON(SSL_R_BAD_SRP_A_LENGTH)      ,"bad srp a length"},
{ERR_REASON(SSL_R_BAD_SRP_B_LENGTH)      ,"bad srp b length"},
{ERR_REASON(SSL_R_BAD_SRP_G_LENGTH)      ,"bad srp g length"},
{ERR_REASON(SSL_R_BAD_SRP_N_LENGTH)      ,"bad srp n length"},
{ERR_REASON(SSL_R_BAD_SRP_PARAMETERS)    ,"bad srp parameters"},
{ERR_REASON(SSL_R_BAD_SRP_S_LENGTH)      ,"bad srp s length"},
{ERR_REASON(SSL_R_BAD_SRTP_MKI_VALUE)    ,"bad srtp mki value"},
{ERR_REASON(SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST),"bad srtp protection profile list"},
{ERR_REASON(SSL_R_BAD_SSL_FILETYPE)      ,"bad ssl filetype"},
{ERR_REASON(SSL_R_BAD_VALUE)             ,"bad value"},
{ERR_REASON(SSL_R_BAD_WRITE_RETRY)       ,"bad write retry"},
{ERR_REASON(SSL_R_BIO_NOT_SET)           ,"bio not set"},
{ERR_REASON(SSL_R_BLOCK_CIPHER_PAD_IS_WRONG),"block cipher pad is wrong"},
{ERR_REASON(SSL_R_BN_LIB)                ,"bn lib"},
{ERR_REASON(SSL_R_CA_DN_LENGTH_MISMATCH) ,"ca dn length mismatch"},
{ERR_REASON(SSL_R_CA_DN_TOO_LONG)        ,"ca dn too long"},
{ERR_REASON(SSL_R_CA_KEY_TOO_SMALL)      ,"ca key too small"},
{ERR_REASON(SSL_R_CA_MD_TOO_WEAK)        ,"ca md too weak"},
{ERR_REASON(SSL_R_CCS_RECEIVED_EARLY)    ,"ccs received early"},
{ERR_REASON(SSL_R_CERTIFICATE_VERIFY_FAILED),"certificate verify failed"},
{ERR_REASON(SSL_R_CERT_CB_ERROR)         ,"cert cb error"},
{ERR_REASON(SSL_R_CERT_LENGTH_MISMATCH)  ,"cert length mismatch"},
{ERR_REASON(SSL_R_CIPHER_CODE_WRONG_LENGTH),"cipher code wrong length"},
{ERR_REASON(SSL_R_CIPHER_OR_HASH_UNAVAILABLE),"cipher or hash unavailable"},
{ERR_REASON(SSL_R_CLIENTHELLO_TLSEXT)    ,"clienthello tlsext"},
{ERR_REASON(SSL_R_COMPRESSED_LENGTH_TOO_LONG),"compressed length too long"},
{ERR_REASON(SSL_R_COMPRESSION_DISABLED)  ,"compression disabled"},
{ERR_REASON(SSL_R_COMPRESSION_FAILURE)   ,"compression failure"},
{ERR_REASON(SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE),"compression id not within private range"},
{ERR_REASON(SSL_R_COMPRESSION_LIBRARY_ERROR),"compression library error"},
{ERR_REASON(SSL_R_CONNECTION_TYPE_NOT_SET),"connection type not set"},
{ERR_REASON(SSL_R_COOKIE_MISMATCH)       ,"cookie mismatch"},
{ERR_REASON(SSL_R_DATA_BETWEEN_CCS_AND_FINISHED),"data between ccs and finished"},
{ERR_REASON(SSL_R_DATA_LENGTH_TOO_LONG)  ,"data length too long"},
{ERR_REASON(SSL_R_DECRYPTION_FAILED)     ,"decryption failed"},
{ERR_REASON(SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC),"decryption failed or bad record mac"},
{ERR_REASON(SSL_R_DH_KEY_TOO_SMALL)      ,"dh key too small"},
{ERR_REASON(SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG),"dh public value length is wrong"},
{ERR_REASON(SSL_R_DIGEST_CHECK_FAILED)   ,"digest check failed"},
{ERR_REASON(SSL_R_DTLS_MESSAGE_TOO_BIG)  ,"dtls message too big"},
{ERR_REASON(SSL_R_DUPLICATE_COMPRESSION_ID),"duplicate compression id"},
{ERR_REASON(SSL_R_ECC_CERT_NOT_FOR_KEY_AGREEMENT),"ecc cert not for key agreement"},
{ERR_REASON(SSL_R_ECC_CERT_NOT_FOR_SIGNING),"ecc cert not for signing"},
{ERR_REASON(SSL_R_ECC_CERT_SHOULD_HAVE_RSA_SIGNATURE),"ecc cert should have rsa signature"},
{ERR_REASON(SSL_R_ECC_CERT_SHOULD_HAVE_SHA1_SIGNATURE),"ecc cert should have sha1 signature"},
{ERR_REASON(SSL_R_ECGROUP_TOO_LARGE_FOR_CIPHER),"ecgroup too large for cipher"},
{ERR_REASON(SSL_R_EE_KEY_TOO_SMALL)      ,"ee key too small"},
{ERR_REASON(SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST),"empty srtp protection profile list"},
{ERR_REASON(SSL_R_ENCRYPTED_LENGTH_TOO_LONG),"encrypted length too long"},
{ERR_REASON(SSL_R_ERROR_GENERATING_TMP_RSA_KEY),"error generating tmp rsa key"},
{ERR_REASON(SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST),"error in received cipher list"},
{ERR_REASON(SSL_R_EXCESSIVE_MESSAGE_SIZE),"excessive message size"},
{ERR_REASON(SSL_R_EXTRA_DATA_IN_MESSAGE) ,"extra data in message"},
{ERR_REASON(SSL_R_GOT_A_FIN_BEFORE_A_CCS),"got a fin before a ccs"},
{ERR_REASON(SSL_R_GOT_NEXT_PROTO_BEFORE_A_CCS),"got next proto before a ccs"},
{ERR_REASON(SSL_R_GOT_NEXT_PROTO_WITHOUT_EXTENSION),"got next proto without seeing extension"},
{ERR_REASON(SSL_R_HTTPS_PROXY_REQUEST)   ,"https proxy request"},
{ERR_REASON(SSL_R_HTTP_REQUEST)          ,"http request"},
{ERR_REASON(SSL_R_ILLEGAL_SUITEB_DIGEST) ,"illegal Suite B digest"},
{ERR_REASON(SSL_R_INAPPROPRIATE_FALLBACK),"inappropriate fallback"},
{ERR_REASON(SSL_R_INCONSISTENT_COMPRESSION),"inconsistent compression"},
{ERR_REASON(SSL_R_INVALID_COMMAND)       ,"invalid command"},
{ERR_REASON(SSL_R_INVALID_COMPRESSION_ALGORITHM),"invalid compression algorithm"},
{ERR_REASON(SSL_R_INVALID_NULL_CMD_NAME) ,"invalid null cmd name"},
{ERR_REASON(SSL_R_INVALID_PURPOSE)       ,"invalid purpose"},
{ERR_REASON(SSL_R_INVALID_SERVERINFO_DATA),"invalid serverinfo data"},
{ERR_REASON(SSL_R_INVALID_SRP_USERNAME)  ,"invalid srp username"},
{ERR_REASON(SSL_R_INVALID_STATUS_RESPONSE),"invalid status response"},
{ERR_REASON(SSL_R_INVALID_TICKET_KEYS_LENGTH),"invalid ticket keys length"},
{ERR_REASON(SSL_R_INVALID_TRUST)         ,"invalid trust"},
{ERR_REASON(SSL_R_KRB5)                  ,"krb5"},
{ERR_REASON(SSL_R_KRB5_C_CC_PRINC)       ,"krb5 client cc principal (no tkt?)"},
{ERR_REASON(SSL_R_KRB5_C_GET_CRED)       ,"krb5 client get cred"},
{ERR_REASON(SSL_R_KRB5_C_INIT)           ,"krb5 client init"},
{ERR_REASON(SSL_R_KRB5_C_MK_REQ)         ,"krb5 client mk_req (expired tkt?)"},
{ERR_REASON(SSL_R_KRB5_S_BAD_TICKET)     ,"krb5 server bad ticket"},
{ERR_REASON(SSL_R_KRB5_S_INIT)           ,"krb5 server init"},
{ERR_REASON(SSL_R_KRB5_S_RD_REQ)         ,"krb5 server rd_req (keytab perms?)"},
{ERR_REASON(SSL_R_KRB5_S_TKT_EXPIRED)    ,"krb5 server tkt expired"},
{ERR_REASON(SSL_R_KRB5_S_TKT_NYV)        ,"krb5 server tkt not yet valid"},
{ERR_REASON(SSL_R_KRB5_S_TKT_SKEW)       ,"krb5 server tkt skew"},
{ERR_REASON(SSL_R_LENGTH_MISMATCH)       ,"length mismatch"},
{ERR_REASON(SSL_R_LENGTH_TOO_SHORT)      ,"length too short"},
{ERR_REASON(SSL_R_LIBRARY_BUG)           ,"library bug"},
{ERR_REASON(SSL_R_LIBRARY_HAS_NO_CIPHERS),"library has no ciphers"},
{ERR_REASON(SSL_R_MISSING_DH_DSA_CERT)   ,"missing dh dsa cert"},
{ERR_REASON(SSL_R_MISSING_DH_KEY)        ,"missing dh key"},
{ERR_REASON(SSL_R_MISSING_DH_RSA_CERT)   ,"missing dh rsa cert"},
{ERR_REASON(SSL_R_MISSING_DSA_SIGNING_CERT),"missing dsa signing cert"},
{ERR_REASON(SSL_R_MISSING_ECDH_CERT)     ,"missing ecdh cert"},
{ERR_REASON(SSL_R_MISSING_ECDSA_SIGNING_CERT),"missing ecdsa signing cert"},
{ERR_REASON(SSL_R_MISSING_EXPORT_TMP_DH_KEY),"missing export tmp dh key"},
{ERR_REASON(SSL_R_MISSING_EXPORT_TMP_RSA_KEY),"missing export tmp rsa key"},
{ERR_REASON(SSL_R_MISSING_RSA_CERTIFICATE),"missing rsa certificate"},
{ERR_REASON(SSL_R_MISSING_RSA_ENCRYPTING_CERT),"missing rsa encrypting cert"},
{ERR_REASON(SSL_R_MISSING_RSA_SIGNING_CERT),"missing rsa signing cert"},
{ERR_REASON(SSL_R_MISSING_SRP_PARAM)     ,"can't find SRP server param"},
{ERR_REASON(SSL_R_MISSING_TMP_DH_KEY)    ,"missing tmp dh key"},
{ERR_REASON(SSL_R_MISSING_TMP_ECDH_KEY)  ,"missing tmp ecdh key"},
{ERR_REASON(SSL_R_MISSING_TMP_RSA_KEY)   ,"missing tmp rsa key"},
{ERR_REASON(SSL_R_MISSING_TMP_RSA_PKEY)  ,"missing tmp rsa pkey"},
{ERR_REASON(SSL_R_MISSING_VERIFY_MESSAGE),"missing verify message"},
{ERR_REASON(SSL_R_MULTIPLE_SGC_RESTARTS) ,"multiple sgc restarts"},
{ERR_REASON(SSL_R_NO_CERTIFICATES_RETURNED),"no certificates returned"},
{ERR_REASON(SSL_R_NO_CERTIFICATE_ASSIGNED),"no certificate assigned"},
{ERR_REASON(SSL_R_NO_CERTIFICATE_RETURNED),"no certificate returned"},
{ERR_REASON(SSL_R_NO_CERTIFICATE_SET)    ,"no certificate set"},
{ERR_REASON(SSL_R_NO_CIPHERS_AVAILABLE)  ,"no ciphers available"},
{ERR_REASON(SSL_R_NO_CIPHERS_PASSED)     ,"no ciphers passed"},
{ERR_REASON(SSL_R_NO_CIPHERS_SPECIFIED)  ,"no ciphers specified"},
{ERR_REASON(SSL_R_NO_CIPHER_MATCH)       ,"no cipher match"},
{ERR_REASON(SSL_R_NO_CLIENT_CERT_METHOD) ,"no client cert method"},
{ERR_REASON(SSL_R_NO_CLIENT_CERT_RECEIVED),"no client cert received"},
{ERR_REASON(SSL_R_NO_COMPRESSION_SPECIFIED),"no compression specified"},
{ERR_REASON(SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER),"Peer haven't sent GOST certificate, required for selected ciphersuite"},
{ERR_REASON(SSL_R_NO_METHOD_SPECIFIED)   ,"no method specified"},
{ERR_REASON(SSL_R_NO_PEM_EXTENSIONS)     ,"no pem extensions"},
{ERR_REASON(SSL_R_NO_PRIVATE_KEY_ASSIGNED),"no private key assigned"},
{ERR_REASON(SSL_R_NO_PROTOCOLS_AVAILABLE),"no protocols available"},
{ERR_REASON(SSL_R_NO_RENEGOTIATION)      ,"no renegotiation"},
{ERR_REASON(SSL_R_NO_REQUIRED_DIGEST)    ,"digest requred for handshake isn't computed"},
{ERR_REASON(SSL_R_NO_SHARED_CIPHER)      ,"no shared cipher"},
{ERR_REASON(SSL_R_NO_SHARED_SIGATURE_ALGORITHMS),"no shared sigature algorithms"},
{ERR_REASON(SSL_R_NO_SRTP_PROFILES)      ,"no srtp profiles"},
{ERR_REASON(SSL_R_NO_VERIFY_CALLBACK)    ,"no verify callback"},
{ERR_REASON(SSL_R_NULL_SSL_CTX)          ,"null ssl ctx"},
{ERR_REASON(SSL_R_NULL_SSL_METHOD_PASSED),"null ssl method passed"},
{ERR_REASON(SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED),"old session cipher not returned"},
{ERR_REASON(SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED),"old session compression algorithm not returned"},
{ERR_REASON(SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE),"only DTLS 1.2 allowed in Suite B mode"},
{ERR_REASON(SSL_R_ONLY_TLS_1_2_ALLOWED_IN_SUITEB_MODE),"only TLS 1.2 allowed in Suite B mode"},
{ERR_REASON(SSL_R_ONLY_TLS_ALLOWED_IN_FIPS_MODE),"only tls allowed in fips mode"},
{ERR_REASON(SSL_R_OPAQUE_PRF_INPUT_TOO_LONG),"opaque PRF input too long"},
{ERR_REASON(SSL_R_PACKET_LENGTH_TOO_LONG),"packet length too long"},
{ERR_REASON(SSL_R_PARSE_TLSEXT)          ,"parse tlsext"},
{ERR_REASON(SSL_R_PATH_TOO_LONG)         ,"path too long"},
{ERR_REASON(SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE),"peer did not return a certificate"},
{ERR_REASON(SSL_R_PEM_NAME_BAD_PREFIX)   ,"pem name bad prefix"},
{ERR_REASON(SSL_R_PEM_NAME_TOO_SHORT)    ,"pem name too short"},
{ERR_REASON(SSL_R_PRE_MAC_LENGTH_TOO_LONG),"pre mac length too long"},
{ERR_REASON(SSL_R_PROTOCOL_IS_SHUTDOWN)  ,"protocol is shutdown"},
{ERR_REASON(SSL_R_PSK_IDENTITY_NOT_FOUND),"psk identity not found"},
{ERR_REASON(SSL_R_PSK_NO_CLIENT_CB)      ,"psk no client cb"},
{ERR_REASON(SSL_R_PSK_NO_SERVER_CB)      ,"psk no server cb"},
{ERR_REASON(SSL_R_READ_BIO_NOT_SET)      ,"read bio not set"},
{ERR_REASON(SSL_R_READ_TIMEOUT_EXPIRED)  ,"read timeout expired"},
{ERR_REASON(SSL_R_RECORD_LENGTH_MISMATCH),"record length mismatch"},
{ERR_REASON(SSL_R_RECORD_TOO_LARGE)      ,"record too large"},
{ERR_REASON(SSL_R_RECORD_TOO_SMALL)      ,"record too small"},
{ERR_REASON(SSL_R_RENEGOTIATE_EXT_TOO_LONG),"renegotiate ext too long"},
{ERR_REASON(SSL_R_RENEGOTIATION_ENCODING_ERR),"renegotiation encoding err"},
{ERR_REASON(SSL_R_RENEGOTIATION_MISMATCH),"renegotiation mismatch"},
{ERR_REASON(SSL_R_REQUIRED_CIPHER_MISSING),"required cipher missing"},
{ERR_REASON(SSL_R_REQUIRED_COMPRESSSION_ALGORITHM_MISSING),"required compresssion algorithm missing"},
{ERR_REASON(SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING),"scsv received when renegotiating"},
{ERR_REASON(SSL_R_SERVERHELLO_TLSEXT)    ,"serverhello tlsext"},
{ERR_REASON(SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED),"session id context uninitialized"},
{ERR_REASON(SSL_R_SIGNATURE_ALGORITHMS_ERROR),"signature algorithms error"},
{ERR_REASON(SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE),"signature for non signing certificate"},
{ERR_REASON(SSL_R_SRP_A_CALC)            ,"error with the srp params"},
{ERR_REASON(SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES),"srtp could not allocate profiles"},
{ERR_REASON(SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG),"srtp protection profile list too long"},
{ERR_REASON(SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE),"srtp unknown protection profile"},
{ERR_REASON(SSL_R_SSL23_DOING_SESSION_ID_REUSE),"ssl23 doing session id reuse"},
{ERR_REASON(SSL_R_SSL3_EXT_INVALID_ECPOINTFORMAT),"ssl3 ext invalid ecpointformat"},
{ERR_REASON(SSL_R_SSL3_EXT_INVALID_SERVERNAME),"ssl3 ext invalid servername"},
{ERR_REASON(SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE),"ssl3 ext invalid servername type"},
{ERR_REASON(SSL_R_SSL3_SESSION_ID_TOO_LONG),"ssl3 session id too long"},
{ERR_REASON(SSL_R_SSL3_SESSION_ID_TOO_SHORT),"ssl3 session id too short"},
{ERR_REASON(SSL_R_SSLV3_ALERT_BAD_CERTIFICATE),"sslv3 alert bad certificate"},
{ERR_REASON(SSL_R_SSLV3_ALERT_BAD_RECORD_MAC),"sslv3 alert bad record mac"},
{ERR_REASON(SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED),"sslv3 alert certificate expired"},
{ERR_REASON(SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED),"sslv3 alert certificate revoked"},
{ERR_REASON(SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN),"sslv3 alert certificate unknown"},
{ERR_REASON(SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE),"sslv3 alert decompression failure"},
{ERR_REASON(SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE),"sslv3 alert handshake failure"},
{ERR_REASON(SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER),"sslv3 alert illegal parameter"},
{ERR_REASON(SSL_R_SSLV3_ALERT_NO_CERTIFICATE),"sslv3 alert no certificate"},
{ERR_REASON(SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE),"sslv3 alert unexpected message"},
{ERR_REASON(SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE),"sslv3 alert unsupported certificate"},
{ERR_REASON(SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION),"ssl ctx has no default ssl version"},
{ERR_REASON(SSL_R_SSL_HANDSHAKE_FAILURE) ,"ssl handshake failure"},
{ERR_REASON(SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS),"ssl library has no ciphers"},
{ERR_REASON(SSL_R_SSL_NEGATIVE_LENGTH)   ,"ssl negative length"},
{ERR_REASON(SSL_R_SSL_SESSION_ID_CALLBACK_FAILED),"ssl session id callback failed"},
{ERR_REASON(SSL_R_SSL_SESSION_ID_CONFLICT),"ssl session id conflict"},
{ERR_REASON(SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG),"ssl session id context too long"},
{ERR_REASON(SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH),"ssl session id has bad length"},
{ERR_REASON(SSL_R_TLSV1_ALERT_ACCESS_DENIED),"tlsv1 alert access denied"},
{ERR_REASON(SSL_R_TLSV1_ALERT_DECODE_ERROR),"tlsv1 alert decode error"},
{ERR_REASON(SSL_R_TLSV1_ALERT_DECRYPTION_FAILED),"tlsv1 alert decryption failed"},
{ERR_REASON(SSL_R_TLSV1_ALERT_DECRYPT_ERROR),"tlsv1 alert decrypt error"},
{ERR_REASON(SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION),"tlsv1 alert export restriction"},
{ERR_REASON(SSL_R_TLSV1_ALERT_INAPPROPRIATE_FALLBACK),"tlsv1 alert inappropriate fallback"},
{ERR_REASON(SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY),"tlsv1 alert insufficient security"},
{ERR_REASON(SSL_R_TLSV1_ALERT_INTERNAL_ERROR),"tlsv1 alert internal error"},
{ERR_REASON(SSL_R_TLSV1_ALERT_NO_RENEGOTIATION),"tlsv1 alert no renegotiation"},
{ERR_REASON(SSL_R_TLSV1_ALERT_PROTOCOL_VERSION),"tlsv1 alert protocol version"},
{ERR_REASON(SSL_R_TLSV1_ALERT_RECORD_OVERFLOW),"tlsv1 alert record overflow"},
{ERR_REASON(SSL_R_TLSV1_ALERT_UNKNOWN_CA),"tlsv1 alert unknown ca"},
{ERR_REASON(SSL_R_TLSV1_ALERT_USER_CANCELLED),"tlsv1 alert user cancelled"},
{ERR_REASON(SSL_R_TLSV1_BAD_CERTIFICATE_HASH_VALUE),"tlsv1 bad certificate hash value"},
{ERR_REASON(SSL_R_TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE),"tlsv1 bad certificate status response"},
{ERR_REASON(SSL_R_TLSV1_CERTIFICATE_UNOBTAINABLE),"tlsv1 certificate unobtainable"},
{ERR_REASON(SSL_R_TLSV1_UNRECOGNIZED_NAME),"tlsv1 unrecognized name"},
{ERR_REASON(SSL_R_TLSV1_UNSUPPORTED_EXTENSION),"tlsv1 unsupported extension"},
{ERR_REASON(SSL_R_TLS_CLIENT_CERT_REQ_WITH_ANON_CIPHER),"tls client cert req with anon cipher"},
{ERR_REASON(SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT),"peer does not accept heartbeats"},
{ERR_REASON(SSL_R_TLS_HEARTBEAT_PENDING) ,"heartbeat request already pending"},
{ERR_REASON(SSL_R_TLS_ILLEGAL_EXPORTER_LABEL),"tls illegal exporter label"},
{ERR_REASON(SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST),"tls invalid ecpointformat list"},
{ERR_REASON(SSL_R_TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST),"tls peer did not respond with certificate list"},
{ERR_REASON(SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG),"tls rsa encrypted value length is wrong"},
{ERR_REASON(SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER),"tried to use unsupported cipher"},
{ERR_REASON(SSL_R_UNABLE_TO_DECODE_DH_CERTS),"unable to decode dh certs"},
{ERR_REASON(SSL_R_UNABLE_TO_DECODE_ECDH_CERTS),"unable to decode ecdh certs"},
{ERR_REASON(SSL_R_UNABLE_TO_FIND_DH_PARAMETERS),"unable to find dh parameters"},
{ERR_REASON(SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS),"unable to find ecdh parameters"},
{ERR_REASON(SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS),"unable to find public key parameters"},
{ERR_REASON(SSL_R_UNABLE_TO_FIND_SSL_METHOD),"unable to find ssl method"},
{ERR_REASON(SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES),"unable to load ssl3 md5 routines"},
{ERR_REASON(SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES),"unable to load ssl3 sha1 routines"},
{ERR_REASON(SSL_R_UNEXPECTED_MESSAGE)    ,"unexpected message"},
{ERR_REASON(SSL_R_UNEXPECTED_RECORD)     ,"unexpected record"},
{ERR_REASON(SSL_R_UNINITIALIZED)         ,"uninitialized"},
{ERR_REASON(SSL_R_UNKNOWN_ALERT_TYPE)    ,"unknown alert type"},
{ERR_REASON(SSL_R_UNKNOWN_CERTIFICATE_TYPE),"unknown certificate type"},
{ERR_REASON(SSL_R_UNKNOWN_CIPHER_RETURNED),"unknown cipher returned"},
{ERR_REASON(SSL_R_UNKNOWN_CIPHER_TYPE)   ,"unknown cipher type"},
{ERR_REASON(SSL_R_UNKNOWN_CMD_NAME)      ,"unknown cmd name"},
{ERR_REASON(SSL_R_UNKNOWN_DIGEST)        ,"unknown digest"},
{ERR_REASON(SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE),"unknown key exchange type"},
{ERR_REASON(SSL_R_UNKNOWN_PKEY_TYPE)     ,"unknown pkey type"},
{ERR_REASON(SSL_R_UNKNOWN_PROTOCOL)      ,"unknown protocol"},
{ERR_REASON(SSL_R_UNKNOWN_REMOTE_ERROR_TYPE),"unknown remote error type"},
{ERR_REASON(SSL_R_UNKNOWN_SSL_VERSION)   ,"unknown ssl version"},
{ERR_REASON(SSL_R_UNKNOWN_STATE)         ,"unknown state"},
{ERR_REASON(SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED),"unsafe legacy renegotiation disabled"},
{ERR_REASON(SSL_R_UNSUPPORTED_CIPHER)    ,"unsupported cipher"},
{ERR_REASON(SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM),"unsupported compression algorithm"},
{ERR_REASON(SSL_R_UNSUPPORTED_DIGEST_TYPE),"unsupported digest type"},
{ERR_REASON(SSL_R_UNSUPPORTED_ELLIPTIC_CURVE),"unsupported elliptic curve"},
{ERR_REASON(SSL_R_UNSUPPORTED_PROTOCOL)  ,"unsupported protocol"},
{ERR_REASON(SSL_R_UNSUPPORTED_SSL_VERSION),"unsupported ssl version"},
{ERR_REASON(SSL_R_UNSUPPORTED_STATUS_TYPE),"unsupported status type"},
{ERR_REASON(SSL_R_USE_SRTP_NOT_NEGOTIATED),"use srtp not negotiated"},
{ERR_REASON(SSL_R_VERSION_TOO_LOW)       ,"version too low"},
{ERR_REASON(SSL_R_WRONG_CERTIFICATE_TYPE),"wrong certificate type"},
{ERR_REASON(SSL_R_WRONG_CIPHER_RETURNED) ,"wrong cipher returned"},
{ERR_REASON(SSL_R_WRONG_CURVE)           ,"wrong curve"},
{ERR_REASON(SSL_R_WRONG_MESSAGE_TYPE)    ,"wrong message type"},
{ERR_REASON(SSL_R_WRONG_SIGNATURE_LENGTH),"wrong signature length"},
{ERR_REASON(SSL_R_WRONG_SIGNATURE_SIZE)  ,"wrong signature size"},
{ERR_REASON(SSL_R_WRONG_SIGNATURE_TYPE)  ,"wrong signature type"},
{ERR_REASON(SSL_R_WRONG_SSL_VERSION)     ,"wrong ssl version"},
{ERR_REASON(SSL_R_WRONG_VERSION_NUMBER)  ,"wrong version number"},
{ERR_REASON(SSL_R_X509_LIB)              ,"x509 lib"},
{ERR_REASON(SSL_R_X509_VERIFICATION_SETUP_PROBLEMS),"x509 verification setup problems"},
{0,NULL}
	};

#endif

void ERR_load_SSL_strings(void)
	{
#ifndef OPENSSL_NO_ERR

	if (ERR_func_error_string(SSL_str_functs[0].error) == NULL)
		{
		ERR_load_strings(0,SSL_str_functs);
		ERR_load_strings(0,SSL_str_reasons);
		}
#endif
	}

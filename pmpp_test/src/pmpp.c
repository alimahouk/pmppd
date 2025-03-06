//
//  pmpp.c
//  pmpp_test
//
//  Created by Ali Mahouk on 3/29/16.
//
//

#include "pmpp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "main.h"
#include "net.h"
#include "util.h"

int pmpp_parse_msg_stat(const struct pmppmsg_t *m)
{
        if ( !m )
                return -1;
        
        char *m_id = get_uuid(PMPP_E_MESSAGE, m->plist);
        
        if ( m_id ) {
                printf("LOG: message %s has been delivered!\n", m_id);
        } else {
                wtf(0, "pmpp_parse_msg_stat: missing status value", 0);
        }
        
        return -1;
}

/**
 * @return 0 if the hash in the presence was successfully parsed, -1 otherwise.
 */
int pmpp_parse_presence(const struct pmppmsg_t *m)
{
        if ( !m )
                return -1;
        
        struct pmppproplist_t *plist_reachability = proplist(PMPP_L_REACHABILITY, 0, m->plist);
        
        if ( plist_reachability ) {
                enum pmppreach_t reach = atoi(plist_reachability->prop->val);
                struct pmppprop_t *p_id      = prop(PMPP_L_UUID, plist_reachability->prop->domain, m->plist);
                struct pmppprop_t *p_id_type = prop(PMPP_L_UUIDTYPE, plist_reachability->prop->domain, m->plist);
                struct pmppproplist_t *plist_laddr = proplist(PMPP_L_INET_LADDR, plist_reachability->prop->domain, m->plist);
                struct pmppproplist_t *plist_lport = proplist(PMPP_L_INET_LPORT, plist_reachability->prop->domain, m->plist);
                struct pmppproplist_t *plist_paddr = proplist(PMPP_L_INET_PADDR, plist_reachability->prop->domain, m->plist);
                struct pmppproplist_t *plist_pport = proplist(PMPP_L_INET_PPORT, plist_reachability->prop->domain, m->plist);
                
                printf("--\n");
                
                if ( p_id &&
                     p_id_type ) {
                        printf("LOG: %s reachability: %d\n", p_id->val, reach);
                        printf("%s:%s (public address)\n", plist_paddr->prop->val, plist_pport->prop->val);
                        printf("%s:%s (private address)\n", plist_laddr->prop->val, plist_lport->prop->val);
                } else {
                        if ( plist_paddr &&
                             plist_pport &&
                             strlen(plist_paddr->prop->val) > 0 ) {
                                printf("LOG: %s:%s reachability (public address): %d\n", plist_paddr->prop->val, plist_pport->prop->val, reach);
                        }
                        
                        if ( plist_laddr &&
                             plist_lport &&
                             strlen(plist_laddr->prop->val) > 0  ) {
                                printf("LOG: %s:%s reachability (private address): %d\n", plist_laddr->prop->val, plist_lport->prop->val, reach);
                        }
                }
        } else {
                wtf(0, "pmpp_parse_presence: missing reachability value", 0);
        }
        
        return -1;
}

/**
 * This function is the command hub. All inbound messages should
 * pass through it. It processes them & decides if/what events
 * should be triggered.
 * @return 0 if the message is a valid PMPP message, -1 otherwise.
 */
int pmpp_process_pmppmsg(struct pmppmsg_t **new_msg)
{
        /*
         * CHECKLIST
         * - Version number?
         * - Timestamp?
         * - Message type?
         *  |_-> Should it be encrypted?
         * - Sending server?
         * - Service identifier included?
         *  |_-> If we have a service UUID but no sending server, that means it came from a local service.
         */
        float pmpp_ver = -1;
        struct pmppproplist_t *plist_version = proplist(PMPP_L_VERSION, 0, (*new_msg)->plist);
        
        if ( plist_version ) {
                pmpp_ver = atof(plist_version->prop->val);
                
                if ( pmpp_ver > atof(PMPP_VERSION) ) {
                        printf("LOG: unsupported PMPP version: %s\n", plist_version->prop->val);
                        free(*new_msg);
                        
                        return -1;
                }
        } else {
                wtf(0, "message missing PMPP version", 0);
                free(*new_msg);
                
                return -1;
        }
        
        enum pmppmessage_t msg_type = PMPP_MT_UNKNOWN;
        struct pmppproplist_t *plist_msg_type = proplist(PMPP_L_MESSAGE_TYPE, 0, (*new_msg)->plist);
        struct pmppproplist_t *plist_time     = proplist(PMPP_L_TIME, 0, (*new_msg)->plist);
        
        if ( plist_msg_type ) {
                msg_type = atoi(plist_msg_type->prop->val);
        } else {
                printf("LOG: message missing type\n");
                free(*new_msg);
                
                return -1;
        }
        
        if ( !plist_time ||
             parse_time(plist_time->prop->val) == -1 ) {
                printf("LOG: message missing timestamp\n");
                free(*new_msg);
                
                return -1;
        }
        
        // Find out who the sender & recipient are so we can fetch the appropriate shared key.
        char *server_id  = get_uuid(PMPP_E_SERVER_SENDER, (*new_msg)->plist);
        char *service_id = get_uuid(PMPP_E_SERVICE, (*new_msg)->plist);
        int ee = crypto_req(msg_type); // Flag for whether encryption is mandatory for this type of message.
        
        if ( service_id ) {
                if ( uuidcmp(service_id, UUID) != 0 ) { // Message is not meant for us.
                        printf("LOG: message not meant for current service\n");
                        free(*new_msg);
                        
                        return -1;
                }
        } else {
                wtf(0, "message is missing service identifier", 0);
                free(*new_msg);
                
                return -1;
        }
        
        if ( ee ) {
                /*
                 * Although we have a message struct, we had no crypto info to decrypt it.
                 * We go thru the process again, this time with crypto keys to decrypt.
                 */
                struct pmppmsg_t *decrypt = util_atom((*new_msg)->pkg, app_key, app_iv, ee);
                
                if ( !decrypt ) { // Message should've been encrypted but it wasn't.
                        pmpp_ack_msg(*new_msg);
                        printf("LOG: received a non-encrypted secure-type message.\n");
                        free(*new_msg);
                        
                        return -1;
                } else {
                        decrypt->sender = (*new_msg)->sender;
                        
                        free(*new_msg);
                        
                        *new_msg = decrypt;
                }
        }
        
        /* At this point, it's safe to respond to the message. */
        
        // See if there's a hash (an ack) & remove the referenced message from the correspondent's outbox.
        struct pmppproplist_t *p_hash = proplist(PMPP_L_REF_HASH, 0, (*new_msg)->plist);
        
        if ( p_hash ) {
                struct pmppmsg_t *ref_msg = msg(p_hash->prop->val, outbox);
                struct pmppproplist_t *p_m_id = proplist(PMPP_L_UUID, p_hash->prop->domain, (*new_msg)->plist);
                
                if ( p_m_id )
                        printf("LOG: pmppd returned message identifier: %s\n", p_m_id->prop->val);
                
                if ( msg_type == PMPP_MT_MESSAGE &&
                     ref_msg) {
                        struct pmppproplist_t *plist_payload = proplist(PMPP_L_PAYLOAD, 0, ref_msg->plist);
                        
                        if ( plist_payload ) {
                                /*char *hash = NULL;
                                 
                                 // Do stuff with this info (update UI, etc.)
                                 sha(plist_payload->prop->val, &hash);*/
                        }
                }
                
                if ( ref_msg )
                        remove_msg(ref_msg, &outbox);
                
                free(*new_msg);
        } else {
                pmpp_ack_msg(*new_msg);
                
                switch ( msg_type ) {
                        case PMPP_MT_HAND_EXTEND: {
                                pmpp_parse_hand_ext(*new_msg);
                                pmpp_hand_shake(*new_msg);
                                free(*new_msg);
                                
                                break;
                        }
                        
                        case PMPP_MT_HAND_SHAKE_OK: {
                                printf("*hand shaken*\n");
                                pmpp_connected();
                                free(*new_msg);
                                
                                break;
                        }
                        
                        case PMPP_MT_MESSAGE: {
                                char *sender_id  = get_uuid(PMPP_E_SERVER, (*new_msg)->plist);
                                struct pmppproplist_t *p_payload = proplist(PMPP_L_PAYLOAD, 0, (*new_msg)->plist);
                                
                                if ( p_payload )
                                        printf("--\n%s SAYS: %s\a\n", sender_id, p_payload->prop->val);
                                
                                break;
                        }
                        
                        case PMPP_MT_MESSAGE_STAT: {
                                pmpp_parse_msg_stat(*new_msg);
                                
                                break;
                        }
                        
                        case PMPP_MT_NOTIF_PRES: {
                                pmpp_parse_presence(*new_msg);
                                free(*new_msg);
                                
                                break;
                        }
                        
                        case PMPP_MT_SLEEP: {
                                printf("LOG: local pmppd has shut down!\n");
                                free(*new_msg);
                                
                                break;
                        }
                        
                        default:
                                break;
                }
        }
        
        return 0;
}

void pmpp_ack_msg(const struct pmppmsg_t *m)
{
        if ( !m ) {
                wtf(0, "attempting to ack null message", 0);
                
                return;
        }
        
        char *hash = NULL;
        enum pmppmessage_t msg_type = PMPP_MT_UNKNOWN;
        struct pmppproplist_t *ack        = NULL;
        struct pmppproplist_t *p_msg_type = proplist(PMPP_L_MESSAGE_TYPE, 0, m->plist);
        
        if ( p_msg_type ) {
                msg_type = atoi(p_msg_type->prop->val);
        } else {
                wtf(0, "pmpp_ack_msg: message missing type", 0);
                
                return;
        }
        
        int ee = crypto_req(msg_type); // Flag for whether encryption is mandatory for this type of message.
        
        sha(m->pkg, &hash);
        
        struct pmppprop_t *p_hash = make_prop(PMPP_L_REF_HASH, hash, ee, 0);
        
        set_prop(p_hash, &ack);
        pmpp_send_msg(msg_type, 0, &ack);
}

void pmpp_add_id(const char *identifier)
{
        if ( identifier ) {
                enum pmppmessage_t msg_type = PMPP_MT_REGISTER;
                int ee = crypto_req(msg_type);
                struct pmppproplist_t *content = NULL;
                
                struct pmppprop_t *p_rid = make_prop(PMPP_L_RUUID, (char *)identifier, ee, 0);
                
                set_prop(p_rid, &content);
                pmpp_send_msg(msg_type, 1, &content);
        }
}

/**
 * Adds the app's auxiliary server.
 */
void pmpp_add_ip(const char *addr, unsigned int port)
{
        if ( addr ) {
                enum pmppmessage_t msg_type = PMPP_MT_REGISTER;
                int ee = crypto_req(msg_type);
                struct pmppprop_t *p_raddr = make_prop(PMPP_L_INET_RADDR, (char *)addr, ee, 0);
                struct pmppproplist_t *content = NULL;
                
                if ( port == 0)
                        port = PMPP_PORT;
                
                set_prop(p_raddr, &content);
                
                struct pmppprop_t *p_rport = make_prop(PMPP_L_INET_RPORT, util_itoa(port), ee, p_raddr->domain);
                
                set_prop(p_rport, &content);
                pmpp_send_msg(msg_type, 1, &content);
        }
}

/**
 * Call when the app no longer needs to use the server in the future.
 */
void pmpp_bye(void)
{
        pmpp_send_msg(PMPP_MT_BYE, 1, NULL);
}

/**
 * Called once a connection has been established with
 * the local server. This function verifies them & dumps
 * the service's data.
 */
void pmpp_connected(void)
{
        dump_corres(local);
}

/**
 * Called when a recipient is not acknowledging a message.
 */
void pmpp_dead(struct pmppmsg_t **m)
{
        if ( !*m )
                return;
        
        // Don't let non-critical messages accumulate!
        if ( (*m)->critical == 0 )
                remove_msg(*m, &outbox);
        
        printf("LOG: pmppd is unreachable\n");
}

void pmpp_greet(void)
{
        char *b64_enc = NULL;
        enum pmppmessage_t msg_type = PMPP_MT_GREET;
        EVP_PKEY *key_public = rsa_fetch_key(UUID, 2);
        struct pmppproplist_t *content = NULL;
        unsigned char *compressed = NULL;
        unsigned char *pkey       = NULL;
        
        size_t key_len        = crypto_ktoc(key_public, &pkey); // Convert the key into binary data.
        size_t compressed_len = util_compress(pkey, key_len, &compressed);           // Compress.
        size_t b64enc_len     = base64_encode(compressed, compressed_len, &b64_enc); // Encode.
        struct pmppprop_t *p_key = make_prop(PMPP_L_CRYPTO_RSA, b64_enc, 0, 0);
        
        set_prop(p_key, &content);
        
        struct pmppprop_t *p_key_size = make_prop(PMPP_L_ENCODE_SIZE, util_itoa((int)b64enc_len), 0, p_key->domain);
        
        set_prop(p_key_size, &content);
        pmpp_send_msg(msg_type, 1, &content);
}

void pmpp_hand_shake(const struct pmppmsg_t *m)
{
        if ( app_iv &&
             app_key ) {
                char *b64_enc = NULL;
                char *hash    = NULL;
                enum pmppmessage_t msg_type = PMPP_MT_HAND_SHAKE;
                struct pmppproplist_t *handshake = NULL;
                unsigned char *ciphertext = NULL;
                unsigned char *compressed = NULL;
                
                sha(m->pkg, &hash);
                
                size_t aes_len        = aes_encrypt(hash, app_key, app_iv, &ciphertext);     // Encrypt the hash.
                size_t compressed_len = util_compress(ciphertext, aes_len, &compressed);     // Compress.
                size_t b64enc_len     = base64_encode(compressed, compressed_len, &b64_enc); // Encode.
                
                struct pmppprop_t *p_hash = make_prop(PMPP_L_HASH, b64_enc, 0, 0);
                
                set_prop(p_hash, &handshake);
                
                struct pmppprop_t *p_hash_size = make_prop(PMPP_L_ENCODE_SIZE, util_itoa((int)b64enc_len), 0, p_hash->domain);
                
                set_prop(p_hash_size, &handshake);
                pmpp_send_msg(msg_type, 1, &handshake);
                
                pmpp_add_ip(AUXILIARY_IP, PMPP_PORT);
        }
}

void pmpp_parse_hand_ext(const struct pmppmsg_t *m)
{
        EVP_PKEY *key_private = rsa_fetch_key(UUID, 1);
        
        if ( key_private ) {
                struct pmppproplist_t *p_iv  = proplist(PMPP_L_CRYPTO_IV, 0, m->plist);
                struct pmppproplist_t *p_key = proplist(PMPP_L_CRYPTO_KEY, 0, m->plist);
                
                if ( p_iv ) {
                        int encoded_len = 0;
                        struct pmppprop_t *p_iv_size_compr = prop(PMPP_L_ENCODE_SIZE, p_iv->prop->domain, m->plist);
                        unsigned char *b64_iv           = NULL;
                        unsigned char *decompressed_iv  = NULL;
                        
                        if ( p_iv_size_compr )
                                encoded_len = atoi(p_iv_size_compr->val);
                        
                        size_t b64_len          = base64_decode(p_iv->prop->val, encoded_len, &b64_iv); // Decode.
                        size_t decompressed_len = util_decompress(b64_iv, b64_len, &decompressed_iv);   // Decompress.
                        
                        rsa_decrypt(key_private, decompressed_iv, decompressed_len, &app_iv);
                        free(b64_iv);
                        free(decompressed_iv);
                }
                
                if ( p_key ) {
                        int encoded_len = 0;
                        struct pmppprop_t *p_key_size_compr = prop(PMPP_L_ENCODE_SIZE, p_key->prop->domain, m->plist);
                        unsigned char *b64_key          = NULL;
                        unsigned char *decompressed_key = NULL;
                        
                        if ( p_key_size_compr )
                                encoded_len = atoi(p_key_size_compr->val);
                        
                        size_t b64_len          = base64_decode(p_key->prop->val, encoded_len, &b64_key); // Decode.
                        size_t decompressed_len = util_decompress(b64_key, b64_len, &decompressed_key);   // Decompress.
                        
                        rsa_decrypt(key_private, decompressed_key, decompressed_len, &app_key);
                        free(b64_key);
                        free(decompressed_key);
                }
                
                printf("Received IV:  %s\n", app_iv);
                printf("Received Key: %s\n", app_key);
                
                if ( app_iv &&
                     app_key ) {
                        // Check for existing records; use their domain to overwrite them.
                        struct pmppproplist_t *plist_iv  = proplist(PMPP_L_CRYPTO_IV, 0, m->plist);
                        unsigned int dom = 0;
                        
                        if ( plist_iv )
                                dom = plist_iv->prop->domain;
                        
                        struct pmppprop_t *p_iv = make_prop(PMPP_L_CRYPTO_IV, app_iv, 0, dom);
                        
                        set_prop(p_iv, &local->plist);
                        
                        struct pmppprop_t *p_key = make_prop(PMPP_L_CRYPTO_KEY, app_key, 0, p_iv->domain);
                        
                        set_prop(p_key, &local->plist);
                }
        }
}

void pmpp_ping_local(void)
{
        enum pmppmessage_t msg_type = PMPP_MT_PING;
        struct pmppprop_t *p_msg_type = make_prop(PMPP_L_MESSAGE_TYPE, util_itoa(msg_type), 0, 0);
        struct pmppproplist_t *ping = NULL;
        
        /*
         * This message needs to be secure, but it's just an empty shell.
         * This dummy property is used to enforce authenticity thru decryption
         * at the recipient's side, which would fail to go thru otherwise.
         */
        struct pmppprop_t *p_dummy = make_prop(PMPP_L_PAYLOAD, util_itoa(rand()), 1, 0);
        
        set_prop(p_msg_type, &ping);
        set_prop(p_dummy, &ping);
        pmpp_send_msg(msg_type, 1, &ping);
}

void pmpp_resend_msg(struct pmppmsg_t *m)
{
        send_udp(m, 0);
}

/**
 * Adds standard PMPP metadata to an outgoing message.
 */
void pmpp_season(struct pmppmsg_t *m)
{
        struct pmppprop_t *p_appid = make_prop(PMPP_L_UUID, UUID, 0, 0);
        
        set_prop(p_appid, &m->plist);
        
        struct pmppprop_t *p_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVICE), 0, p_appid->domain); // Use the identifier's domain.
        struct pmppprop_t *p_version = make_prop(PMPP_L_VERSION, PMPP_VERSION, 0, p_appid->domain);
        
        set_prop(p_id_type, &m->plist);
        set_prop(p_version, &m->plist);
}

void pmpp_send_msg(const enum pmppmessage_t type, const int need_ack, struct pmppproplist_t **content)
{
        struct pmppmsg_t *m = make_msg();
        m->plist = *content;
        
        // We just need to insert some metadata before sending.
        struct pmppprop_t *p_msg_type = make_prop(PMPP_L_MESSAGE_TYPE, util_itoa(type), 0, 0);
        
        set_prop(p_msg_type, &m->plist);
        pmpp_season(m);
        
        /*
         * Store the serialized version of the message.
         * We will be resending this message a few times (because UDP)
         * so we don't want to keep on encrypting, compressing, etc.
         */
        m->pkg = util_mtoa(m, app_key, app_iv);
        
        sha(m->pkg, &m->m_hash); // Save a hash of the original message.
        send_udp(m, need_ack);
}

void pmpp_sleep(void)
{
        enum pmppmessage_t msg_type = PMPP_MT_SLEEP;
        struct pmppproplist_t *sleep = NULL;
        
        /*
         * This message needs to be secure, but it's just an empty shell.
         * This dummy property is used to enforce authenticity thru decryption
         * at the recipient's side, which would fail to go thru otherwise.
         */
        struct pmppprop_t *p_dummy = make_prop(PMPP_L_PAYLOAD, util_itoa(rand()), 1, 0);
        
        set_prop(p_dummy, &sleep);
        pmpp_send_msg(msg_type, 0, &sleep);
}

//
//  pmpp.c
//  pmppd
//
//  Created by Ali Mahouk on 3/29/16.
//
//

#include "pmpp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "main.h"
#include "net.h"
#include "util.h"

/**
 * Called when a recipient is not acknowledging a message.
 * @return -1 if the passed message is null, 1 if a correspondent
 * or message list was modified, or 0 if nothing was modified.
 */
int pmpp_dead(struct pmppmsg_t **m)
{
        int ret = 0;
        
        if ( !*m )
                return -1;
        
        // Unreachable, unverified correspondents should be removed.
        if ( (*m)->recipient->verified == 0 ) {
                remove_corres_iaddr(&(*m)->recipient->paddr, &local->clist);
                
                ret = 1;
        } else if ( (*m)->recipient->rvp == 0 ) { // Don't probe for unreachable RVPs.
                pmpp_probe((*m)->recipient);
        }
        
        printf("LOG: unreachable correspondent\n");
        pmpp_notif_presence_list((*m)->recipient, PMPP_R_OFFLINE, NULL);
        
        // Don't let non-critical messages accumulate!
        if ( (*m)->critical == 0 ) {
                remove_msg(*m, &(*m)->recipient->mlist);
                
                ret = 1;
        } else if ( ret != 1 ) {
                /*
                 * Critical message for an unreachable, verified
                 * correspondent. Dump the mlist.
                 */
                dump_corres((*m)->recipient);
        }
        
        return ret;
}

/**
 * The shared AES key generated as a result of the hand extension is placed
 * in @p key. The generated IV is stored in @p iv.
 * @return 0 if the greeting was parsed correctly, -1 otherwise.
 */
int pmpp_parse_greet(const struct pmppmsg_t *m, char **key, char **iv, EVP_PKEY **pkey)
{
        int encoded_rsa_len = 0;
        unsigned char *b64_rsa_dec      = NULL;
        unsigned char *decompressed_rsa = NULL;
        
        *pkey = NULL;
        
        if ( !*iv ||
             !*key ) {
                aes_gen(iv, AES256_IV_SIZE);
                aes_gen(key, AES256_KEY_SIZE);
        }
        
        printf("IV: %s\n", *iv);
        printf("Key: %s\n", *key);
        
        if ( !*iv ||
             !*key )
                return -1;
        
        struct pmppproplist_t *p_size_compr = proplist(PMPP_L_ENCODE_SIZE, 0, m->plist);
        struct pmppproplist_t *p_rsa        = proplist(PMPP_L_CRYPTO_RSA, 0, m->plist);
        
        if ( p_size_compr )
                encoded_rsa_len = atoi(p_size_compr->prop->val);
        
        if ( !p_rsa ) // Missing public key.
                return -1;
        
        size_t b64dec_len       = base64_decode(p_rsa->prop->val, encoded_rsa_len, &b64_rsa_dec); // Decode.
        size_t decompressed_len = util_decompress(b64_rsa_dec, b64dec_len, &decompressed_rsa);    // Decompress.
        
        *pkey = crypto_ctok(&decompressed_rsa, decompressed_len);
        
        if ( !pkey ) // Corrupt public key.
                return -1;
        
        return 0;
}

/**
 * @return 0 if the shared key was successfully decrypted, -1 otherwise.
 */
int pmpp_parse_hand_ext(const struct pmppmsg_t *m)
{
        if ( !m )
                return -1;
        
        char *local_id = get_uuid(PMPP_E_SERVER, local->plist);
        EVP_PKEY *key_private = rsa_fetch_key(local_id, 1);
        
        m->sender->reachability = PMPP_R_ONLINE;
        
        if ( key_private ) {
                char *iv  = NULL;
                char *key = NULL;
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
                        
                        rsa_decrypt(key_private, decompressed_iv, decompressed_len, &iv);
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
                        
                        rsa_decrypt(key_private, decompressed_key, decompressed_len, &key);
                        free(b64_key);
                        free(decompressed_key);
                }
                
                printf("Generated IV: %s\n", iv);
                printf("Generated Key: %s\n", key);
                
                if ( iv &&
                     key ) {
                        // Check for existing records; use their domain to overwrite them.
                        struct pmppproplist_t *plist_iv  = proplist(PMPP_L_CRYPTO_IV, 0, m->plist);
                        unsigned int dom = 0;
                        
                        if ( plist_iv )
                                dom = plist_iv->prop->domain;
                        
                        struct pmppprop_t *p_iv = make_prop(PMPP_L_CRYPTO_IV, iv, 0, dom);
                        
                        set_prop(p_iv, &m->sender->plist);
                        
                        struct pmppprop_t *p_key = make_prop(PMPP_L_CRYPTO_KEY, key, 0, p_iv->domain);
                        
                        set_prop(p_key, &m->sender->plist);
                }
                
                return 0;
        }
        
        return -1;
}

/**
 * @return 0 if the hash in the handshake was successfully decrypted, -1 otherwise.
 */
int pmpp_parse_hand_shake(const struct pmppmsg_t *m, const char *recipient_id, const enum pmppentity_t recipient_type, char *key, char *iv)
{
        if ( !m )
                return -1;
        
        printf("*hand shaken*\n");
        char *hash = NULL;
        int encoded_hash_len = 0;
        unsigned char *b64 = NULL;
        unsigned char *ciphertext = NULL;
        
        struct pmppproplist_t *p_size_compr = proplist(PMPP_L_ENCODE_SIZE, 0, m->plist);
        struct pmppproplist_t *p_hash       = proplist(PMPP_L_HASH, 0, m->plist);
        
        if ( p_size_compr )
                encoded_hash_len = atoi(p_size_compr->prop->val);
        
        size_t b64dec_len       = base64_decode(p_hash->prop->val, encoded_hash_len, &b64); // Decode.
        size_t decompressed_len = util_decompress(b64, b64dec_len, &ciphertext);            // Decompress.
        
        aes_decrypt(ciphertext, decompressed_len, key, iv, &hash); // Decrypt the hash.
        printf("Decrypted hash is: %s\n", hash);
        
        if ( !hash )
                return -1;
        
        return 0;
}

/**
 * This function is called for parsing the delivery receipts
 * of messages delivered by RVPs.
 * @return 0 if the hash of the referenced message was
 * successfully extracted, -1 otherwise.
 */
int pmpp_parse_msg_stat(const struct pmppmsg_t *m)
{
        if ( m ) {
                struct pmppproplist_t *plist_hash = proplist(PMPP_L_HASH, 0, m->plist);
                
                if ( plist_hash ) {
                        struct pmppprop_t *p_recip_id = prop(PMPP_L_UUID, plist_hash->prop->domain, m->plist);
                        struct pmppcorres_t *original_recip = corres(p_recip_id->val, PMPP_E_SERVER, local->clist);
                        
                        if ( original_recip ) {
                                struct pmppmsg_t *ref_msg = msg(plist_hash->prop->val, original_recip->mlist);
                                
                                // Message acknowledged, send a delivery receipt to the service.
                                pmpp_delivery_receipt(ref_msg);
                                
                                return 0;
                        }
                }
        }
        
        return -1;
}

/**
 * @return 0 if the presence was successfully parsed, -1 otherwise.
 */
int pmpp_parse_presence(const struct pmppmsg_t *m)
{
        if ( !m ||
             !m->sender )
                return -1;
        
        struct pmppproplist_t *plist_reachability = proplist(PMPP_L_REACHABILITY, 0, m->plist);
        
        if ( plist_reachability ) {
                enum pmppreach_t reach = atoi(plist_reachability->prop->val);
                struct pmppprop_t *p_id      = prop(PMPP_L_UUID, plist_reachability->prop->domain, m->plist);
                struct pmppprop_t *p_id_type = prop(PMPP_L_UUIDTYPE, plist_reachability->prop->domain, m->plist);
                
                if ( p_id &&
                     p_id_type ) {
                        /*
                         * Before notifying the service, check if it's present
                         * on the sending server's clist. To prevent spam, the
                         * service should be subscribed to the server in order
                         * for it to receive notifications about it.
                         */
                        struct pmppcorres_t *c = corres(p_id->val, atoi(p_id_type->val), m->sender->clist);
                        
                        if ( c ) {
                                enum pmppreach_t service_reach = PMPP_R_UNKNOWN;
                                
                                if ( reach == PMPP_R_OFFLINE )
                                        service_reach = PMPP_R_SERVICE_OFFLINE;
                                else
                                        service_reach = PMPP_R_SERVICE_ONLINE;
                                
                                pmpp_notif_presence(c, m->sender, service_reach);
                                
                                return 0;
                        }
                } else {
                        wtf(0, "pmpp_parse_presence: could not find referenced correspondent's identifier/type", 0);
                }
        } else {
                wtf(0, "pmpp_parse_presence: missing reachability value", 0);
        }
        
        return -1;
}

int pmpp_parse_probe(const struct pmppmsg_t *m)
{
        if ( !m ) {
                wtf(0, "pmpp_parse_probe: null message", 0);
                
                return -1;
        }
        
        char *target_id = get_uuid(PMPP_E_SERVER, m->plist);
        
        if ( target_id ) {
                struct pmppcorres_t *target = corres(target_id, PMPP_E_SERVER, local->clist);
                
                if ( target ) { // TODO: && target->reachability == PMPP_R_ONLINE
                        char *sender_id = get_uuid(PMPP_E_SERVER_SENDER, m->plist);
                        struct pmppprop_t *p_id = make_prop(PMPP_L_UUID, sender_id, 0, 0);
                        struct pmppproplist_t *plist_laddr = proplist(PMPP_L_INET_LADDR, 0, target->plist);
                        struct pmppproplist_t *plist_lport = proplist(PMPP_L_INET_LPORT, 0, target->plist);
                        struct pmppproplist_t *plist_paddr = proplist(PMPP_L_INET_PADDR, 0, target->plist);
                        struct pmppproplist_t *plist_pport = proplist(PMPP_L_INET_PPORT, 0, target->plist);
                        struct pmppproplist_t *res = NULL;
                        
                        set_prop(p_id, &res);
                        
                        struct pmppprop_t *p_reach = make_prop(PMPP_L_REACHABILITY, util_itoa(target->reachability), 0, 0);
                        
                        set_prop(p_reach, &res);
                        
                        struct pmppprop_t *p_laddr     = make_prop(PMPP_L_INET_LADDR, "", 0, p_reach->domain);
                        struct pmppprop_t *p_lport     = make_prop(PMPP_L_INET_LPORT, "", 0, p_reach->domain);
                        struct pmppprop_t *p_paddr     = make_prop(PMPP_L_INET_PADDR, "", 0, p_reach->domain);
                        struct pmppprop_t *p_pport     = make_prop(PMPP_L_INET_PPORT, "", 0, p_reach->domain);
                        struct pmppprop_t *p_target_id = make_prop(PMPP_L_UUID, target_id, 0, p_reach->domain);
                        struct pmppprop_t *p_type      = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVER_RECIPIENT), 0, p_id->domain);
                        
                        if ( plist_laddr )
                                p_laddr->val = plist_laddr->prop->val;
                        
                        if ( plist_lport )
                                p_lport->val = plist_lport->prop->val;
                        
                        if ( plist_paddr )
                                p_paddr->val = plist_paddr->prop->val;
                        
                        if ( plist_pport )
                                p_pport->val = plist_pport->prop->val;
                        
                        set_prop(p_type, &res);
                        set_prop(p_target_id, &res);
                        set_prop(p_laddr, &res);
                        set_prop(p_lport, &res);
                        set_prop(p_paddr, &res);
                        set_prop(p_pport, &res);
                        pmpp_send_msg(m->sender, PMPP_MT_PROBE_RES, 1, &res, NULL, NULL);
                        
                        return 0;
                }
        }
        
        return -1;
}

int pmpp_parse_probe_res(const struct pmppmsg_t *m)
{
        if ( !m ) {
                wtf(0, "pmpp_parse_probe_res: null message", 0);
                
                return -1;
        }
        
        struct pmppproplist_t *plist_reachability = proplist(PMPP_L_REACHABILITY, 0, m->plist);
        
        if ( plist_reachability ) {
                struct pmppprop_t *p_id = prop(PMPP_L_UUID, plist_reachability->prop->domain, m->plist);
                
                if ( p_id ) {
                        struct pmppcorres_t *c = corres(p_id->val, PMPP_E_SERVER, local->clist);
                        
                        if ( c &&
                             c->probe != 0 ) { // Only parse the probe response if we were actually probing for this correspondent.
                                struct pmppproplist_t *existing = proplist(PMPP_L_INET_LADDR, 0, c->plist);
                                unsigned int domain = 0;
                                
                                if ( existing ) // We need the existing domain to overwrite the properties.
                                        domain = existing->prop->domain;
                                
                                struct pmppproplist_t *plist_laddr = proplist(PMPP_L_INET_LADDR, plist_reachability->prop->domain, m->plist);
                                struct pmppproplist_t *plist_lport = proplist(PMPP_L_INET_LPORT, plist_reachability->prop->domain, m->plist);
                                struct pmppproplist_t *plist_paddr = proplist(PMPP_L_INET_PADDR, plist_reachability->prop->domain, m->plist);
                                struct pmppproplist_t *plist_pport = proplist(PMPP_L_INET_PPORT, plist_reachability->prop->domain, m->plist);
                                
                                /*
                                 * Don't set any of these values in the correspondent's
                                 * clist. That way, when the ping ack returns, it can
                                 * trigger a presence notif update to deliver the new
                                 * address to registered correspondents.
                                 */
                                
                                if ( plist_laddr &&
                                     plist_lport )
                                        c->laddr = make_iaddr(plist_laddr->prop->val, atoi(plist_lport->prop->val));
                                
                                if ( plist_paddr &&
                                     plist_pport )
                                        c->paddr = make_iaddr(plist_paddr->prop->val, atoi(plist_pport->prop->val));
                                
                                pmpp_ping(c); // Now try pinging them.
                                
                                return 0;
                        }
                } else {
                        wtf(0, "pmpp_parse_probe_res: could not find referenced correspondent's identifier/type", 0);
                }
        } else {
                wtf(0, "pmpp_parse_probe_res: missing reachability value", 0);
        }
        
        return -1;
}

/**
 * Registers with the remote server mentioned in the given message.
 * This function is used to parse service registration requests.
 * @return 0 if the request was parsed properly, -1 otherwise.
 */
int pmpp_parse_reg_req(const struct pmppmsg_t *m)
{
        if ( !m ) {
                wtf(0, "pmpp_parse_reg_req: null message", 0);
                
                return -1;
        }
        
        char *addr        = NULL;
        char *local_id    = get_uuid(PMPP_E_SERVER, local->plist);
        char *local_laddr = net_ntoa(local->laddr.sin_addr);
        char *local_paddr = net_ntoa(local->paddr.sin_addr);
        char *service_id  = get_uuid(PMPP_E_SERVICE, m->plist);
        struct pmppproplist_t *p_rid   = proplist(PMPP_L_RUUID, 0, m->plist); // Requesting by UUID has higher precedence than by IP.
        struct pmppproplist_t *p_raddr = NULL;
        unsigned int port = 0;
        
        if ( !service_id ) {
                wtf(0, "registration request missing a service identifier", 0);
                
                return -1;
        }
        
        struct pmppcorres_t *service = corres(service_id, PMPP_E_SERVICE, local->clist);
        
        if ( !service ) {
                wtf(0, "service requesting server registration not present in local", 0);
                
                return -1;
        }
        
        if ( !p_rid ) { // Requesting by IP.
                p_raddr = proplist(PMPP_L_INET_RADDR, 0, m->plist);
                
                if ( p_raddr )
                        addr = p_raddr->prop->val;
                else
                        return -1;
                
                struct pmppprop_t *p_rport = prop(PMPP_L_INET_RPORT, p_raddr->prop->domain, m->plist);
                
                if ( p_rport )
                        port = atoi(p_rport->val);
                else
                        port = PMPP_PORT; // Assume default port.
                
                struct sockaddr_in server_addr = make_iaddr(addr, port);
                struct pmppcorres_t *server = iaddr_corres(&server_addr, local->clist);
                
                if ( strcmp(addr, local_laddr) == 0 ||
                     strcmp(addr, local_paddr) == 0 ) { // Service is adding the server it's already running on.
                        pmpp_notif_presence(service, local, local->reachability); // Just send a presence notif back.
                        printf("LOG: service requested registration of local address\n");
                } else {
                        if ( !server ) {
                                server = make_corres();
                                server->laddr = server_addr;
                                server->paddr = server_addr;
                                
                                // Set the IP address info in the plist.
                                struct pmppprop_t *p_laddr = make_prop(PMPP_L_INET_LADDR, addr, 0, 0);
                                
                                set_prop(p_laddr, &server->plist);
                                
                                struct pmppprop_t *p_lport = make_prop(PMPP_L_INET_LPORT, util_itoa(port), 0, p_laddr->domain);
                                struct pmppprop_t *p_paddr = make_prop(PMPP_L_INET_PADDR, addr, 0, p_laddr->domain);
                                struct pmppprop_t *p_pport = make_prop(PMPP_L_INET_PPORT, util_itoa(port), 0, p_laddr->domain);
                                
                                set_prop(p_lport, &server->plist);
                                set_prop(p_paddr, &server->plist);
                                set_prop(p_pport, &server->plist);
                                add_corres(server, PMPP_E_SERVER, &local->clist);
                        }
                        
                        // Add references between the server & the requesting service.
                        add_corres(server, PMPP_E_SERVER, &service->clist);
                        add_corres(service, PMPP_E_SERVER, &server->clist);
                        
                        if ( server->verified != 0 &&
                             server->rvp == 0 ) { // Server was already registered.
                                // Save new changes.
                                dump_corres(server);
                                dump_corres(service);
                                
                                // Send a presence notif to both the service & the requested server.
                                pmpp_notif_presence(service, server, server->reachability);
                                pmpp_notif_presence(server, service, service->reachability);
                        } else { // Dispatch a registration message to the remote server.
                                pmpp_greet(server, service_id);
                        }
                }
        } else { // Requesting by UUID.
                if ( strcmp(p_rid->prop->val, local_id) == 0 ) { // Service is adding the server it's already running on.
                        pmpp_notif_presence(service, local, local->reachability);     // Just send a presence notif back.
                        printf("LOG: service requested registration of local server\n");
                } else if ( strcmp(p_rid->prop->val, service_id) == 0 ) { // Service is adding itself… (-_-)
                        printf("LOG: service requested registration of itself\n");
                } else {
                      struct pmppcorres_t *server = corres(p_rid->prop->val, PMPP_E_SERVER, local->clist);
                        
                        if ( server ) {
                                // Add references between the server & the requesting service.
                                add_corres(server, PMPP_E_SERVER, &service->clist);
                                add_corres(service, PMPP_E_SERVER, &server->clist);
                                
                                // Save new changes.
                                dump_corres(server);
                                dump_corres(service);
                                
                                // Send a presence notif to the service.
                                pmpp_notif_presence(service, server, server->reachability);
                        }
                }
        }
        
        return 0;
}

int pmpp_parse_rvp(const struct pmppmsg_t *m)
{
        if ( !m ) {
                wtf(0, "pmpp_parse_rvp: null message", 0);
                
                return -1;
        }
        
        if ( !m->sender ) {
                wtf(0, "pmpp_parse_rvp: message missing sender", 0);
                
                return -1;
        }
        
        char *local_id = get_uuid(PMPP_E_SERVER, local->plist);
        struct pmppprop_t *p_id    = get_uuidp(PMPP_E_RVP, m->plist);
        
        if ( p_id &&
             local_id ) {
                if ( strcmp(local_id, p_id->val) != 0 ) { // Guard against someone sending the current server as an RVP to itself.
                        enum pmppentity_t rvp_type = PMPP_E_SERVER;
                        struct pmppprop_t *p_type  = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_RVP), 0, p_id->domain);
                        struct pmppprop_t *p_laddr = prop(PMPP_L_INET_LADDR, p_id->domain, m->plist);
                        struct pmppprop_t *p_lport = prop(PMPP_L_INET_LPORT, p_id->domain, m->plist);
                        struct pmppprop_t *p_paddr = prop(PMPP_L_INET_PADDR, p_id->domain, m->plist);
                        struct pmppprop_t *p_pport = prop(PMPP_L_INET_PPORT, p_id->domain, m->plist);
                        struct pmppcorres_t *rvp = corres(p_id->val, PMPP_E_SERVER, local->clist); // Check if it's already a registered server.
                        
                        if ( !rvp ) {
                                rvp = make_corres();
                                rvp->rvp      = 1;
                                rvp->verified = 1;
                                
                                rvp_type = PMPP_E_RVP;
                                
                                // Turn off encryption for storage.
                                p_id->secure    = 0;
                                p_type->secure  = 0;
                                p_laddr->secure = 0;
                                p_lport->secure = 0;
                                p_paddr->secure = 0;
                                p_pport->secure = 0;
                                
                                set_prop(p_id, &rvp->plist);
                                set_prop(p_type, &rvp->plist);
                                set_prop(p_laddr, &rvp->plist);
                                set_prop(p_lport, &rvp->plist);
                                set_prop(p_paddr, &rvp->plist);
                                set_prop(p_pport, &rvp->plist);
                                add_corres(rvp, PMPP_E_RVP, &local->clist);
                                dump_corres(rvp);
                                dump_corres(local);
                        }
                        
                        add_corres(rvp, rvp_type, &m->sender->clist);
                        dump_corres(m->sender);
                        
                        return 0;
                }
        } else {
                wtf(0, "pmpp_parse_rvp: missing RVP identifier", 0);
        }
        
        return -1;
}

int pmpp_parse_sleep(const struct pmppmsg_t *m)
{
        if ( m ) {
                pmpp_notif_presence_list(m->sender, PMPP_R_OFFLINE, NULL);
                
                return 0;
        }
        
        return -1;
}

int pmpp_process_fwd(struct pmppmsg_t *m)
{
        if ( m ) {
                struct pmppproplist_t *plist_payload = proplist(PMPP_L_PAYLOAD, 0, m->plist); // The payload is encrypted.
                
                if ( plist_payload ) {
                        struct pmppprop_t *p_sender_id = prop(PMPP_L_UUID, plist_payload->prop->domain, m->plist);
                        
                        if ( p_sender_id ) {
                                struct pmppcorres_t *sender_original = corres(p_sender_id->val, PMPP_E_SERVER, local->clist);
                                
                                if ( sender_original ) {
                                        char *iv        = NULL;
                                        char *key       = NULL;
                                        char *plaintext = NULL;
                                        unsigned char *b64          = NULL;
                                        unsigned char *decompressed = NULL;
                                        struct pmppprop_t *p_encode_len = prop(PMPP_L_ENCODE_SIZE, plist_payload->prop->domain, m->plist);
                                        struct pmppproplist_t *plist_iv  = proplist(PMPP_L_CRYPTO_IV, 0, m->sender->plist);
                                        struct pmppproplist_t *plist_key = proplist(PMPP_L_CRYPTO_KEY, 0, m->sender->plist);
                                        
                                        if ( plist_iv )
                                                iv = plist_iv->prop->val;
                                        
                                        if ( plist_key )
                                                key = plist_key->prop->val;
                                        
                                        size_t b64_len = base64_decode(plist_payload->prop->val, atoi(p_encode_len->val), &b64); // Decode.
                                        size_t decompressed_len = util_decompress(b64, b64_len, &decompressed);                  // Decompress.
                                        
                                        aes_decrypt(decompressed, decompressed_len, key, iv, &plaintext);                        // Decrypt.
                                        
                                        if ( plaintext ) {
                                                char *iv  = NULL;
                                                char *key = NULL;
                                                struct pmppproplist_t *plist_iv  = proplist(PMPP_L_CRYPTO_IV, 0, sender_original->plist);
                                                struct pmppproplist_t *plist_key = proplist(PMPP_L_CRYPTO_KEY, 0, sender_original->plist);
                                                
                                                if ( plist_iv )
                                                        iv = plist_iv->prop->val;
                                                
                                                if ( plist_key )
                                                        key = plist_key->prop->val;
                                                
                                                struct pmppmsg_t *original = util_atom(plaintext, key, iv, 1);
                                                
                                                if ( original ) {
                                                        original->sender = sender_original;
                                                        
                                                        pmpp_process_pmppmsg(&original);
                                                        
                                                        return 0;
                                                } else {
                                                        wtf(0, "pmpp_process_fwd: could not parse original message", 0);
                                                }
                                        } else {
                                                wtf(0, "pmpp_process_fwd: failed to decrypt payload", 0);
                                        }
                                } else {
                                        wtf(0, "pmpp_process_fwd: could not find referenced sender", 0);
                                }
                        } else {
                                wtf(0, "pmpp_process_fwd: missing original sender identifier", 0);
                        }
                } else {
                        wtf(0, "pmpp_process_fwd: missing payload", 0);
                }
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
        if ( !*new_msg ) {
                wtf(0, "pmpp_process_pmppmsg: null message", 0);
                
                return -1;
        }
        
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
                wtf(0, "message missing PMPP version number", 0);
                free(*new_msg);
                
                return -1;
        }
        
        enum pmppmessage_t msg_type = PMPP_MT_UNKNOWN;
        struct pmppmsg_t *decrypt = NULL;
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
                wtf(0, "message missing timestamp", 0);
                free(*new_msg);
                
                return -1;
        }
        
        // Set message criticality.
        (*new_msg)->critical = criticality(*new_msg);
        
        // Find out who the sender & recipient are so we can fetch the appropriate shared key.
        char *local_id = get_uuid(PMPP_E_SERVER, local->plist);
        char *recip_id = get_uuid(PMPP_E_SERVER_RECIPIENT, (*new_msg)->plist);
        
        if ( recip_id ) {
                if ( uuidcmp(recip_id, local_id) != 0 ) { // Message is meant for someone else.
                        if ( pmpp_safekeep(*new_msg) != 0 )
                                free(*new_msg);
                        
                        return 0;
                }
        }
        
        char *aes_iv     = NULL;
        char *aes_key    = NULL;
        char *sender_id  = NULL;
        char *server_id  = get_uuid(PMPP_E_SERVER_SENDER, (*new_msg)->plist);
        char *service_id = get_uuid(PMPP_E_SERVICE, (*new_msg)->plist);
        enum pmppentity_t sender_type = PMPP_E_ANY;
        int ee = crypto_req(msg_type); // Flag for whether encryption is mandatory for this type of message.
        struct pmppprop_t *p_iv  = NULL;
        struct pmppprop_t *p_key = NULL;
        
        if ( server_id ) {
                sender_id = server_id;
                sender_type = PMPP_E_SERVER;
        } else if ( service_id ) {
                sender_id = service_id;
                sender_type = PMPP_E_SERVICE;
        }
        
        if ( (*new_msg)->sender ) {
                struct pmppproplist_t *plist_iv  = proplist(PMPP_L_CRYPTO_IV, 0, (*new_msg)->sender->plist);
                struct pmppproplist_t *plist_key = proplist(PMPP_L_CRYPTO_KEY, 0, (*new_msg)->sender->plist);
                
                if ( plist_iv ) {
                        p_iv = plist_iv->prop;
                        aes_iv = p_iv->val;
                }
                
                if ( plist_key ) {
                        p_key = plist_key->prop;
                        aes_key = p_key->val;
                }
        } else {
                printf("LOG: message is missing its sender\n");
        }
        
        if ( ee ) { // Now we have to determine whose shared key to use.
                if ( !p_iv ||
                     !p_key ) {
                        printf("LOG: could not locate shared key for %s\n", sender_id);
                        free(*new_msg);
                        
                        return -1;
                }
                
                /*
                 * Although we have a message struct, we had no crypto info to decrypt it.
                 * We go thru the process again, this time with crypto keys to decrypt.
                 */
                decrypt = util_atom((*new_msg)->pkg, p_key->val, p_iv->val, ee);
                
                if ( !decrypt ) { // Message should've been encrypted but it wasn't.
                        pmpp_ack_msg((*new_msg), sender_id, sender_type);
                        printf("LOG: received a non-encrypted secure-type message.\n");
                        free(*new_msg);
                        
                        return -1;
                } else {
                        decrypt->critical = (*new_msg)->critical;
                        decrypt->m_hash   = (*new_msg)->m_hash;
                        decrypt->sender   = (*new_msg)->sender;
                        
                        free(*new_msg);
                        
                        *new_msg = decrypt;
                }
        }
        
        /* At this point, it's safe to respond to the message. */
        
        // See if there's a hash (an ack) & remove the referenced message from the correspondent's outbox.
        struct pmppproplist_t *p_hash = proplist(PMPP_L_REF_HASH, 0, (*new_msg)->plist);
        
        if ( p_hash ) {
                if ( sender_type == PMPP_E_SERVER )
                {
                        /*
                         * Acks should hold our own public address as seen by the server on the
                         * other side.
                         */
                        util_parse_paddr(*new_msg);
                }
                
                if ( (*new_msg)->sender ) {
                        struct pmppmsg_t *ref_msg = msg(p_hash->prop->val, (*new_msg)->sender->mlist);
                        
                        /*
                         * Pings are sent on startup to reconnect to
                         * peers. An ack to a ping means they're reachable.
                         */
                        if ( msg_type == PMPP_MT_PING &&
                             (*new_msg)->sender->reachability != PMPP_R_ONLINE ) { // Don't do the following actions for every ping ack; only if they were unreachable before.
                                (*new_msg)->sender->probe = 0; // Reset the probe flag.
                                
                                pmpp_notif_presence_list((*new_msg)->sender, PMPP_R_ONLINE, NULL);
                                pmpp_update_presence((*new_msg)->sender);
                                pmpp_flush_outbox((*new_msg)->sender);
                                
                                // Update RVPs.
                                if ( sender_type == PMPP_E_SERVER )
                                        pmpp_rvp(local->clist, (*new_msg)->sender);
                        } else if ( msg_type == PMPP_MT_NOTIF_PRES &&
                                    sender_type == PMPP_E_SERVER ) {
                                /*
                                 * Presence notification acks invoked by service presence will include
                                 * the service's current presence on the acknowledging remote machine.
                                 */
                                struct pmppproplist_t *p_service_reach = proplist(PMPP_L_REACHABILITY, 0, (*new_msg)->plist);
                                
                                if ( p_service_reach ) {
                                        enum pmppreach_t reach = atoi(p_service_reach->prop->val);
                                        struct pmppprop_t *p_service_id = prop(PMPP_L_UUID, p_service_reach->prop->domain, (*new_msg)->plist);
                                        
                                        if ( p_service_id ) {
                                                /*
                                                 * Before notifying the service, check if it's present
                                                 * on the sending server's clist. To prevent spam, the
                                                 * service should be subscribed to the server in order
                                                 * for it to receive notifications about it.
                                                 */
                                                struct pmppcorres_t *service = corres(p_service_id->val, PMPP_E_SERVICE, (*new_msg)->sender->clist);
                                                
                                                if ( service ) {
                                                        enum pmppreach_t service_reach = PMPP_R_UNKNOWN;
                                                        
                                                        if ( reach == PMPP_R_OFFLINE )
                                                                service_reach = PMPP_R_SERVICE_OFFLINE;
                                                        else
                                                                service_reach = PMPP_R_SERVICE_ONLINE;
                                                        
                                                        pmpp_notif_presence(service, (*new_msg)->sender, service_reach);
                                                }
                                        }
                                }
                        } else if ( msg_type == PMPP_MT_MESSAGE &&
                                    sender_type == PMPP_E_SERVER ) {
                                // Message acknowledged, send a delivery receipt to the service.
                                pmpp_delivery_receipt(ref_msg);
                        } else if ( msg_type == PMPP_MT_MESSAGE_FWD) {
                                // Forwarded message delivered. Generate a receipt for the original sender.
                                pmpp_fwd_delivery_receipt(*new_msg);
                        }
                        
                        if ( ref_msg ) {
                                remove_msg(ref_msg, &(*new_msg)->sender->mlist);
                        }
                } else {
                        printf("LOG: could not ack because message is missing its sender\n");
                }
                
                free(*new_msg);
        } else {
                pmpp_ack_msg(*new_msg, sender_id, sender_type);
                
                switch ( msg_type ) {
                        case PMPP_MT_GREET: {
                                if ( !service_id ) { // Greetings can only take place on behalf of services.
                                        printf("LOG: received greeting with no service identifier.\n");
                                        free(*new_msg);
                                        
                                        return -1;
                                }
                                
                                EVP_PKEY *pkey = NULL;
                                
                                if ( pmpp_parse_greet(*new_msg, &aes_key, &aes_iv, &pkey) == 0 ) {
                                        if ( !p_iv )
                                                p_iv = make_prop(PMPP_L_CRYPTO_IV, aes_iv, 0, 0);
                                        
                                        set_prop(p_iv, &(*new_msg)->sender->plist);
                                        
                                        if ( !p_key )
                                                p_key = make_prop(PMPP_L_CRYPTO_KEY, aes_key, 0, p_iv->domain);
                                        
                                        set_prop(p_key, &(*new_msg)->sender->plist);
                                        add_corres((*new_msg)->sender, sender_type, &local->clist); // Add the new correspondent to the local clist.
                                        pmpp_hand_ext(*new_msg, sender_id, sender_type, aes_key, aes_iv, pkey);
                                } else {
                                        wtf(0, "encountered a greeting error", 0);
                                }
                                
                                free(*new_msg);
                                
                                break;
                        }
                        
                        case PMPP_MT_HAND_EXTEND: {
                                pmpp_parse_hand_ext(*new_msg);
                                pmpp_hand_shake(*new_msg, sender_id, sender_type);
                                free(*new_msg);
                                
                                break;
                        }
                        
                        case PMPP_MT_HAND_SHAKE: {
                                if ( pmpp_parse_hand_shake(*new_msg, sender_id, sender_type, aes_key, aes_iv) == 0 ) {
                                        pmpp_hand_shake_ok((*new_msg)->sender, sender_id, sender_type);
                                        pmpp_connected((*new_msg)->sender);
                                        
                                        if ( sender_type == PMPP_E_SERVER )
                                                pmpp_rvp(local->clist, (*new_msg)->sender);
                                        
                                        if ( service_id ) {
                                                if ( strcmp(service_id, sender_id) != 0 ) { // This block should only be executed for server-server handshakes.
                                                        struct pmppcorres_t *service = corres(service_id, PMPP_E_SERVICE, local->clist);
                                                        
                                                        if ( service ) {
                                                                add_corres((*new_msg)->sender, PMPP_E_SERVER, &service->clist); // Link up the remote server with the service it requested.
                                                                pmpp_notif_presence((*new_msg)->sender, service, service->reachability);
                                                                dump_corres(service);
                                                        } else {
                                                                wtf(0, "handling handshake: requested service not found", 0);
                                                        }
                                                }
                                        }
                                }
                                
                                free(*new_msg);
                                
                                break;
                        }
                        
                        case PMPP_MT_HAND_SHAKE_OK: {
                                // The other server has accepted our handshake.
                                pmpp_connected((*new_msg)->sender);
                                
                                if ( sender_type == PMPP_E_SERVER )
                                        pmpp_rvp(local->clist, (*new_msg)->sender);
                                
                                free(*new_msg);
                                
                                break;
                        }
                        
                        case PMPP_MT_MESSAGE: {
                                pmpp_process_msg(*new_msg);
                                
                                break;
                        }
                        
                        case PMPP_MT_MESSAGE_FWD: {
                                pmpp_process_fwd(*new_msg);
                                free(*new_msg);
                                
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
                        
                        case PMPP_MT_PING: {
                                /*
                                 * Pings are sent on startup to reconnect to
                                 * peers.
                                 */
                                if ( (*new_msg)->sender->reachability != PMPP_R_ONLINE ) { // Somebody came online. Inform their clist.
                                        (*new_msg)->sender->probe = 0; // Reset the probe flag.
                                        
                                        pmpp_notif_presence_list((*new_msg)->sender, PMPP_R_ONLINE, NULL);
                                        pmpp_update_presence((*new_msg)->sender);
                                        pmpp_flush_outbox((*new_msg)->sender);
                                        
                                        // Update RVPs.
                                        if ( sender_type == PMPP_E_SERVER )
                                                pmpp_rvp(local->clist, (*new_msg)->sender);
                                }
                                
                                free(*new_msg);
                                
                                break;
                        }
                        
                        case PMPP_MT_PROBE: {
                                pmpp_parse_probe(*new_msg);
                                free(*new_msg);
                                
                                break;
                        }
                        
                        case PMPP_MT_PROBE_RES: {
                                pmpp_parse_probe_res(*new_msg);
                                free(*new_msg);
                                
                                break;
                        }
                        
                        case PMPP_MT_REGISTER: {
                                pmpp_parse_reg_req(*new_msg);
                                free(*new_msg);
                                
                                break;
                        }
                        
                        case PMPP_MT_RVP: {
                                pmpp_parse_rvp(*new_msg);
                                free(*new_msg);
                                
                                break;
                        }
                        
                        case PMPP_MT_SLEEP: {
                                pmpp_parse_sleep(*new_msg);
                                free(*new_msg);
                                
                                break;
                        }
                        
                        default:
                                break;
                }
        }
        
        return 0;
}

/**
 * Holds onto a message for forwarding to the intended
 * recipient once they're reachable.
 * @return 0 if the message was stored, -1 otherwise.
 */
int pmpp_safekeep(const struct pmppmsg_t *m)
{
        if ( m ) {
                char *recip_id  = get_uuid(PMPP_E_SERVER_RECIPIENT, m->plist);
                char *sender_id = get_uuid(PMPP_E_SERVER_SENDER, m->plist);
                struct pmppcorres_t *recipient = corres(recip_id, PMPP_E_SERVER, local->clist);
                
                if ( recipient &&
                     sender_id ) {
                        char *b64    = NULL;
                        char *iv     = NULL;
                        char *key    = NULL;
                        unsigned char *ciphertext = NULL;
                        unsigned char *compressed = NULL;
                        struct pmppproplist_t *plist_iv  = proplist(PMPP_L_CRYPTO_IV, 0, recipient->plist);
                        struct pmppproplist_t *plist_key = proplist(PMPP_L_CRYPTO_KEY, 0, recipient->plist);
                        struct pmppproplist_t *fwd       = NULL;
                        
                        if ( plist_iv )
                                iv = plist_iv->prop->val;
                        
                        if ( plist_key )
                                key = plist_key->prop->val;
                        
                        size_t aes_len = aes_encrypt(m->pkg, key, iv, &ciphertext);              // Encrypt.
                        size_t compressed_len = util_compress(ciphertext, aes_len, &compressed); // Compress.
                        size_t b64enc_len = base64_encode(compressed, compressed_len, &b64);     // Encode.
                        
                        // Reuse the message's identifier (we need it for generating the delivery receipt later).
                        struct pmppprop_t *p_m_id     = clonep(get_uuidp(PMPP_E_MESSAGE, m->plist));
                        struct pmppprop_t *p_payload  = make_prop(PMPP_L_PAYLOAD, b64, 0, 0);
                        struct pmppprop_t *p_recip_id = make_prop(PMPP_L_UUID, recip_id, 0, 0);
                        
                        p_m_id->domain = 0;
                        
                        set_prop(p_m_id, &fwd);
                        set_prop(p_payload, &fwd);
                        set_prop(p_recip_id, &fwd);
                        
                        // Make this secure so as not to conflict with the encode size of the main message.
                        struct pmppprop_t *p_encode_len = make_prop(PMPP_L_ENCODE_SIZE, util_itoa((int)b64enc_len), 1, p_payload->domain);
                        struct pmppprop_t *p_hash       = make_prop(PMPP_L_HASH, m->m_hash, 0, p_payload->domain);
                        struct pmppprop_t *p_m_id_type  = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_MESSAGE), 0, p_m_id->domain);
                        struct pmppprop_t *p_sender     = make_prop(PMPP_L_UUID, sender_id, 1, p_payload->domain);
                        struct pmppprop_t *p_recip_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVER_RECIPIENT), 0, p_recip_id->domain);
                        
                        set_prop(p_encode_len, &fwd);
                        set_prop(p_hash, &fwd);
                        set_prop(p_m_id_type, &fwd);
                        set_prop(p_sender, &fwd);
                        set_prop(p_recip_type, &fwd);
                        pmpp_send_msg(recipient, PMPP_MT_MESSAGE_FWD, 1, &fwd, key, iv);
                        
                        return 0;
                }
        }
        
        return -1;
}

void pmpp_ack_msg(const struct pmppmsg_t *m, const char *sender_id, const enum pmppentity_t sender_type)
{
        if ( !m ) {
                wtf(0, "attempting to ack null message", 0);
                
                return;
        }
        
        char *iv  = NULL;
        char *key = NULL;
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
        struct pmppprop_t *p_hash      = make_prop(PMPP_L_REF_HASH, m->m_hash, ee, 0);
        struct pmppprop_t *p_msg_id    = clonep(get_uuidp(PMPP_E_MESSAGE, m->plist));
        struct pmppprop_t *p_sender_id = make_prop(PMPP_L_UUID, (char *)sender_id, 0, 0);
        
        set_prop(p_hash, &ack);
        
        p_msg_id->domain = p_hash->domain;
        
        set_prop(p_msg_id, &ack);
        
        struct pmppprop_t *p_msg_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_MESSAGE), ee, p_msg_id->domain);
        
        set_prop(p_msg_id_type, &ack);
        set_prop(p_sender_id, &ack);
        
        struct pmppprop_t *p_sender_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(sender_type), 0, p_sender_id->domain);
        struct pmppprop_t *p_sender_paddr   = NULL;
        struct pmppprop_t *p_sender_pport   = NULL;
        
        if ( sender_type == PMPP_E_SERVICE ) {
                /*
                 * A service could make more use of the server's IP
                 * address rather than its own (localhost).
                 */
                struct pmppprop_t *p_sender_laddr = make_prop(PMPP_L_INET_LADDR, net_ntoa(local->laddr.sin_addr), ee, p_sender_id->domain);
                struct pmppprop_t *p_sender_lport = make_prop(PMPP_L_INET_LPORT, util_itoa(net_ntohs(local->laddr)), ee, p_sender_id->domain);
                
                set_prop(p_sender_laddr, &ack);
                set_prop(p_sender_lport, &ack);
                
                p_sender_paddr = make_prop(PMPP_L_INET_PADDR, net_ntoa(local->paddr.sin_addr), ee, p_sender_id->domain);
                p_sender_pport = make_prop(PMPP_L_INET_PPORT, util_itoa(net_ntohs(local->paddr)), ee, p_sender_id->domain);
        } else {
                p_sender_paddr = make_prop(PMPP_L_INET_PADDR, net_ntoa(m->sender->paddr.sin_addr), ee, p_sender_id->domain);
                p_sender_pport = make_prop(PMPP_L_INET_PPORT, util_itoa(net_ntohs(m->sender->paddr)), ee, p_sender_id->domain);
        }
        
        /* Presence notifications special case */
        
        if ( msg_type == PMPP_MT_NOTIF_PRES ) {
                char *server_id  = get_uuid(PMPP_E_SERVER_SENDER, m->plist);
                
                if ( server_id ) {
                        char *service_id = get_uuid(PMPP_E_SERVICE, m->plist);
                        
                        // Include the service's current presence on our side in the ack.
                        if ( service_id ) {
                                struct pmppcorres_t *service = corres(service_id, PMPP_E_SERVICE, local->clist);
                                
                                if ( service ) {
                                        struct pmppprop_t *p_reach = make_prop(PMPP_L_REACHABILITY, util_itoa(service->reachability), ee, 0);
                                        
                                        set_prop(p_reach, &ack);
                                        
                                        struct pmppprop_t *p_id = make_prop(PMPP_L_UUID, service_id, ee, p_reach->domain);
                                        
                                        set_prop(p_id, &ack);
                                }
                        }
                }
        } else if ( msg_type == PMPP_MT_MESSAGE &&
                    sender_type == PMPP_E_SERVER ) {
                char *service_id = get_uuid(PMPP_E_SERVICE, m->plist);
                
                if ( service_id ) {
                        struct pmppprop_t *p_id = make_prop(PMPP_L_UUID, service_id, ee, 0);
                        
                        set_prop(p_id, &ack);
                        
                        struct pmppprop_t *p_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVICE), ee, p_id->domain);
                        
                        set_prop(p_id_type, &ack);
                }
        }
        
        // Now we have to determine whose shared key to use.
        if ( ee ) {
                if ( m->sender ) {
                        struct pmppproplist_t *plist_aes_iv  = proplist(PMPP_L_CRYPTO_IV, 0, m->sender->plist);
                        struct pmppproplist_t *plist_aes_key = proplist(PMPP_L_CRYPTO_KEY, 0, m->sender->plist);
                        
                        if ( plist_aes_iv )
                                iv = plist_aes_iv->prop->val;
                        
                        if ( plist_aes_key )
                                key = plist_aes_key->prop->val;
                } else {
                        wtf(0, "pmpp_ack_msg: message missing sender", 0);
                }
        }
        
        if ( sender_type == PMPP_E_SERVER )
                p_sender_id_type->val = util_itoa(PMPP_E_SERVER_RECIPIENT);
        
        set_prop(p_sender_id_type, &ack);
        set_prop(p_sender_paddr, &ack);
        set_prop(p_sender_pport, &ack);
        pmpp_send_msg(m->sender, msg_type, 0, &ack, key, iv); // This is an ack, so it should go back to the sender.
}

/**
 * Sends @p content as a message to all correspondents on the given list, with the exception of
 * @p exclude.
 * @param type The required type of the correspondents for them to receive the broadcast.
 * @param reachability The required reachability of the correspondents for them to receive the
 * broadcast.
 * @attention Set the message type in @p content before calling this function.
 */
void pmpp_broadcast(struct pmppproplist_t *content, const struct pmppcorreslist_t *list, const struct pmppcorres_t *exclude, int ack, enum pmppentity_t type, enum pmppreach_t reachability)
{
        if ( content &&
             list ) {
                char *exc_id = NULL;
                enum pmppmessage_t msg_type = PMPP_MT_UNKNOWN;
                struct pmppcorreslist_t *iter = (struct pmppcorreslist_t *)list;
                struct pmppproplist_t *p_msg_type = proplist(PMPP_L_MESSAGE_TYPE, 0, content);
                
                if ( p_msg_type )
                        msg_type = atoi(p_msg_type->prop->val);
                
                if ( exclude ) {
                        exc_id = get_uuid(PMPP_E_SERVER, exclude->plist);
                       
                        if ( !exc_id )
                                exc_id = get_uuid(PMPP_E_SERVICE, exclude->plist);
                }
                
                while ( iter ) {
                        if ( iter->corres->verified != 1 ||
                             iter->corres->rvp == 1 ) { // Skip these guys.
                                iter = iter->next;
                                
                                continue;
                        }
                        
                        if ( reachability != PMPP_R_UNKNOWN ) {
                                if ( iter->corres->reachability != reachability ) { // Skip.
                                        iter = iter->next;
                                        
                                        continue;
                                }
                        }
                        
                        char *c_id = NULL;
                        char *iv   = NULL;
                        char *key  = NULL;
                        enum pmppentity_t c_type = type;
                        
                        if ( type == PMPP_E_ANY ) {
                                c_id = get_uuid(PMPP_E_SERVER, iter->corres->plist);
                                c_type = PMPP_E_SERVER_RECIPIENT;
                                
                                if ( !c_id ) {
                                        c_type = PMPP_E_SERVICE;
                                        c_id = get_uuid(c_type, iter->corres->plist);
                                }
                        } else {
                                c_id = get_uuid(type, iter->corres->plist);
                        }
                        
                        if ( c_id ) {
                                if ( exclude ) {
                                        char *iter_id = get_uuid(PMPP_E_SERVER, iter->corres->plist);
                                        
                                        if ( !iter_id )
                                                iter_id = get_uuid(PMPP_E_SERVICE, iter->corres->plist);
                                        
                                        if ( strcmp(exc_id, iter_id) == 0 ) { // The excluded one; skip.
                                                iter = iter->next;
                                                
                                                continue;
                                        }
                                }
                                
                                struct pmppproplist_t *broadcast = cloneplist(content);
                                struct pmppproplist_t *plist_iv  = proplist(PMPP_L_CRYPTO_IV, 0, iter->corres->plist);
                                struct pmppproplist_t *plist_key = proplist(PMPP_L_CRYPTO_KEY, 0, iter->corres->plist);
                                
                                if ( plist_iv )
                                        iv = plist_iv->prop->val;
                                
                                if ( plist_key )
                                        key = plist_key->prop->val;
                                
                                struct pmppprop_t *p_c_id = make_prop(PMPP_L_UUID, c_id, 0, 0);
                                
                                set_prop(p_c_id, &broadcast);
                                
                                struct pmppprop_t *p_c_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(c_type), 0, p_c_id->domain);
                                
                                set_prop(p_c_id_type, &broadcast);
                                pmpp_send_msg(iter->corres, msg_type, ack, &broadcast, key, iv);
                        }
                        
                        iter = iter->next;
                }
        }
}

/**
 * Called to send a farewell message to a remote
 * server informing them that no services on the
 * local machine require its services.
 */
void pmpp_bye(const struct pmppcorres_t *c)
{
        
}

/**
 * Called once a connection has been established with
 * a correspondent after a handshake. This function
 * verifies them, dumps their data, & flushes any
 * messages pending for them.
 */
void pmpp_connected(struct pmppcorres_t *c)
{
        /*
         * Special handling is necessary in case the new connection
         * is currently an RVP. We need to convert it to a regular
         * server correspondent.
         */
        c->rvp      = 0;
        c->verified = 1;
        
        unsigned int dom = domain(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_RVP), c->plist);
        
        if ( dom > 0 ) {
                struct pmppprop_t *p_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVER), 0, dom);
                
                set_prop(p_type, &c->plist);
        }
        
        dump_corres(c);
        dump_corres(local);
        dump_clist(c->clist);
        pmpp_notif_presence_list(c, PMPP_R_ONLINE, NULL);
        pmpp_update_presence(c);
        pmpp_flush_outbox(c);
}

void pmpp_delivery_receipt(const struct pmppmsg_t *m)
{
        if ( m ) {
                char *service_id = get_uuid(PMPP_E_SERVICE, m->plist);
                
                if ( service_id &&
                     m->m_hash ) {
                        char *m_id = get_uuid(PMPP_E_MESSAGE, m->plist);
                        struct pmppcorres_t *service = corres(service_id, PMPP_E_SERVICE, local->clist);
                        
                        if ( m_id &&
                             service ) {
                                char *iv  = NULL;
                                char *key = NULL;
                                enum pmppmessage_t msg_type = PMPP_MT_MESSAGE_STAT;
                                enum pmppmessagestat_t status = PMPP_MS_DELIVERED_SERVER;
                                int ee = crypto_req(msg_type);
                                struct pmppprop_t *p_s_id   = make_prop(PMPP_L_UUID, service_id, 0, 0);
                                struct pmppprop_t *p_status = make_prop(PMPP_L_PAYLOAD, util_itoa(status), ee, 0);
                                struct pmppproplist_t *receipt = NULL;
                                
                                set_prop(p_s_id, &receipt);
                                set_prop(p_status, &receipt);
                                
                                struct pmppprop_t *p_m_id      = make_prop(PMPP_L_UUID, m_id, ee, p_status->domain);
                                struct pmppprop_t *p_m_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_MESSAGE), ee, p_status->domain);
                                struct pmppprop_t *p_s_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVICE), 0, p_s_id->domain);
                                struct pmppproplist_t *plist_iv  = proplist(PMPP_L_CRYPTO_IV, 0, service->plist);
                                struct pmppproplist_t *plist_key = proplist(PMPP_L_CRYPTO_KEY, 0, service->plist);
                                
                                set_prop(p_m_id, &receipt);
                                set_prop(p_m_id_type, &receipt);
                                set_prop(p_s_id_type, &receipt);
                                
                                if ( plist_iv )
                                        iv = plist_iv->prop->val;
                                
                                if ( plist_key )
                                        key = plist_key->prop->val;
                                
                                pmpp_send_msg(service, msg_type, 1, &receipt, key, iv);
                        }
                }
        }
}

/**
 * Distributes the given correspondent's pending messages
 * to its RVPs.
 */
void pmpp_dist_outbox(const struct pmppcorres_t *c)
{
        if ( c &&
             c->rvp == 0 ) {
                char *server_id = get_uuid(PMPP_E_SERVER, c->plist); // Servers only!
                
                if ( server_id ) {
                        char *iv  = NULL;
                        char *key = NULL;
                        struct pmppmsglist_t *iter_m = c->mlist;
                        struct pmppproplist_t *plist_iv  = proplist(PMPP_L_CRYPTO_IV, 0, c->plist);
                        struct pmppproplist_t *plist_key = proplist(PMPP_L_CRYPTO_KEY, 0, c->plist);
                        
                        // Only the intended recipient should be able to decrypt the messages!
                        if ( plist_iv )
                                iv = plist_iv->prop->val;
                        
                        if ( plist_key )
                                key = plist_key->prop->val;
                        
                        while ( iter_m ) {
                                if ( iter_m->msg &&
                                     iter_m->msg->critical != 0 ) {
                                        enum pmppmessage_t m_type = PMPP_MT_UNKNOWN;
                                        struct pmppproplist_t *plist_msg_type  = proplist(PMPP_L_MESSAGE_TYPE, 0, iter_m->msg->plist);
                                        
                                        if ( plist_msg_type )
                                                m_type = atoi(plist_msg_type->prop->val);
                                        
                                        // Don't redistribute messages stored for safekeeping.
                                        if ( m_type != PMPP_MT_MESSAGE_FWD ) {
                                                struct pmppcorreslist_t *iter_c = local->clist;
                                                
                                                while ( iter_c ) {
                                                        if ( iter_c->corres &&
                                                             iter_c->corres->reachability == PMPP_R_ONLINE ) {
                                                                char *iter_id = get_uuid(PMPP_E_SERVER, iter_c->corres->plist);
                                                                
                                                                if ( !iter_id )
                                                                        iter_id = get_uuid(PMPP_E_RVP, iter_c->corres->plist);
                                                                
                                                                if ( iter_id ) {
                                                                        struct pmppproplist_t *copy = cloneplist(iter_m->msg->plist);
                                                                        
                                                                        pmpp_send_msg(iter_c->corres, PMPP_MT_MESSAGE, 1, &copy, key, iv);
                                                                }
                                                        }
                                                        
                                                        iter_c = iter_c->next;
                                                }
                                        }
                                }
                                
                                iter_m = iter_m->next;
                        }
                }
        }
}

void pmpp_dist_outboxes(void)
{
        struct pmppcorreslist_t *iter = local->clist;
        
        while ( iter ) {
                if ( iter->corres )
                        pmpp_dist_outbox(iter->corres);
                
                iter = iter->next;
        }
}

/**
 * Call on a correspondent that comes online to send
 * any messages that are pending for them.
 */
void pmpp_flush_outbox(const struct pmppcorres_t *c)
{
        struct pmppmsglist_t *iter = c->mlist;
        
        while ( iter ) {
                if ( iter->msg ) {
                        iter->msg->attempts = 0; // Reset the counter.
                        
                        pmpp_resend_msg(iter->msg);
                }
                
                iter = iter->next;
        }
}

/**
 * Call after delivering a message on someone else's
 * behalf. This function generates a receipt & sends
 * it back to the original sender.
 */
void pmpp_fwd_delivery_receipt(const struct pmppmsg_t *m)
{
        if ( m ) {
                struct pmppproplist_t *plist_ref_hash = proplist(PMPP_L_REF_HASH, 0, m->plist);
                
                if ( plist_ref_hash ) {
                        struct pmppmsg_t *ref_msg = msg(plist_ref_hash->prop->val, m->sender->mlist);
                        
                        if ( ref_msg ) {
                                struct pmppproplist_t *plist_hash = proplist(PMPP_L_HASH, 0, ref_msg->plist);
                                struct pmppproplist_t *plist_payload = proplist(PMPP_L_PAYLOAD, 0, ref_msg->plist);
                                
                                if ( plist_hash &&
                                     plist_payload ) {
                                        struct pmppprop_t *sender_id = prop(PMPP_L_UUID, plist_payload->prop->domain, ref_msg->plist);
                                        
                                        if ( sender_id ) {
                                                struct pmppcorres_t *original_sender = corres(sender_id->val, PMPP_E_SERVER, local->clist);
                                                
                                                if ( ! original_sender )
                                                        original_sender = corres(sender_id->val, PMPP_E_RVP, local->clist);
                                                
                                                if ( original_sender ) {
                                                        char *iv       = NULL;
                                                        char *key      = NULL;
                                                        char *recip_id = get_uuid(PMPP_E_SERVER, m->sender->plist);
                                                        struct pmppprop_t *p_hash = clonep(plist_hash->prop);
                                                        struct pmppproplist_t *plist_iv  = proplist(PMPP_L_CRYPTO_IV, 0, original_sender->plist);
                                                        struct pmppproplist_t *plist_key = proplist(PMPP_L_CRYPTO_KEY, 0, original_sender->plist);
                                                        struct pmppproplist_t *receipt = NULL;
                                                        
                                                        if ( plist_iv )
                                                                iv = plist_iv->prop->val;
                                                        
                                                        if ( plist_key )
                                                                key = plist_key->prop->val;
                                                        
                                                        p_hash->domain = 0;
                                                        p_hash->secure = 1;
                                                        
                                                        set_prop(p_hash, &receipt);
                                                        
                                                        struct pmppprop_t *p_recip_id = make_prop(PMPP_L_UUID, recip_id, 1, p_hash->domain);
                                                        
                                                        set_prop(p_recip_id, &receipt);
                                                        pmpp_send_msg(original_sender, PMPP_MT_MESSAGE_STAT, 1, &receipt, key, iv);
                                                        
                                                        /*
                                                         * The final message should hold a hash of the original message
                                                         * as well as the ID of the server it was sent to.
                                                         */
                                                }
                                        }
                                }
                        }
                }
        }
}

/**
 * Called when a registering with a remote server for the
 * first time.
 */
void pmpp_greet(const struct pmppcorres_t *c, const char *service_id)
{
        char *b64_enc  = NULL;
        char *local_id = get_uuid(PMPP_E_SERVER, local->plist);
        enum pmppmessage_t msg_type = PMPP_MT_GREET;
        EVP_PKEY *key_public = rsa_fetch_key(local_id, 2);
        struct pmppproplist_t *content = NULL;
        unsigned char *compressed = NULL;
        unsigned char *pkey       = NULL;
        
        size_t key_len        = crypto_ktoc(key_public, &pkey); // Convert the key into binary data.
        size_t compressed_len = util_compress(pkey, key_len, &compressed);           // Compress.
        size_t b64enc_len     = base64_encode(compressed, compressed_len, &b64_enc); // Encode.
        struct pmppprop_t *p_key = make_prop(PMPP_L_CRYPTO_RSA, b64_enc, 0, 0);
        
        set_prop(p_key, &content);
        
        struct pmppprop_t *p_key_size = make_prop(PMPP_L_ENCODE_SIZE, util_itoa((int)b64enc_len), 0, p_key->domain);
        struct pmppprop_t *p_service_id = make_prop(PMPP_L_UUID, (char *)service_id, 0, 0); // Insert the requesting service's identifier.
        
        set_prop(p_key_size, &content);
        set_prop(p_service_id, &content);
        
        struct pmppprop_t *p_service_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVICE), 0, p_service_id->domain);
        
        set_prop(p_service_id_type, &content);
        pmpp_send_msg(c, msg_type, 1, &content, NULL, NULL);
}

/**
 * Encrypts the given shared key with the given public key & sends
 * it to the message sender.
 */
void pmpp_hand_ext(const struct pmppmsg_t *m, const char *recipient_id, const enum pmppentity_t recipient_type, char *key, char *iv, EVP_PKEY *pkey)
{
        char *b64_iv_enc  = NULL;
        char *b64_key_enc = NULL;
        char *service_id  = get_uuid(PMPP_E_SERVICE, m->plist);
        enum pmppmessage_t msg_type = PMPP_MT_HAND_EXTEND;
        struct pmppprop_t *p_iv_size      = NULL;
        struct pmppprop_t *p_key_size     = NULL;
        struct pmppprop_t *p_recipient_id = NULL;
        struct pmppproplist_t *handext = NULL;
        unsigned char *compressed_iv  = NULL;
        unsigned char *compressed_key = NULL;
        unsigned char *iv_encrypted   = NULL;
        unsigned char *key_encrypted  = NULL;
        
        // Save their public key.
        rsa_dump_key(pkey, recipient_id, 2);
        
        // Encrypt the generated shared key with their public key.
        size_t iv_len  = rsa_encrypt(pkey, iv, &iv_encrypted);
        size_t key_len = rsa_encrypt(pkey, key, &key_encrypted);
        
        size_t compressed_iv_len  = util_compress(iv_encrypted, iv_len, &compressed_iv);          // Compress.
        size_t compressed_key_len = util_compress(key_encrypted, key_len, &compressed_key);
        size_t b64enc_iv_len      = base64_encode(compressed_iv, compressed_iv_len, &b64_iv_enc); // Encode.
        size_t b64enc_key_len     = base64_encode(compressed_key, compressed_key_len, &b64_key_enc);
        
        p_recipient_id = make_prop(PMPP_L_UUID, (char *)recipient_id, 0, 0);
        
        set_prop(p_recipient_id, &handext);
        
        struct pmppprop_t *p_recipient_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(recipient_type), 0, p_recipient_id->domain);
        struct pmppprop_t *p_iv             = make_prop(PMPP_L_CRYPTO_IV, b64_iv_enc, 0, 0);
        struct pmppprop_t *p_key            = make_prop(PMPP_L_CRYPTO_KEY, b64_key_enc, 0, 0);
        
        set_prop(p_recipient_type, &handext);
        set_prop(p_iv, &handext);
        set_prop(p_key, &handext);
        
        p_iv_size  = make_prop(PMPP_L_ENCODE_SIZE, util_itoa((int)b64enc_iv_len), 0, p_iv->domain);
        p_key_size = make_prop(PMPP_L_ENCODE_SIZE, util_itoa((int)b64enc_key_len), 0, p_key->domain);
        
        set_prop(p_iv_size, &handext);
        set_prop(p_key_size, &handext);
        
        if ( service_id &&
             strcmp(service_id, recipient_id) != 0 ) { // Include the requested service's identifier during the entire handshake process.
                struct pmppprop_t *p_service_id = make_prop(PMPP_L_UUID, service_id, 0, 0);
                
                set_prop(p_service_id, &handext);
                
                struct pmppprop_t *p_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVICE), 0, p_service_id->domain);
                
                set_prop(p_id_type, &handext);
        }
        
        pmpp_send_msg(m->sender, msg_type, 1, &handext, NULL, NULL);
}

void pmpp_hand_shake(const struct pmppmsg_t *m, const char *recipient_id, const enum pmppentity_t recipient_type)
{
        char *iv  = NULL;
        char *key = NULL;
        struct pmppproplist_t *p_iv = proplist(PMPP_L_CRYPTO_IV, 0, m->sender->plist);
        struct pmppproplist_t *p_key = proplist(PMPP_L_CRYPTO_KEY, 0, m->sender->plist);
        
        if ( p_iv )
                iv = p_iv->prop->val;
        
        if ( p_key )
                key = p_key->prop->val;
        
        if ( iv &&
             key ) {
                char *b64_enc    = NULL;
                char *hash       = NULL;
                char *service_id = get_uuid(PMPP_E_SERVICE, m->plist);
                enum pmppmessage_t msg_type = PMPP_MT_HAND_SHAKE;
                struct pmppproplist_t *handshake = NULL;
                unsigned char *ciphertext = NULL;
                unsigned char *compressed = NULL;
                
                sha(m->pkg, &hash);
                
                size_t aes_len        = aes_encrypt(hash, key, iv, &ciphertext);     // Encrypt the hash.
                size_t compressed_len = util_compress(ciphertext, aes_len, &compressed);     // Compress.
                size_t b64enc_len     = base64_encode(compressed, compressed_len, &b64_enc); // Encode.
                
                struct pmppprop_t *p_hash = make_prop(PMPP_L_HASH, b64_enc, 0, 0);
                
                set_prop(p_hash, &handshake);
                
                struct pmppprop_t *p_hash_size = make_prop(PMPP_L_ENCODE_SIZE, util_itoa((int)b64enc_len), 0, p_hash->domain);
                
                set_prop(p_hash_size, &handshake);
                
                struct pmppprop_t *p_recipient_id = make_prop(PMPP_L_UUID, (char *)recipient_id, 0, 0);
                
                set_prop(p_recipient_id, &handshake);
                
                struct pmppprop_t *p_recipient_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(recipient_type), 0, p_recipient_id->domain);
                
                set_prop(p_recipient_id_type, &handshake);
                
                if ( service_id &&
                     strcmp(service_id, recipient_id) != 0 ) { // Include the requested service's identifier during the entire handshake process.
                        struct pmppprop_t *p_service_id = make_prop(PMPP_L_UUID, service_id, 0, 0);
                        
                        set_prop(p_service_id, &handshake);
                        
                        struct pmppprop_t *p_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVICE), 0, p_service_id->domain);
                        
                        set_prop(p_id_type, &handshake);
                }
                
                pmpp_send_msg(m->sender, msg_type, 1, &handshake, NULL, NULL);
        }
}

void pmpp_hand_shake_ok(const struct pmppcorres_t *c, const char *recipient_id, const enum pmppentity_t recipient_type)
{
        char *iv  = NULL;
        char *key = NULL;
        enum pmppmessage_t msg_type = PMPP_MT_HAND_SHAKE_OK;
        struct pmppproplist_t *ok = NULL;
        
        struct pmppproplist_t *plist_aes_iv  = proplist(PMPP_L_CRYPTO_IV, 0, c->plist);
        struct pmppproplist_t *plist_aes_key = proplist(PMPP_L_CRYPTO_KEY, 0, c->plist);
        
        if ( plist_aes_iv )
                iv = plist_aes_iv->prop->val;
        
        if ( plist_aes_key )
                key = plist_aes_key->prop->val;
        
        /*
         * This message needs to be secure, but it's just an empty shell.
         * This dummy property is used to enforce authenticity thru decryption
         * at the recipient's side, which would fail to go thru otherwise.
         */
        struct pmppprop_t *p_dummy = make_prop(PMPP_L_PAYLOAD, util_itoa(rand()), 1, 0);
        struct pmppprop_t *p_recipient_id = make_prop(PMPP_L_UUID, (char *)recipient_id, 0, 0);
        
        set_prop(p_dummy, &ok);
        set_prop(p_recipient_id, &ok);
        
        struct pmppprop_t *p_recipient_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(recipient_type), 0, p_recipient_id->domain);
        
        set_prop(p_recipient_id_type, &ok);
        pmpp_send_msg(c, msg_type, 1, &ok, key, iv);
}

/**
 * Notifies the given recipient about @p c's current presence.
 */
void pmpp_notif_presence(const struct pmppcorres_t *recipient, const struct pmppcorres_t *c, enum pmppreach_t reachability)
{
        if ( !recipient ) {
                wtf(0, "attempting to send presence notification to null recipient", 0);
                
                return;
        }
        
        if ( !c ) {
                wtf(0, "attempting to send presence notification about a null correspondent", 0);
                
                return;
        }
        
        if ( recipient->reachability != PMPP_R_ONLINE ) // Why bother if they're unreachable?
                return;
        
        char *c_id         = get_uuid(PMPP_E_SERVICE, c->plist);
        char *iv           = NULL;
        char *key          = NULL;
        char *recipient_id = get_uuid(PMPP_E_SERVICE, recipient->plist);
        enum pmppentity_t c_type         = PMPP_E_SERVICE;
        enum pmppentity_t recipient_type = PMPP_E_SERVICE;
        enum pmppmessage_t msg_type = PMPP_MT_NOTIF_PRES;
        struct pmppproplist_t *plist_aes_iv  = proplist(PMPP_L_CRYPTO_IV, 0, recipient->plist);
        struct pmppproplist_t *plist_aes_key = proplist(PMPP_L_CRYPTO_KEY, 0, recipient->plist);
        struct pmppproplist_t *plist_laddr   = proplist(PMPP_L_INET_LADDR, 0, c->plist);
        struct pmppproplist_t *plist_lport   = proplist(PMPP_L_INET_LPORT, 0, c->plist);
        struct pmppproplist_t *plist_paddr   = proplist(PMPP_L_INET_PADDR, 0, c->plist);
        struct pmppproplist_t *plist_pport   = proplist(PMPP_L_INET_PPORT, 0, c->plist);
        struct pmppproplist_t *presence      = NULL;
        
        if ( !c_id ) {
                c_type = PMPP_E_SERVER;
                c_id = get_uuid(c_type, c->plist);
        }
        
        if ( !recipient_id ) {
                recipient_id = get_uuid(PMPP_E_SERVER, recipient->plist);
                recipient_type = PMPP_E_SERVER_RECIPIENT;
        }
        
        if ( !recipient_id ) {
                wtf(0, "pmpp_notif_presence: could not find recipient identifier", 0);
                
                return;
        }
        
        if ( plist_aes_iv )
                iv = plist_aes_iv->prop->val;
        
        if ( plist_aes_key )
                key = plist_aes_key->prop->val;
        
        /*
         * DO NOT stick the address properties from up above
         * into each message! Make copies.
         */
        struct pmppprop_t *p_reach = make_prop(PMPP_L_REACHABILITY, util_itoa(reachability), 1, 0);
        
        set_prop(p_reach, &presence);
        
        /*
         * There will be cases where an ID is still unknown, such as
         * unverified servers. In such cases, the IP address is all we have.
         */
        if ( c_id ) {
                struct pmppprop_t *p_c_id   = make_prop(PMPP_L_UUID, c_id, 1, p_reach->domain);
                struct pmppprop_t *p_c_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(c_type), 1, p_reach->domain);
                
                set_prop(p_c_id, &presence);
                set_prop(p_c_type, &presence);
        }
        
        struct pmppprop_t *p_laddr        = make_prop(PMPP_L_INET_LADDR, "", 1, p_reach->domain);
        struct pmppprop_t *p_lport        = make_prop(PMPP_L_INET_LPORT, "", 1, p_reach->domain);
        struct pmppprop_t *p_paddr        = make_prop(PMPP_L_INET_PADDR, "", 1, p_reach->domain);
        struct pmppprop_t *p_pport        = make_prop(PMPP_L_INET_PPORT, "", 1, p_reach->domain);
        struct pmppprop_t *p_recipient_id = make_prop(PMPP_L_UUID, recipient_id, 0, 0);
        
        if ( plist_laddr )
                p_laddr->val = plist_laddr->prop->val;
        
        if ( plist_lport )
                p_lport->val = plist_lport->prop->val;
        
        if ( plist_paddr )
                p_paddr->val = plist_paddr->prop->val;
        
        if ( plist_pport )
                p_pport->val = plist_pport->prop->val;
        
        set_prop(p_laddr, &presence);
        set_prop(p_lport, &presence);
        set_prop(p_paddr, &presence);
        set_prop(p_pport, &presence);
        set_prop(p_recipient_id, &presence);
        
        struct pmppprop_t *p_recipient_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(recipient_type), 0, p_recipient_id->domain);
        
        set_prop(p_recipient_type, &presence);
        pmpp_send_msg(recipient, msg_type, 1, &presence, key, iv);
}

/**
 * Notifies the correspondents on the given correspondent's
 * list regarding its current presence status, excluding @p exclude.
 */
void pmpp_notif_presence_list(struct pmppcorres_t *c, enum pmppreach_t reachability, struct pmppcorres_t *exclude)
{
        if ( c ) {
                c->reachability = reachability;
                
                if ( c->clist ) {
                        /*
                         * broadcast_type:
                         * Servers only receive notifications about services.
                         * Services only receive notifications about servers.
                         */
                        
                        char *c_id = get_uuid(PMPP_E_SERVICE, c->plist);
                        enum pmppentity_t broadcast_type = PMPP_E_SERVER;
                        enum pmppentity_t c_type = PMPP_E_SERVICE;
                        enum pmppmessage_t msg_type = PMPP_MT_NOTIF_PRES;
                        struct pmppprop_t *p_msg_type = make_prop(PMPP_L_MESSAGE_TYPE, util_itoa(msg_type), 0, 0);
                        struct pmppproplist_t *plist_laddr = proplist(PMPP_L_INET_LADDR, 0, c->plist);
                        struct pmppproplist_t *plist_lport = proplist(PMPP_L_INET_LPORT, 0, c->plist);
                        struct pmppproplist_t *plist_paddr = proplist(PMPP_L_INET_PADDR, 0, c->plist);
                        struct pmppproplist_t *plist_pport = proplist(PMPP_L_INET_PPORT, 0, c->plist);
                        struct pmppproplist_t *presence    = NULL;
                        
                        if ( !c_id ) {
                                broadcast_type = PMPP_E_SERVICE;
                                c_type = PMPP_E_SERVER;
                                c_id = get_uuid(c_type, c->plist);
                        }
                        
                        /*
                         * DO NOT stick the address properties from up above
                         * into each message! Make copies.
                         */
                        struct pmppprop_t *p_reach = make_prop(PMPP_L_REACHABILITY, util_itoa(reachability), 1, 0);
                        
                        set_prop(p_msg_type, &presence);
                        set_prop(p_reach, &presence);
                        
                        /*
                         * There will be cases where an ID is still unknown, such as
                         * unverified servers. In such cases, the IP address is all we have.
                         */
                        if ( c_id ) {
                                struct pmppprop_t *p_c_id   = make_prop(PMPP_L_UUID, c_id, 1, p_reach->domain);
                                struct pmppprop_t *p_c_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(c_type), 1, p_reach->domain);
                                
                                set_prop(p_c_id, &presence);
                                set_prop(p_c_type, &presence);
                        }
                        
                        struct pmppprop_t *p_laddr = make_prop(PMPP_L_INET_LADDR, "", 1, p_reach->domain);
                        struct pmppprop_t *p_lport = make_prop(PMPP_L_INET_LPORT, "", 1, p_reach->domain);
                        struct pmppprop_t *p_paddr = make_prop(PMPP_L_INET_PADDR, "", 1, p_reach->domain);
                        struct pmppprop_t *p_pport = make_prop(PMPP_L_INET_PPORT, "", 1, p_reach->domain);
                        
                        if ( plist_laddr )
                                p_laddr->val = plist_laddr->prop->val;
                        
                        if ( plist_lport )
                                p_lport->val = plist_lport->prop->val;
                        
                        if ( plist_paddr )
                                p_paddr->val = plist_paddr->prop->val;
                        
                        if ( plist_pport )
                                p_pport->val = plist_pport->prop->val;
                        
                        set_prop(p_laddr, &presence);
                        set_prop(p_lport, &presence);
                        set_prop(p_paddr, &presence);
                        set_prop(p_pport, &presence);
                        pmpp_broadcast(presence, c->clist, exclude, 1, broadcast_type, PMPP_R_ONLINE);
                }
        }
}

/**
 * Pings the given correspondent.
 */
void pmpp_ping(const struct pmppcorres_t *c)
{
        if ( c ) {
                char *c_id = get_uuid(PMPP_E_SERVER, c->plist);
                char *iv   = NULL;
                char *key  = NULL;
                enum pmppentity_t c_type = PMPP_E_SERVER_RECIPIENT;
                enum pmppmessage_t msg_type = PMPP_MT_PING;
                struct pmppprop_t *p_msg_type = make_prop(PMPP_L_MESSAGE_TYPE, util_itoa(msg_type), 0, 0);
                struct pmppproplist_t *plist_aes_iv  = proplist(PMPP_L_CRYPTO_IV, 0, c->plist);
                struct pmppproplist_t *plist_aes_key = proplist(PMPP_L_CRYPTO_KEY, 0, c->plist);
                struct pmppproplist_t *ping          = NULL;
                
                if ( !c_id ) {
                        c_type = PMPP_E_SERVICE;
                        c_id = get_uuid(c_type, c->plist);
                }
                
                if ( c_id ) {
                        if ( plist_aes_iv )
                                iv = plist_aes_iv->prop->val;
                        
                        if ( plist_aes_key )
                                key = plist_aes_key->prop->val;
                        
                        /*
                         * This message needs to be secure, but it's just an empty shell.
                         * This dummy property is used to enforce authenticity thru decryption
                         * at the recipient's side, which would fail to go thru otherwise.
                         */
                        struct pmppprop_t *p_dummy = make_prop(PMPP_L_PAYLOAD, util_itoa(rand()), 1, 0);
                        struct pmppprop_t *p_c_id  = make_prop(PMPP_L_UUID, c_id, 0, 0);
                        
                        set_prop(p_msg_type, &ping);
                        set_prop(p_dummy, &ping);
                        set_prop(p_c_id, &ping);
                        
                        struct pmppprop_t *p_c_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(c_type), 0, p_c_id->domain);
                        
                        set_prop(p_c_type, &ping);
                        pmpp_send_msg(c, msg_type, 1, &ping, key, iv);
                }
        }
}

/**
 * Pings everyone on the given correspondent's correspondent
 * list.
 */
void pmpp_ping_list(const struct pmppcorres_t *c)
{
        if ( c ) {
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
                pmpp_broadcast(ping, c->clist, NULL, 1, PMPP_E_ANY, PMPP_R_UNKNOWN);
        }
}

void pmpp_process_msg(struct pmppmsg_t *m)
{
        if ( !m ||
             !m->sender )
                return;
        
        struct pmppproplist_t *plist_payload = proplist(PMPP_L_PAYLOAD, 0, m->plist);
        
        if ( plist_payload ) {
                enum pmppentity_t recip_type = PMPP_E_ANY;
                struct pmppprop_t *p_recip_id   = prop(PMPP_L_UUID, plist_payload->prop->domain, m->plist);
                struct pmppprop_t *p_recip_type = prop(PMPP_L_UUIDTYPE, plist_payload->prop->domain, m->plist);
                
                if ( p_recip_id &&
                     p_recip_type ) {
                        recip_type = atoi(p_recip_type->val);
                        char *iv  = NULL;
                        char *key = NULL;
                        struct pmppcorres_t *recipient = NULL;
                        
                        if ( recip_type == PMPP_E_SERVER ) { // Received a message for dispatching.
                                recipient = corres(p_recip_id->val, PMPP_E_SERVER, local->clist);
                                
                                if ( recipient ) {
                                        /* Construct a new message.
                                         * NOTE: reuse the message identifier that the server already gave back
                                         * to the service. DON'T create a new one.
                                         */
                                        struct pmppprop_t *p_m_id         = clonep(get_uuidp(PMPP_E_MESSAGE, m->plist));
                                        struct pmppprop_t *p_m_id_type    = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_MESSAGE), 0, p_m_id->domain);
                                        struct pmppprop_t *tmp_recip_id   = clonep(p_recip_id);
                                        struct pmppprop_t *tmp_recip_type = clonep(p_recip_type);
                                        struct pmppprop_t *p_service_id   = clonep(get_uuidp(PMPP_E_SERVICE, m->sender->plist));
                                        struct pmppprop_t *p_service_type = clonep(prop(PMPP_L_UUIDTYPE, p_service_id->domain, m->sender->plist));
                                        struct pmppproplist_t *plist_iv  = proplist(PMPP_L_CRYPTO_IV, 0, recipient->plist);
                                        struct pmppproplist_t *plist_key = proplist(PMPP_L_CRYPTO_KEY, 0, recipient->plist);
                                        struct pmppproplist_t *new_m     = NULL;
                                        
                                        p_service_id->domain   = plist_payload->prop->domain;
                                        p_service_type->domain = plist_payload->prop->domain;
                                        tmp_recip_id->domain   = 0;
                                        tmp_recip_id->secure   = 0;
                                        tmp_recip_type->secure = 0;
                                        tmp_recip_type->val    = util_itoa(PMPP_E_SERVER_RECIPIENT);
                                        
                                        set_prop(clonep(plist_payload->prop), &new_m);
                                        set_prop(p_m_id, &new_m);
                                        set_prop(p_m_id_type, &new_m);
                                        set_prop(p_service_id, &new_m);
                                        set_prop(p_service_type, &new_m);
                                        set_prop(tmp_recip_id, &new_m);
                                        
                                        tmp_recip_type->domain = tmp_recip_id->domain;
                                        
                                        set_prop(tmp_recip_type, &new_m);
                                        
                                        if ( plist_iv )
                                                iv = plist_iv->prop->val;
                                        
                                        if ( plist_key )
                                                key = plist_key->prop->val;
                                        
                                        pmpp_send_msg(recipient, PMPP_MT_MESSAGE, 1, &new_m, key, iv);
                                } else {
                                        printf("LOG: recipient server %s not found!\n", p_recip_id->val);
                                }
                        } else if ( recip_type == PMPP_E_SERVICE ) { // Received a message for delivery.
                                recipient = corres(p_recip_id->val, PMPP_E_SERVICE, local->clist);
                                
                                if ( recipient ) {
                                        /* Construct a new message. */
                                        struct pmppprop_t *p_m_id           = clonep(get_uuidp(PMPP_E_MESSAGE, m->plist));
                                        struct pmppprop_t *p_m_id_type      = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_MESSAGE), 0, p_m_id->domain);
                                        struct pmppprop_t *p_server_id      = clonep(get_uuidp(PMPP_E_SERVER, m->sender->plist));
                                        struct pmppprop_t *p_server_id_type = clonep(prop(PMPP_L_UUIDTYPE, p_server_id->domain, m->sender->plist));
                                        struct pmppproplist_t *plist_iv    = proplist(PMPP_L_CRYPTO_IV, 0, recipient->plist);
                                        struct pmppproplist_t *plist_key   = proplist(PMPP_L_CRYPTO_KEY, 0, recipient->plist);
                                        struct pmppproplist_t *plist_laddr = proplist(PMPP_L_INET_LADDR, 0, m->plist);
                                        struct pmppproplist_t *plist_lport = proplist(PMPP_L_INET_LPORT, 0, m->plist);
                                        struct pmppproplist_t *plist_paddr = proplist(PMPP_L_INET_PADDR, 0, m->plist);
                                        struct pmppproplist_t *plist_pport = proplist(PMPP_L_INET_PPORT, 0, m->plist);
                                        struct pmppproplist_t *new_m       = NULL;
                                        struct pmppprop_t *p_laddr            = clonep(plist_laddr->prop);
                                        struct pmppprop_t *p_lport            = clonep(plist_lport->prop);
                                        struct pmppprop_t *p_paddr            = clonep(plist_paddr->prop);
                                        struct pmppprop_t *p_pport            = clonep(plist_pport->prop);
                                        struct pmppprop_t *tmp_recipient_id   = clonep(p_recip_id);
                                        struct pmppprop_t *tmp_recipient_type = clonep(p_recip_type);
                                        
                                        p_server_id->domain = 0;
                                        tmp_recipient_id->domain = 0;
                                        
                                        // Tie these to the message ID.
                                        p_laddr->domain = p_m_id->domain;
                                        p_lport->domain = p_m_id->domain;
                                        p_paddr->domain = p_m_id->domain;
                                        p_pport->domain = p_m_id->domain;
                                        
                                        set_prop(p_m_id, &new_m);
                                        set_prop(p_m_id_type, &new_m);
                                        set_prop(p_server_id, &new_m);
                                        
                                        p_server_id_type->domain = p_server_id->domain;
                                        
                                        set_prop(p_server_id_type, &new_m);
                                        set_prop(tmp_recipient_id, &new_m);
                                        
                                        tmp_recipient_type->domain = tmp_recipient_id->domain;
                                        
                                        set_prop(tmp_recipient_type, &new_m);
                                        set_prop(p_laddr, &new_m);
                                        set_prop(p_lport, &new_m);
                                        set_prop(p_paddr, &new_m);
                                        set_prop(p_pport, &new_m);
                                        set_prop(clonep(plist_payload->prop), &new_m);
                                        
                                        if ( plist_iv )
                                                iv = plist_iv->prop->val;
                                        
                                        if ( plist_key )
                                                key = plist_key->prop->val;
                                        
                                        printf("LOG: new message for %s\n", p_recip_id->val);
                                        pmpp_send_msg(recipient, PMPP_MT_MESSAGE, 1, &new_m, key, iv);
                                } else {
                                        printf("LOG: recipient service %s not found!\n", p_recip_id->val);
                                }
                        }
                }
                else {
                        wtf(0, "pmpp_process_msg: message is missing a recipient", 0);
                }
        } else {
                wtf(0, "pmpp_process_msg: message is missing payload", 0);
        }
}

void pmpp_probe(struct pmppcorres_t *c)
{
        // Don't keep probing for the same correspondent.
        if ( c &&
             c->rvp == 0 &&
             c->probe == 0 ) {
                char *c_id = get_uuid(PMPP_E_SERVER, c->plist);
                
                if ( c_id ) {
                        struct pmppcorreslist_t *iter = c->clist;
                        
                        while ( iter ) {
                                if ( iter->corres ) {
                                        char *rvp_id = get_uuid(PMPP_E_RVP, iter->corres->plist);
                                        
                                        if ( !rvp_id )
                                                rvp_id = get_uuid(PMPP_E_SERVER, iter->corres->plist);
                                        
                                        if ( rvp_id ) {
                                                c->probe = 1;
                                                
                                                struct pmppprop_t *p_rvp_id = make_prop(PMPP_L_UUID, rvp_id, 0, 0);
                                                struct pmppprop_t *p_target = make_prop(PMPP_L_UUID, c_id, 0, 0);
                                                struct pmppproplist_t *probe = NULL;
                                                
                                                set_prop(p_rvp_id, &probe);
                                                set_prop(p_target, &probe);
                                                
                                                struct pmppprop_t *p_target_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVER), 0, p_target->domain);
                                                struct pmppprop_t *p_type        = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVER_RECIPIENT), 0, p_rvp_id->domain);
                                                
                                                set_prop(p_target_type, &probe);
                                                set_prop(p_type, &probe);
                                                
                                                pmpp_send_msg(iter->corres, PMPP_MT_PROBE, 1, &probe, NULL, NULL);
                                        }
                                }
                                
                                iter = iter->next;
                        }
                }
        }
}

/**
 * Request identification from someone for the given
 * correspondent.
 */
void pmpp_req_key(const struct pmppcorres_t *c)
{
        
}

void pmpp_resend_msg(struct pmppmsg_t *m)
{
        char *recipient_addr = net_ntoa(m->recipient->laddr.sin_addr);
        m->attempts++;
        
        if ( strcmp(recipient_addr, LOCALHOST) == 0 ||
             sock_addr_cmp_addr(&m->recipient->laddr, &m->recipient->paddr) == 0 ) {
                send_udp(m, m->recipient->laddr, 0);
        } else {
                // Since we have no idea whether they're on our LAN or not, send to both addresses.
                send_udp(m, m->recipient->laddr, 0);
                send_udp(m, m->recipient->paddr, 0);
        }
        
        free(recipient_addr);
}

void pmpp_rvp(struct pmppcorreslist_t *clist, const struct pmppcorres_t *recipient)
{
        if ( clist &&
             recipient ) {
                char *recipient_id = get_uuid(PMPP_E_SERVER, recipient->plist);
                struct pmppcorreslist_t *iter = clist;
                
                while ( iter ) {
                        if ( iter->corres &&
                             iter->corres->verified ) {
                                char *server_id = get_uuid(PMPP_E_SERVER, iter->corres->plist);
                                
                                if ( server_id &&
                                     strcmp(server_id, recipient_id) != 0 ) { // Don't send the recipient to itself!
                                        char *iv  = NULL;
                                        char *key = NULL;
                                        struct pmppprop_t *p_id = make_prop(PMPP_L_UUID, recipient_id, 0, 0);
                                        struct pmppprop_t *p_rvp_id = make_prop(PMPP_L_UUID, server_id, 1, 0);
                                        struct pmppproplist_t *plist_iv  = proplist(PMPP_L_CRYPTO_IV, 0, recipient->plist);
                                        struct pmppproplist_t *plist_key = proplist(PMPP_L_CRYPTO_KEY, 0, recipient->plist);
                                        struct pmppproplist_t *plist_laddr = proplist(PMPP_L_INET_LADDR, 0, iter->corres->plist);
                                        struct pmppproplist_t *plist_lport = proplist(PMPP_L_INET_LPORT, 0, iter->corres->plist);
                                        struct pmppproplist_t *plist_paddr = proplist(PMPP_L_INET_PADDR, 0, iter->corres->plist);
                                        struct pmppproplist_t *plist_pport = proplist(PMPP_L_INET_PPORT, 0, iter->corres->plist);
                                        struct pmppproplist_t *m         = NULL;
                                        
                                        struct pmppprop_t *p_laddr = clonep(plist_laddr->prop);
                                        struct pmppprop_t *p_lport = clonep(plist_lport->prop);
                                        struct pmppprop_t *p_paddr = clonep(plist_paddr->prop);
                                        struct pmppprop_t *p_pport = clonep(plist_pport->prop);
                                        
                                        set_prop(p_id, &m);
                                        set_prop(p_rvp_id, &m);
                                        
                                        // Tie these to the RVP's ID.
                                        p_laddr->domain = p_rvp_id->domain;
                                        p_lport->domain = p_rvp_id->domain;
                                        p_paddr->domain = p_rvp_id->domain;
                                        p_pport->domain = p_rvp_id->domain;
                                        
                                        struct pmppprop_t *p_rvp_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_RVP), 1, p_rvp_id->domain);
                                        struct pmppprop_t *p_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVER_RECIPIENT), 0, p_id->domain);
                                        
                                        set_prop(p_rvp_type, &m);
                                        set_prop(p_type, &m);
                                        set_prop(p_laddr, &m);
                                        set_prop(p_lport, &m);
                                        set_prop(p_paddr, &m);
                                        set_prop(p_pport, &m);
                                        
                                        if ( plist_iv )
                                                iv = plist_iv->prop->val;
                                        
                                        if ( plist_key )
                                                key = plist_key->prop->val;
                                        
                                        pmpp_send_msg(recipient, PMPP_MT_RVP, 1, &m, key, iv);
                                }
                        }
                        
                        iter = iter->next;
                }
        }
}

/**
 * Adds standard PMPP metadata to an outgoing message.
 */
void pmpp_season(struct pmppmsg_t *m)
{
        char *local_id = get_uuid(PMPP_E_SERVER, local->plist);
        struct pmppprop_t *p_id = clonep(get_uuidp(PMPP_E_MESSAGE, m->plist));
        
        if ( !p_id )
                p_id = make_prop(PMPP_L_UUID, uuid(), 0, 0);
        
        set_prop(p_id, &m->plist);
        
        struct pmppprop_t *p_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_MESSAGE), 0, p_id->domain);
        struct pmppprop_t *p_time    = prop(PMPP_L_TIME, p_id->domain, m->plist);
        struct pmppprop_t *p_version = prop(PMPP_L_VERSION, p_id->domain, m->plist);
        
        if ( !p_time )
                p_time = make_prop(PMPP_L_TIME, timestamp(), 0, p_id->domain);
        
        if ( !p_version )
                p_version = make_prop(PMPP_L_VERSION, PMPP_VERSION, 0, p_id->domain);
        
        set_prop(p_id_type, &m->plist);
        set_prop(p_time, &m->plist);
        set_prop(p_version, &m->plist);
        
        if ( local_id ) {
                struct pmppprop_t *p_sender_id = clonep(get_uuidp(PMPP_E_SERVER_SENDER, m->plist));
                
                if ( !p_sender_id )
                        p_sender_id = make_prop(PMPP_L_UUID, local_id, 0, 0);
                
                set_prop(p_sender_id, &m->plist);
                
                struct pmppprop_t *p_sender_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVER_SENDER), 0, p_sender_id->domain);
                struct pmppprop_t *p_laddr          = make_prop(PMPP_L_INET_LADDR, net_ntoa(local->laddr.sin_addr), 0, p_sender_id->domain);
                struct pmppprop_t *p_lport          = make_prop(PMPP_L_INET_LPORT, util_itoa(net_ntohs(local->laddr)), 0, p_sender_id->domain);
                
                set_prop(p_sender_id_type, &m->plist);
                set_prop(p_laddr, &m->plist);
                set_prop(p_lport, &m->plist);
        }
}

void pmpp_send_msg(const struct pmppcorres_t *recipient, const enum pmppmessage_t type, const int need_ack, struct pmppproplist_t **content, const char *key, const char *iv)
{
        struct pmppmsg_t *m = make_msg();
        m->plist    = *content;
        
        // We just need to insert some metadata before sending.
        struct pmppproplist_t *plist_msg_type = proplist(PMPP_L_MESSAGE_TYPE, 0, *content); // Check if the message type is already included.
        struct pmppprop_t *p_msg_type = NULL;
        
        if ( plist_msg_type ) {
                p_msg_type = plist_msg_type->prop;
        } else {
                p_msg_type = make_prop(PMPP_L_MESSAGE_TYPE, util_itoa(type), 0, 0); // Not; insert it.
                
                set_prop(p_msg_type, &m->plist);
        }
        
        pmpp_season(m);
        
        /*
         * Store the serialized version of the message.
         * We will be resending this message a few times (because UDP)
         * so we don't want to keep on encrypting, compressing, etc.
         */
        m->critical  = criticality(m); // Call after setting message plist (with the message type included).
        m->pkg       = util_mtoa(m, key, iv);
        m->recipient = (struct pmppcorres_t *)recipient;
        m->sender    = local;
        
        sha(m->pkg, &m->m_hash); // Save a hash of the original message.
        
        char *recipient_addr = net_ntoa(recipient->paddr.sin_addr);
        
        /*
         * In the case of localhost, or the public address being
         * identical to the private one, send the message to only
         * 1 address, not both.
         */
        if ( strcmp(recipient_addr, LOCALHOST) == 0 ||
             sock_addr_cmp_addr(&recipient->laddr, &recipient->paddr) == 0 ) {
                send_udp(m, recipient->laddr, need_ack);
        } else {
                // Since we have no idea whether they're on our LAN or not, send to both addresses.
                send_udp(m, recipient->laddr, need_ack);
                send_udp(m, recipient->paddr, need_ack);
        }
        
        free(recipient_addr);
}

/**
 * Informs correspondents that the local machine is
 * going offline.
 */
void pmpp_sleep(void)
{
        enum pmppmessage_t msg_type = PMPP_MT_SLEEP;
        struct pmppprop_t *p_msg_type = make_prop(PMPP_L_MESSAGE_TYPE, util_itoa(msg_type), 0, 0);
        struct pmppproplist_t *sleep = NULL;
        
        /*
         * This message needs to be secure, but it's just an empty shell.
         * This dummy property is used to enforce authenticity thru decryption
         * at the recipient's side, which would fail to go thru otherwise.
         */
        struct pmppprop_t *p_dummy = make_prop(PMPP_L_PAYLOAD, util_itoa(rand()), 1, 0);
        
        set_prop(p_msg_type, &sleep);
        set_prop(p_dummy, &sleep);
        pmpp_broadcast(sleep, local->clist, NULL, 0, PMPP_E_ANY, PMPP_R_ONLINE);
}

/**
 * Updates the given correspondent on the presence of the
 * correspondents on its correspondent list.
 */
void pmpp_update_presence(const struct pmppcorres_t *c)
{
        if ( c &&
             local->clist ) {
                char *c_id = get_uuid(PMPP_E_SERVER, c->plist);
                enum pmppentity_t c_type = PMPP_E_SERVER;
                struct pmppcorreslist_t *iter_local = local->clist;
                
                if ( !c_id ) {
                        c_type = PMPP_E_SERVICE;
                        c_id = get_uuid(c_type, c->plist);
                }
                
                while ( iter_local ) {
                        if ( iter_local->corres ) {
                                char *iter_local_id = get_uuid(PMPP_E_SERVER, iter_local->corres->plist);
                                enum pmppentity_t iter_type = PMPP_E_SERVER;
                                struct pmppcorreslist_t *iter = iter_local->corres->clist;
                                
                                if ( !iter_local_id ) {
                                        iter_type = PMPP_E_SERVICE;
                                        iter_local_id = get_uuid(iter_type, iter_local->corres->plist);
                                }
                                
                                /*
                                 * Conditions:
                                 * • Don't compare the given one to itself.
                                 * • Don't notify servers about other servers.
                                 * • Don't notify services about other services.
                                 */
                                if ( !iter_local_id ||
                                     strcmp(c_id, iter_local_id) == 0 ||
                                     c_type == iter_type ) {
                                        iter_local = iter_local->next;
                                        
                                        continue;
                                }
                                
                                while ( iter ) {
                                        if ( iter->corres ) {
                                                char *iter_id = get_uuid(c_type, iter->corres->plist);
                                                
                                                if ( iter_id &&
                                                     strcmp(c_id, iter_id) == 0 ) // The given one is on this correspondent's clist, send an update about them.
                                                        pmpp_notif_presence(c, iter_local->corres, iter_local->corres->reachability);
                                                
                                                iter = iter->next;
                                        }
                                        
                                }
                        }
                        
                        iter_local = iter_local->next;
                }
        }
}

//
//  util.c
//  pmppd
//
//  Created on 3/5/16.
//
//

#include "util.h"

#define __USE_XOPEN

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uuid/uuid.h>
#include <zlib.h>

#define TIMESTAMP_FORM  "%Y-%m-%d %H:%M:%S"
#define ZLIB_CHUNK      16384

#include "crypto.h"
#include "io.h"
#include "main.h"
#include "net.h"
#include "pmpp.h"

char *get_uuid(const enum pmppentity_t type, struct pmppproplist_t *list)
{
        char *identifier = NULL;
        
        if ( list ) {
                struct pmppprop_t *p_id = get_uuidp(type, list);
                
                if ( p_id )
                        identifier = p_id->val;
        }
        
        return identifier;
}

/**
 * This function returns a formatted string of the correspondents' UUIDs.
 */
char *serializec(const struct pmppcorreslist_t *clist)
{
        char *text = NULL;
        const struct pmppcorreslist_t *iter = clist;
        
        while ( iter ) {
                if ( iter->corres) {
                        enum pmppentity_t c_type = PMPP_E_SERVER;
                        
                        if ( iter->corres->rvp )
                                c_type = PMPP_E_RVP;
                        
                        if ( iter->corres->verified != 0 ) { // Only verified ones get dumped.
                                char *c_id = get_uuid(c_type, iter->corres->plist);
                                
                                if ( !c_id ) {
                                        c_type = PMPP_E_SERVICE;
                                        c_id = get_uuid(c_type, iter->corres->plist);
                                }
                                
                                size_t needed = snprintf(NULL, 0, "%s%s", c_id, PMPP_PROP_DELIMETER) + 1; // +1 for '\0'.
                                char *line = malloc(needed);
                                
                                sprintf(line, "%s%s", c_id, PMPP_PROP_DELIMETER);
                                
                                if ( !text ) {
                                        text = malloc(strlen(line) + 1);
                                        
                                        strcpy(text, line);
                                } else {
                                        text = realloc(text, strlen(text) + strlen(line) + 1);
                                        
                                        strcat(text, line);
                                }
                                
                                if ( line ) {
                                        free(line);
                                        
                                        line = NULL;
                                }
                        }
                }
                
                iter = iter->next;
        }
        
        if ( !text )
                text = ""; // To avoid "(null)" being dumped into the file.
        
        return text;
}

/**
 * This function returns a formatted string of the messages' UUIDs. It also dumps each
 * individual message to the disk.
 */
char *serializem(const struct pmppmsglist_t *mlist, const char *key, const char *iv)
{
        char *text = NULL;
        const struct pmppmsglist_t *iter = mlist;
        
        while ( iter ) {
                if ( iter->msg &&
                     iter->msg->critical != 0 ) { // Ignore non-critical messages.
                        char *m_id = get_uuid(PMPP_E_MESSAGE, iter->msg->plist);
                        size_t needed = snprintf(NULL, 0, "%s%s", m_id, PMPP_PROP_DELIMETER) + 1; // +1 for '\0'.
                        char *line = malloc(needed);
                        
                        sprintf(line, "%s%s", m_id, PMPP_PROP_DELIMETER);
                        
                        if ( !text ) {
                                text = malloc(strlen(line) + 1);
                                
                                strcpy(text, line);
                        } else {
                                text = realloc(text, strlen(text) + strlen(line) + 1);
                                
                                strcat(text, line);
                        }
                        
                        if ( line ) {
                                free(line);
                                
                                line = NULL;
                        }
                        
                        dump_msg(iter->msg, key, iv);
                }
                
                iter = iter->next;
        }
        
        if ( !text )
                text = ""; // To avoid "(null)" being dumped into the file.
        
        return text;
}

char *serializep(const struct pmppproplist_t *plist, const char *key, const char *iv)
{
        char *plaintext = NULL;
        char *secure    = NULL;
        const struct pmppproplist_t *iter = plist;
        
        while ( iter ) {
                struct pmppprop_t *property = iter->prop;
                char *prop = util_ptoa(property);
                
                if ( prop ) {
                        if ( property->secure == 0 ) {
                                if ( !plaintext ) {
                                        plaintext = malloc(strlen(prop) + 1);
                                        
                                        strcpy(plaintext, prop);
                                } else {
                                        plaintext = realloc(plaintext, strlen(plaintext) + strlen(prop) + 1);
                                        
                                        strcat(plaintext, prop);
                                }
                        } else if ( iv &&
                                    key ) {
                                if ( !secure ) {
                                        secure = malloc(strlen(prop) + 1);
                                        
                                        strcpy(secure, prop);
                                } else {
                                        secure = realloc(secure, strlen(secure) + strlen(prop) + 1);
                                        
                                        strcat(secure, prop);
                                }
                        }
                }
                
                iter = iter->next;
        }
        
        // Encrypt & attach the encrypted part.
        if ( secure ) {
                char *b64 = NULL;
                unsigned char *ciphertext = NULL;
                unsigned char *compressed = NULL;
                
                size_t aes_len = aes_encrypt(secure, key, iv, &ciphertext);                // Encrypt.
                size_t compressed_len = util_compress(ciphertext, aes_len, &compressed);   // Compress.
                size_t b64enc_len = base64_encode(compressed, compressed_len, &b64);       // Encode.
                size_t needed = snprintf(NULL, 0, "#!%s%s", b64, PMPP_PROP_DELIMETER) + 1; // +1 for '\0'.
                char *buf = malloc(needed);
                
                struct pmppprop_t *p_encoded_len = make_prop(PMPP_L_ENCODE_SIZE, util_itoa((int)b64enc_len), 0, 1);
                char *encoded_len = util_ptoa(p_encoded_len);
                
                sprintf(buf, "#!%s%s", b64, PMPP_PROP_DELIMETER);
                
                if ( plaintext ) {
                        plaintext = realloc(plaintext, strlen(plaintext) + strlen(encoded_len) + strlen(buf) + 1);
                        
                        strcat(plaintext, encoded_len); // Attach the size of the compressed data.
                } else {
                        plaintext = malloc(strlen(encoded_len) + strlen(buf) + 1);
                        
                        strcpy(plaintext, encoded_len);
                }
                
                strcat(plaintext, buf); // Attach the compressed, encoded, encrypted data.
                free(buf);
                free(b64);
                free(ciphertext);
                free(compressed);
                free(secure);
                
                buf        = NULL;
                b64        = NULL;
                ciphertext = NULL;
                compressed = NULL;
                secure     = NULL;
        }
        
        if ( !plaintext )
                plaintext = ""; // To avoid "(null)" being dumped into the file.
        
        return plaintext;
}

/**
 * @return A Unix timestamp string of the current date & time.
 */
char *timestamp(void)
{
        time_t curr_time;
        
        time(&curr_time);
        
        struct tm *ptm = gmtime(&curr_time);
        char *buf = malloc(25);
        
        strftime(buf, 25, TIMESTAMP_FORM, ptm);
        
        return buf;
}

/**
 * Converts a float to a char pointer.
 */
char *util_ftoa(const float f)
{
        size_t needed = snprintf(NULL, 0, "%f", f) + 1; // +1 for '\0'.
        char *c = malloc(needed);
        
        sprintf(c, "%f", f);
        
        return c;
}

/**
 * Converts an int to a char pointer.
 */
char *util_itoa(const int i)
{
        size_t needed = snprintf(NULL, 0, "%d", i) + 1; // +1 for '\0'.
        char *c = malloc(needed);
        
        sprintf(c, "%d", i);
        
        return c;
}

/**
 * Converts a message into an ASCII string. Secure properties are encrypted
 * using the provided key & IV.
 */
char *util_mtoa(const struct pmppmsg_t *m, const char *key, const char *iv)
{
        if ( m )
                return serializep(m->plist, key, iv);
        
        return NULL;
}

/**
 * Converts a property into an ASCII string.
 */
char *util_ptoa(const struct pmppprop_t *property)
{
        if ( property ) {
                size_t needed = snprintf(NULL, 0, "%d:%d>%s%s", property->domain, property->label, property->val, PMPP_PROP_DELIMETER) + 1; // +1 for '\0'.
                char *buf = malloc(needed);
                
                sprintf(buf, "%d:%d>%s%s", property->domain, property->label, property->val, PMPP_PROP_DELIMETER);
                
                return buf;
        }
        
        return NULL;
}

/**
 * @return A universally unique identifier.
 */
char *uuid(void)
{
        char *uuid_str = malloc(37); // e.g. "1b4e28ba-2fa1-11d2-883f-0016d3cca427" + '\0'
        uuid_t id;
        
        uuid_generate(id);
        uuid_unparse_lower(id, uuid_str);
        
        return uuid_str;
}

/**
 * Adds the given correspondet to the given correspondet list.
 */
int add_corres(struct pmppcorres_t *c, enum pmppentity_t type, struct pmppcorreslist_t **clist)
{
        if ( c &&
             clist ) {
                if ( !*clist ) {
                        *clist = malloc(sizeof(*clist));
                        
                        if ( *clist ) {
                                (*clist)->next = NULL;
                                (*clist)->corres = c;
                        } else {
                                return -1;
                        }
                } else {
                        // Search if the correspondent already exists.
                        struct pmppcorreslist_t *iter = *clist;
                        char *c_id    = get_uuid(type, c->plist);
                        char *iter_id = get_uuid(type, iter->corres->plist);
                        
                        while ( iter->next ) {
                                if ( c_id &&
                                     iter_id ) {
                                        if ( uuidcmp(iter_id, c_id) == 0 ) // Exists.
                                                return 0;
                                } else {
                                        // No identifier present. Compare IP addresses.
                                        char *paddr_c    = net_ntoa(c->paddr.sin_addr);
                                        char *paddr_iter = net_ntoa(iter->corres->paddr.sin_addr);
                                        struct sockaddr_in addr_c    = c->paddr;
                                        struct sockaddr_in addr_iter = iter->corres->paddr;
                                        
                                        // We want to first try their public addresses. Check if both have one.
                                        if ( paddr_c &&
                                             paddr_iter &&
                                             (strcmp(paddr_c, "0.0.0.0") == 0 ||
                                             strcmp(paddr_iter, "0.0.0.0") == 0) ) {
                                                addr_c    = c->laddr;
                                                addr_iter = iter->corres->laddr;
                                        }
                                        
                                        if ( sock_addr_cmp_addr(&addr_c, &addr_iter) == 0) {
                                                if ( paddr_c )
                                                        free(paddr_c);
                                                
                                                if ( paddr_iter )
                                                        free(paddr_iter);
                                                
                                                return 0;
                                        }
                                        
                                        if ( paddr_c )
                                                free(paddr_c);
                                        
                                        if ( paddr_iter )
                                                free(paddr_iter);
                                }
                                
                                iter = iter->next;
                                iter_id = get_uuid(type, iter->corres->plist);
                        }
                        
                        // This block checks the final item (skipped by the while loop).
                        if ( c_id &&
                             iter_id ) {
                                if ( uuidcmp(iter_id, c_id) == 0 ) // Exists.
                                        return 0;
                        } else {
                                // No identifier present. Compare IP addresses.
                                if ( !c_id &&
                                     sock_addr_cmp_addr(&c->paddr, &iter->corres->paddr) == 0 )
                                        return 0;
                        }
                        
                        // At this point, it means we have to create a new correspondent item.
                        iter->next = malloc(sizeof(*clist));
                        iter = iter->next;
                        
                        if ( !iter )
                                return -1;
                        
                        iter->corres = c;
                        iter->next = NULL;
                }
                
                return 0;
        }
        
        return -1;
}

/**
 * Adds the given message to the given message list.
 */
int add_msg(struct pmppmsg_t *m, struct pmppmsglist_t **mlist)
{
        while ( pthread_mutex_trylock(&mutex_util) != 0 ); // Wait to obtain a lock.
        
        if ( m &&
             mlist ) {
                if ( !m->m_hash ) {
                        wtf(0, "add_msg: message missing hash", 0);
                        pthread_mutex_unlock(&mutex_util);
                        
                        return -1;
                }
                
                if ( !*mlist ) {
                        *mlist = malloc(sizeof(*mlist));
                        
                        if ( *mlist ) {
                                (*mlist)->next = NULL;
                                (*mlist)->msg = m;
                        } else {
                                wtf(0, "add_msg: malloc failed for new message list", 0);
                                pthread_mutex_unlock(&mutex_util);
                                
                                return -1;
                        }
                } else {
                        // Search if the message already exists.
                        struct pmppmsglist_t *iter = *mlist;
                        
                        while ( iter->next ) {
                                if ( iter->msg->m_hash &&
                                     strcmp(m->m_hash, iter->msg->m_hash) == 0 ) { // Exists.
                                        pthread_mutex_unlock(&mutex_util);
                                        
                                        return 0;
                                }
                                
                                iter = iter->next;
                        }
                        
                        // This block checks the final item (skipped by the while loop).
                        if ( iter->msg->m_hash ) {
                                if ( strcmp(m->m_hash, iter->msg->m_hash) == 0 ) {
                                        pthread_mutex_unlock(&mutex_util);
                                        
                                        return 0;
                                }
                        }
                        
                        // At this point, it means we have to create a new message item.
                        iter->next = malloc(sizeof(*mlist));
                        iter = iter->next;
                        
                        if ( !iter ) {
                                pthread_mutex_unlock(&mutex_util);
                                
                                return -1;
                        }
                        
                        iter->msg = m;
                        iter->next = NULL;
                }
                
                pthread_mutex_unlock(&mutex_util);
                
                return 0;
        }
        
        pthread_mutex_unlock(&mutex_util);
        
        return -1;
}

int criticality(const struct pmppmsg_t *m)
{
        enum pmppmessage_t msg_type = PMPP_MT_UNKNOWN;
        int ret = 0;
        struct pmppproplist_t *p_msg_type = proplist(PMPP_L_MESSAGE_TYPE, 0, m->plist);
        
        if ( p_msg_type ) {
                msg_type = atoi(p_msg_type->prop->val);
                
                struct pmppproplist_t *p_hash = proplist(PMPP_L_REF_HASH, 0, m->plist);
                
                /*
                 * Check if this is an ack. Acks are never critical, regardless
                 * of the message type.
                 */
                if ( !p_hash ) {
                        switch ( msg_type ) {
                                case PMPP_MT_BYE:
                                case PMPP_MT_MESSAGE:
                                case PMPP_MT_MESSAGE_FWD:
                                case PMPP_MT_MESSAGE_STAT:
                                case PMPP_MT_UNREGISTER:
                                        ret = 1;
                                        
                                        break;
                                        
                                default:
                                        break;
                        }
                }
                
        } else {
                wtf(0, "criticality: missing message type", 0);
        }
        
        return ret;
}

/**
 * Dumps all the correspondents in the given list.
 * @return 0 if all correspondents were successfully
 * dumped or in case the list is empty, -1 otherwise.
 */
int dump_clist(const struct pmppcorreslist_t *list)
{
        int ret = 0;
        
        if ( list ) {
                struct pmppcorreslist_t *iter = (struct pmppcorreslist_t *)list;
                
                while ( iter ) {
                        if ( iter->corres->verified != 0 ) { // Only verified ones get dumped.
                                if ( dump_corres(iter->corres) != 0 )
                                        ret = -1;
                        }
                        
                        iter = iter->next;
                }
        }
        
        return ret;
}

/**
 * Dumps the given correspondent to the disk.
 * @return 0 if the correspondent was successfully dumped,
 * -1 otherwise.
 */
int dump_corres(const struct pmppcorres_t *c)
{
        if ( c ) {
                char *c_id = get_uuid(PMPP_E_SERVER, c->plist);
                char *clist = NULL;
                char *mlist = NULL;
                char *plist = NULL;
                
                if ( !c_id )
                        c_id = get_uuid(PMPP_E_SERVICE, c->plist);
                
                if ( !c_id )
                        c_id = get_uuid(PMPP_E_RVP, c->plist);
                
                util_ctoa(c, &clist, &mlist, &plist);
                
                if ( !clist ||
                     !mlist ||
                     !plist ) {
                        wtf(0, "dump_corres: one of the lists is null", 0);
                        
                        return -1;
                }
                
                int ret_c = io_dump(c_id, clist, 'c');
                int ret_m = io_dump(c_id, mlist, 'm');
                int ret_p = io_dump(c_id, plist, 'p');
                
                if ( ret_c != 0 ||
                     ret_m != 0 ||
                     ret_p != 0 ) {
                        wtf(0, "dump_corres: bad dump", 0);
                        
                        return -1;
                }
                
                return 0;
        }
        
        wtf(0, "attempting to dump null correspondent", 0);
        
        return -1;
}

/**
 * Dumps the given message to the disk.
 */
int dump_msg(const struct pmppmsg_t *m, const char *key, const char *iv)
{
        char *m_id = get_uuid(PMPP_E_MESSAGE, m->plist);
        
        if ( !m_id )
                return -1;
        
        char *plist = util_mtoa(m, key, iv);
        
        return io_dump(m_id, plist, 'p');
}

int erase_corres(const char *c_id)
{
        int ret_c = io_remove(c_id, 'c');
        int ret_m = io_remove(c_id, 'm');
        int ret_p = io_remove(c_id, 'p');
        int ret_s = rsa_remove_keys(c_id);
        
        if ( ret_c != 0 ||
             ret_m != 0 ||
             ret_p != 0 ||
             ret_s != 0 )
                return -1;
        
        return 0;
}

int erase_msg(const char *m_id)
{
        return io_remove(m_id, 'p');
}

/**
 * Checks if the given string is a valid UUID.
 * @return 0 if it is a valid UUID, -1 otherwise.
 */
int is_uuid(char *str)
{
        if ( !str )
                return -1;
        
        uuid_t uuid;
        
        return uuid_parse(str, uuid);
}

/**
 * Removes the correspondent with the matching identifier.
 * @return 1 if the correspondent was removed, 0 if it was not found,
 * or -1 if any errors were encountered.
 */
int remove_corres(const char *c_id, enum pmppentity_t type, struct pmppcorreslist_t **clist)
{
        if ( c_id &&
             clist &&
            *clist ) {
                // Search if the correspondent exists.
                struct pmppcorreslist_t *iter = *clist;
                struct pmppcorreslist_t *prev = *clist;
                
                while ( iter ) {
                        char *iter_id = get_uuid(type, iter->corres->plist);
                        
                        if ( uuidcmp(iter_id, c_id) == 0 ) {
                                // Chain the previous item to the next one in line (if one exists).
                                if ( iter->next )
                                        prev->next = iter->next;
                                else
                                        prev->next = NULL;
                                
                                if ( iter == prev ) {
                                        /*
                                         * If we're removing the 1st item & the list still has
                                         * more items, we need to advance the list pointer forward.
                                         */
                                        if ( !prev->next ) {
                                                (*clist)->corres = NULL;
                                                
                                                free(*clist);
                                                
                                                *clist = NULL;
                                                clist = NULL;
                                        } else {
                                                *clist = iter->next;
                                        }
                                } else {
                                        iter->corres = NULL;
                                }
                                
                                return 1;
                        }
                        
                        prev = iter;
                        iter = iter->next;
                }
        } else {
                wtf(0, "Removing correspondent by identifier from null list", 0);
                
                return -1;
        }
        
        return 0;
}

/**
 * Removes the correspondent with the matching IP address. This function can match
 * both private & public addresses.
 * @return 1 if the correspondent was removed, 0 if it was not found,
 * or -1 if any errors were encountered.
 */
int remove_corres_iaddr(const struct sockaddr_in *addr, struct pmppcorreslist_t **clist)
{
        if ( clist &&
            *clist ) {
                // Search if the correspondent exists.
                struct pmppcorreslist_t *iter = *clist;
                struct pmppcorreslist_t *prev = *clist;
                
                while ( iter ) {
                        if ( (sock_addr_cmp_addr(&iter->corres->paddr, addr) == 0 && sock_addr_cmp_port(&iter->corres->paddr, addr) == 0) ||
                             (sock_addr_cmp_addr(&iter->corres->laddr, addr) == 0 && sock_addr_cmp_port(&iter->corres->laddr, addr) == 0) ) {
                                // Chain the previous item to the next one in line (if one exists).
                                if ( iter->next )
                                        prev->next = iter->next;
                                else
                                        prev->next = NULL;
                                
                                if ( iter == prev ) {
                                        /*
                                         * If we're removing the 1st item & the list still has
                                         * more items, we need to advance the list pointer forward.
                                         */
                                        if ( !prev->next ) {
                                                (*clist)->corres = NULL;
                                                
                                                free(*clist);
                                                
                                                *clist = NULL;
                                                clist = NULL;
                                        } else {
                                                *clist = iter->next;
                                        }
                                } else {
                                        iter->corres = NULL;
                                }
                                
                                return 1;
                        }
                        
                        prev = iter;
                        iter = iter->next;
                }
        } else {
                wtf(0, "Removing correspondent by address from null list", 0);
                
                return -1;
        }
        
        return 0;
}

/**
 * Removes the given message from the given message list, if it
 * exists.
 * @return 1 if the message was removed, 0 if it was not found,
 * or -1 if any errors were encountered.
 */
int remove_msg(const struct pmppmsg_t *m, struct pmppmsglist_t **mlist)
{
        while ( pthread_mutex_trylock(&mutex_util) != 0 ); // Wait to obtain a lock.
        
        if ( !m ) {
                wtf(0, "Removing null message from list", 0);
                pthread_mutex_unlock(&mutex_util);
                
                return -1;
        }
        
        if ( !m->m_hash ) {
                wtf(0, "Removing message with null hash from list", 0);
                pthread_mutex_unlock(&mutex_util);
                
                return -1;
        }
        
        if ( !mlist ||
            !*mlist ) {
                wtf(0, "Removing message from null list", 0);
                pthread_mutex_unlock(&mutex_util);
                
                return -1;
        }
        
        // Search if the message exists.
        struct pmppmsglist_t *iter = *mlist;
        struct pmppmsglist_t *prev = *mlist;
        
        while ( iter ) {
                if ( iter->msg ) {
                        if ( strcmp(m->m_hash, iter->msg->m_hash) == 0 ) {
                                char *m_id = get_uuid(PMPP_E_MESSAGE, m->plist);
                                
                                // Chain the previous item to the next one in line (if one exists).
                                if ( iter->next )
                                        prev->next = iter->next;
                                else
                                        prev->next = NULL;
                                
                                if ( iter == prev ) {
                                        /*
                                         * If we're removing the 1st item & the list still has
                                         * more items, we need to advance the list pointer forward.
                                         */
                                        if ( !prev->next ) {
                                                if ( *mlist ) {
                                                        (*mlist)->msg = NULL;
                                                        
                                                        free(*mlist);
                                                        
                                                        *mlist = NULL;
                                                        mlist = NULL;
                                                }
                                        } else {
                                                *mlist = iter->next;
                                        }
                                } else if ( iter ) {
                                        iter->msg = NULL;
                                }
                                
                                erase_msg(m_id);
                                pthread_mutex_unlock(&mutex_util);
                                
                                return 1;
                        }
                }
                
                prev = iter;
                iter = iter->next;
        }
        
        pthread_mutex_unlock(&mutex_util);
        
        return 0;
}

/**
 * Removes the property with the given label & domain from the given
 * property list, if they exist. If the domain is 0, any properties with matching
 * the given label will be removed.
 * @return 1 if the property was removed, 0 if it was not found,
 * or -1 if any errors were encountered.
 */
int remove_prop(const enum pmpplabel_t label, int domain, struct pmppproplist_t **plist)
{
        if ( plist &&
            *plist ) {
                // Search if the property exists.
                struct pmppproplist_t *iter = *plist;
                struct pmppproplist_t *prev = *plist;
                
                while ( iter ) {
                        if ( (domain == 0 && iter->prop->label == label) ||
                             (iter->prop->label == label && iter->prop->domain == domain) ) {
                                // Chain the previous item to the next one in line (if one exists).
                                if ( iter->next )
                                        prev->next = iter->next;
                                else
                                        prev->next = NULL;
                                
                                if ( iter == prev ) {
                                        /*
                                         * If we're removing the 1st item & the list still has
                                         * more items, we need to advance the list pointer forward.
                                         */
                                        if ( !prev->next ) {
                                                (*plist)->prop = NULL;
                                                
                                                free(*plist);
                                                
                                                *plist = NULL;
                                                plist = NULL;
                                        } else {
                                                *plist = iter->next;
                                        }
                                } else {
                                        iter->prop = NULL;
                                }
                                
                                return 1;
                        }
                        
                        prev = iter;
                        iter = iter->next;
                }
        } else {
                wtf(0, "Removing property from null list", 0);
                
                return -1;
        }
        
        return 0;
}

/**
 * A property will overwrite a previous property that has the same
 * label & domain. Assign your own domain, or use 0 to assign a domain
 * that is unused in the list.
 */
int set_prop(struct pmppprop_t *property, struct pmppproplist_t **plist)
{
        if ( property &&
             plist ) {
                if ( !*plist ) {
                        *plist = malloc(sizeof(*plist));
                        
                        if ( *plist ) {
                                if ( property->domain == 0 )
                                        property->domain = 1; // Since the list is empty, just use 1.
                                
                                (*plist)->next = NULL;
                                (*plist)->prop = property;
                        } else {
                                return -1;
                        }
                } else {
                        // Search if the property already exists.
                        struct pmppproplist_t *iter = *plist;
                        unsigned int unused_dom = 1;
                        
                        while ( iter->next ) {
                                if ( iter->prop->label == property->label &&
                                     iter->prop->domain == property->domain ) { // Overwrite the property.
                                        iter->prop = property;
                                        
                                        return 0;
                                }
                                
                                // Keep track of an unused domain in case we need one later.
                                if ( iter->prop->domain >= unused_dom )
                                        unused_dom = iter->prop->domain + 1;
                                
                                iter = iter->next;
                        }
                        
                        // This block checks the final item (skipped by the while loop).
                        if ( iter->prop->label == property->label &&
                             iter->prop->domain == property->domain ) {
                                iter->prop = property;
                                
                                return 0;
                        }
                        
                        if ( iter->prop->domain >= unused_dom )
                                unused_dom = iter->prop->domain + 1;
                        
                        // At this point, it means we have to create a new property item.
                        iter->next = malloc(sizeof(*plist));
                        iter = iter->next;
                        
                        if ( !iter )
                                return -1;
                        
                        if ( property->domain == 0 )
                                property->domain = unused_dom;
                        
                        iter->prop = property;
                        iter->next = NULL;
                }
                
                return 0;
        } else {
                wtf(0, "setting null property", 0);
        }
        
        return -1;
}

/**
 * Finds the public IP address referenced in the
 * given message & sets it as local's public address.
 * @return 0 if the address was set successfully, -1 otherwise.
 */
int util_parse_paddr(const struct pmppmsg_t *m)
{
        if ( m ) {
                char *local_id = get_uuid(PMPP_E_SERVER, local->plist);
                unsigned int dom = domain(PMPP_L_UUID, local_id, m->plist);
                struct pmppproplist_t *p_paddr = proplist(PMPP_L_INET_PADDR, dom, m->plist);
                struct pmppproplist_t *p_pport = proplist(PMPP_L_INET_PPORT, dom, m->plist);
                
                if ( p_paddr &&
                     p_pport ) {
                        if ( net_valid_ip(p_paddr->prop->val) != 1 ) {
                                wtf(0, "parsed an invalid public IP address", 0);
                                
                                return -1;
                        }
                        
                        struct sockaddr_in addr = make_iaddr(p_paddr->prop->val, atoi(p_pport->prop->val));
                        
                        /*
                         * Special check required:
                         * Only set as a public address if it's not identical to
                         * the private one! Servers on local's LAN will report its
                         * own private address as the one visible to them.
                         */
                        if ( sock_addr_cmp_addr(&addr, &local->laddr) != 0 ) {
                                if ( sock_addr_cmp_addr(&addr, &local->paddr) != 0 ) { // Public address changed?
                                        char *paddr = net_ntoa(addr.sin_addr);
                                        unsigned int pport = net_ntohs(addr);
                                        
                                        local->paddr = addr;
                                        
                                        set_paddr(paddr, pport, local);
                                        dump_corres(local);
                                        printf("Public IP address changed: %s:%d\n", paddr, pport);
                                        pmpp_notif_presence_list(local, PMPP_R_ONLINE, m->sender);
                                }
                                
                                return 0;
                        }
                }
        }
        
        return -1;
}

/**
 * The uuidcmp function compares the two supplied UUID variables to each other.
 * @return An integer less than, equal to, or greater than zero if @p uuid_str1 is
 * found, respectively, to be lexigraphically less than, equal, or greater than 
 * @p uuid_str2.
 */
int uuidcmp(const char *uuid_str1, const char *uuid_str2)
{
        if ( uuid_str1 &&
             uuid_str2 ) {
                uuid_t id1;
                uuid_t id2;
                
                uuid_parse(uuid_str1, id1);
                uuid_parse(uuid_str2, id2);
                
                return uuid_compare(id1, id2);
        }
        
        return -1;
}

/**
 * Uses zlib to compress a string. The output is not
 * null-terminated, so don't bother printf-ing it.
 */
size_t util_compress(const unsigned char *src, size_t len, unsigned char **dest)
{
        *dest = malloc(ZLIB_CHUNK);
        
        if ( dest ) {
                int ret;
                z_stream stream;
                stream.zalloc = Z_NULL;
                stream.zfree  = Z_NULL;
                stream.opaque = Z_NULL;
                stream.avail_in  = (uInt)len;
                stream.avail_out = ZLIB_CHUNK;
                stream.next_in  = (Bytef *)src;
                stream.next_out = (Bytef *)*dest;
                
                deflateInit(&stream, Z_BEST_COMPRESSION);
                ret = deflate(&stream, Z_FINISH);
                deflateEnd(&stream);
                
                //printf("Compressed size is: %lu\n", stream.total_out);
                
                return stream.total_out;
        }
        
        return -1;
}

/**
 * Uses zlib to decompress a string.
 */
size_t util_decompress(const unsigned char *src, size_t len, unsigned char **dest)
{
        *dest = malloc(ZLIB_CHUNK);
        
        if ( dest ) {
                int ret;
                z_stream stream;
                stream.zalloc = Z_NULL;
                stream.zfree  = Z_NULL;
                stream.opaque = Z_NULL;
                stream.avail_in  = (uInt)len;
                stream.avail_out = ZLIB_CHUNK;
                stream.next_in  = (Bytef *)src;
                stream.next_out = (Bytef *)*dest;
                
                inflateInit(&stream);
                ret = inflate(&stream, Z_NO_FLUSH);
                inflateEnd(&stream);
                
                //printf("Uncompressed size is: %lu\n", stream.total_out);
                //printf("Uncompressed string is: %s\n", *dest);
                
                return stream.total_out;
        }
        
        return -1;
}

/**
 * @return The correspondent with the given UUID.
 */
struct pmppcorres_t *corres(const char *c_id, const enum pmppentity_t type, struct pmppcorreslist_t *clist)
{
        if ( clist &&
             c_id ) {
                // Search if the correspondent exists.
                struct pmppcorreslist_t *iter = clist;
                
                while ( iter ) {
                        char *iter_id = get_uuid(type, iter->corres->plist);
                        
                        if ( iter_id &&
                             uuidcmp(iter_id, c_id) == 0 )
                                return iter->corres;
                        
                        iter = iter->next;
                }
        }
        
        return NULL;
}

struct pmppcorres_t *fetch_corres(const char *c_id, const int resident)
{
        struct pmppcorres_t *c = NULL;
        
        if ( c_id &&
             strlen(c_id) > 0 ) {
                char *clist = NULL;
                char *mlist = NULL;
                char *plist = NULL;
                
                io_fetch(c_id, &clist, 'c');
                io_fetch(c_id, &mlist, 'm');
                io_fetch(c_id, &plist, 'p');
                
                c = util_atoc(clist, mlist, plist, resident);
                
                if ( c ) {
                        c->verified = 1; // Correspondents previously saved to the disk are always verified.
                        
                        enum pmppentity_t c_type = PMPP_E_ANY;
                        struct pmppproplist_t *p_type = proplist(PMPP_L_UUIDTYPE, 0, c->plist);
                        
                        // Check if this is a rendesvouz server.
                        if ( p_type )
                                c_type = atoi(p_type->prop->val);
                        
                        if ( c_type == PMPP_E_RVP )
                                c->rvp = 1;
                        
                        // Get their IP address info & make sockets out of them.
                        struct pmppproplist_t *p_laddr = proplist(PMPP_L_INET_LADDR, 0, c->plist);
                        struct pmppproplist_t *p_lport = proplist(PMPP_L_INET_LPORT, 0, c->plist);
                        struct pmppproplist_t *p_paddr = proplist(PMPP_L_INET_PADDR, 0, c->plist);
                        struct pmppproplist_t *p_pport = proplist(PMPP_L_INET_PPORT, 0, c->plist);
                        
                        if ( p_laddr &&
                             p_lport )
                                c->laddr = make_iaddr(p_laddr->prop->val, atoi(p_lport->prop->val));
                        
                        if ( p_paddr &&
                             p_pport )
                                c->paddr = make_iaddr(p_paddr->prop->val, atoi(p_pport->prop->val));
                        
                        // Messages in the mlist need their recipient to be set.
                        struct pmppmsglist_t *iter_m = c->mlist;
                        
                        while ( iter_m ) {
                                iter_m->msg->recipient = c;
                                iter_m = iter_m->next;
                        }
                }
        }
        
        return c;
}

/**
 * Finds & returns the correspondent with the matching IP address.
 */
struct pmppcorres_t *iaddr_corres(const struct sockaddr_in *addr, const struct pmppcorreslist_t *clist)
{
        struct pmppcorreslist_t *iter = (struct pmppcorreslist_t *)clist;
        
        while ( iter ) {
                if ( (sock_addr_cmp_addr(&iter->corres->paddr, addr) == 0 && sock_addr_cmp_port(&iter->corres->paddr, addr) == 0) ||
                     (sock_addr_cmp_addr(&iter->corres->laddr, addr) == 0 && sock_addr_cmp_port(&iter->corres->laddr, addr) == 0) )
                        return iter->corres;
                
                iter = iter->next;
        }
        
        return NULL;
}

struct pmppcorres_t *make_corres(void)
{
        // Inits & returns a fresh correspondent.
        struct pmppcorres_t *c = malloc(sizeof(*c));
        
        if ( c ) {
                c->clist        = NULL;
                c->mlist        = NULL;
                c->plist        = NULL;
                c->reachability = PMPP_R_OFFLINE;
                c->probe        = 0;
                c->rvp          = 0;
                c->verified     = 0;
        }
        
        return c;
}

/**
 * Constructs a correspondent struct out of the given ASCII components.
 */
struct pmppcorres_t *util_atoc(const char *clist, const char *mlist, const char *plist, const int resident)
{
        struct pmppcorres_t *c = NULL;
        
        if ( plist ) { // There needs to be a plist at the bare minimum.
                c = make_corres();
                
                if ( c ) {
                        deserializep(plist, NULL, NULL, 0, &c->plist, NULL);
                        
                        if ( resident )
                                deserializec(clist, &c->clist);
                        
                        char *iv  = NULL;
                        char *key = NULL;
                        struct pmppproplist_t *p_key = proplist(PMPP_L_CRYPTO_KEY, 0, c->plist);
                        struct pmppproplist_t *p_iv  = proplist(PMPP_L_CRYPTO_IV, 0, c->plist);
                        
                        if ( p_iv )
                                iv = p_iv->prop->val;
                        
                        if ( p_key )
                                key = p_key->prop->val;
                        
                        deserializem(mlist, key, iv, &c->mlist);
                }
        }
        
        return c;
}

struct pmppmsg_t *fetch_msg(const char *m_id, const char *key, const char *iv)
{
        struct pmppmsg_t *m = NULL;
        
        if ( m_id &&
             strlen(m_id) > 0 ) {
                char *plist = NULL;
                
                io_fetch(m_id, &plist, 'p');
                
                if ( plist ) {
                        m = util_atom(plist, key, iv, 0);
                        m->pkg = plist;
                }
        }
        
        return m;
}

/**
 * Creates a new message struct.
 */
struct pmppmsg_t *make_msg(void)
{
        struct pmppmsg_t *m = malloc(sizeof(*m));
        
        if ( m ) {
                m->attempts  = 0;
                m->critical  = 0;
                m->m_hash    = NULL;
                m->pkg       = NULL;
                m->plist     = NULL;
                m->recipient = NULL;
                m->sender    = NULL;
        }
        
        return m;
}

/**
 * @return The message with the given UUID.
 */
struct pmppmsg_t *msg(const char *msg_hash, struct pmppmsglist_t *mlist)
{
        while ( pthread_mutex_trylock(&mutex_util) != 0 ); // Wait to obtain a lock.
        
        if ( mlist ) {
                // Search if the message exists.
                struct pmppmsglist_t *iter = mlist;
                
                while ( iter ) {
                        if ( iter->msg &&
                             iter->msg->m_hash &&
                             strlen(iter->msg->m_hash) > 0 )
                                if ( strcmp(msg_hash, iter->msg->m_hash) == 0 ) {
                                        pthread_mutex_unlock(&mutex_util);
                                        
                                        return iter->msg;
                                }
                        
                        iter = iter->next;
                }
        }
        
        pthread_mutex_unlock(&mutex_util);
        
        return NULL;
}

/**
 * Converts an ASCII string into a message struct.
 * @param ee Whether encryption should be enforced or not.
 */
struct pmppmsg_t *util_atom(const char *plist, const char *key, const char *iv, const int ee)
{
        struct pmppmsg_t *m = NULL;
        
        if ( plist ) {
                m = make_msg();
                
                if ( m ) {
                        m->pkg = strdup(plist);
                        
                        sha(m->pkg, &m->m_hash); // Save a hash of the original message.
                        deserializep(m->pkg, key, iv, ee, &m->plist, &m->cipherblock);
                }
        }
        
        return m;
}

/**
 * Makes a copy of the given property.
 * @return The copy.
 */
struct pmppprop_t *clonep(const struct pmppprop_t *property)
{
        struct pmppprop_t *p = NULL;
        
        if ( property )
                p = make_prop(property->label, strdup(property->val), property->secure, property->domain);
        
        return p;
}

struct pmppprop_t *get_uuidp(const enum pmppentity_t type, struct pmppproplist_t *list)
{
        struct pmppproplist_t *p_id_types = proplist(PMPP_L_UUIDTYPE, 0, list);
        unsigned int dom = domain(PMPP_L_UUIDTYPE, util_itoa(type), p_id_types);
        struct pmppprop_t *p_id = NULL;
        
        if ( dom > 0 ) {
                p_id = prop(PMPP_L_UUID, dom, list);
        }
        
        return p_id;
}

struct pmppprop_t *make_prop(const enum pmpplabel_t label, char *val, int secure, int domain)
{
        struct pmppprop_t *p = NULL;
        
        if ( val ) {
                p = malloc(sizeof(*p));
                
                if ( p ) {
                        p->domain = domain;
                        p->label  = label;
                        p->secure = secure;
                        p->val    = strdup(val);
                }
        } else {
                printf("Warning: assigning null value to property\n");
        }
        
        return p;
}

/**
 * The 0 wildcard will not work with this function. It expects both a label & a domain.
 * @return The property with the given label.
 */
struct pmppprop_t *prop(const enum pmpplabel_t label, int domain, struct pmppproplist_t *plist)
{
        if ( plist ) {
                // Search if the property exists.
                struct pmppproplist_t *iter = plist;
                
                while ( iter ) {
                        if ( iter->prop ) {
                                if ( iter->prop->label == label &&
                                     iter->prop->domain == domain )
                                        return iter->prop;
                        }
                        
                        iter = iter->next;
                }
        } else {
                wtf(0, "Accessing property from null list", 0);
        }
        
        return NULL;
}

/**
 * Converts an ASCII string into a property struct.
 */
struct pmppprop_t *util_atop(const char *p, int secure)
{
        struct pmppprop_t *prop = NULL;
        unsigned int domain = -1;
        
        if ( p &&
            strlen(p) > 0 ) {
                // Processing order matters here!
                char *tmp = strdup(p);
                domain = atoi(strsep(&tmp, ":")); // Extract the domain.
                
                if ( domain > 0 ) {
                        char *label_test = strsep(&tmp, ">");
                        
                        if ( label_test ) {
                                enum pmpplabel_t label = atoi(label_test); // Once the label is extracted, tmp will contain the value.
                                
                                if ( tmp )
                                        prop = make_prop(label, tmp, secure, domain);
                        }
                }
        }
        
        return prop;
}

struct pmppproplist_t *cloneplist(const struct pmppproplist_t *plist)
{
        struct pmppproplist_t *list = NULL;
        
        if ( plist ) {
                struct pmppproplist_t *iter = (struct pmppproplist_t *)plist;
                
                while ( iter ) {
                        if ( iter->prop )
                                set_prop(clonep(iter->prop), &list);
                        
                        iter = iter->next;
                }
        }
        
        return list;
}

struct pmppproplist_t *proplist(const enum pmpplabel_t label, int domain, const struct pmppproplist_t *list)
{
        if ( list ) {
                struct pmppproplist_t *results = NULL;
                struct pmppproplist_t *iter    = (struct pmppproplist_t *)list;
                
                while ( iter ) {
                        if ( iter->prop ) {
                                if ( label != PMPP_L_UNKNOWN ) {
                                        if ( domain != 0 ) {
                                                if ( iter->prop->label == label &&
                                                     iter->prop->domain == domain )
                                                        set_prop(iter->prop, &results);
                                        } else {
                                                if ( iter->prop->label == label )
                                                        set_prop(iter->prop, &results);
                                        }
                                } else {
                                        if ( domain != 0 ) {
                                                if ( iter->prop->domain == domain )
                                                        set_prop(iter->prop, &results);
                                        } else { // This case will match any property.
                                                set_prop(iter->prop, &results);
                                        }
                                }
                        }
                        
                        iter = iter->next;
                }
                
                return results;
        }
        
        return NULL;
}

/**
 * Parses the time represented by a Unix timestamp.
 */
time_t parse_time(const char *tstr)
{
        struct tm time;
        
        strptime(tstr, TIMESTAMP_FORM, &time);
        
        time_t t = timegm(&time);
        
        return t;
}

/**
 * Reverse-lookup a domain based on a property's label & value.
 * @return The domain of the property, or 0 if it does not exist.
 */
unsigned int domain(const enum pmpplabel_t label, const char *val, struct pmppproplist_t *plist)
{
        if ( val &&
             plist ) {
                struct pmppproplist_t *iter = plist;
                
                while ( iter ) {
                        if ( iter->prop->label == label &&
                             strcmp(iter->prop->val, val) == 0 )
                                return iter->prop->domain;
                        
                        iter = iter->next;
                }
        }
        
        return 0;
}

/**
 * Analyzes & creates links between the correspondents in the
 * given list.
 */
void clink(struct pmppcorreslist_t *clist)
{
        struct pmppcorreslist_t *iter_1 = clist;
        
        while ( iter_1 ) {
                char *iter_1_id = get_uuid(PMPP_E_SERVER, iter_1->corres->plist);
                
                if ( !iter_1_id )
                        iter_1_id = get_uuid(PMPP_E_SERVICE, iter_1->corres->plist);
                
                if ( !iter_1_id )
                        iter_1_id = get_uuid(PMPP_E_RVP, iter_1->corres->plist);
                
                if ( iter_1_id ) {
                        char *tmp_c = NULL;
                        
                        io_fetch(iter_1_id, &tmp_c, 'c');
                        
                        if ( tmp_c &&
                             strlen(tmp_c) > 0 ) {
                                char *tmp  = strdup(tmp_c);
                                char *c_id = NULL;
                                
                                while ( tmp ) {
                                        c_id = strsep(&tmp, PMPP_PROP_DELIMETER);
                                        
                                        // Now, we loop again to find the referenced correspondent & save a pointer to them.
                                        struct pmppcorreslist_t *iter_2 = clist;
                                        
                                        while ( iter_2 ) {
                                                enum pmppentity_t iter_2_type = PMPP_E_SERVER;
                                                char *iter_2_id = get_uuid(iter_2_type, iter_2->corres->plist);
                                                
                                                if ( !iter_2_id ) {
                                                        iter_2_type = PMPP_E_SERVICE;
                                                        iter_2_id = get_uuid(iter_2_type, iter_2->corres->plist);
                                                }
                                                
                                                if ( !iter_2_id ) {
                                                        iter_2_type = PMPP_E_RVP;
                                                        iter_2_id = get_uuid(iter_2_type, iter_2->corres->plist);
                                                }
                                                
                                                if ( uuidcmp(c_id, iter_2_id) == 0) {
                                                        add_corres(iter_2->corres, iter_2_type, &iter_1->corres->clist);
                                                        
                                                        break;
                                                }
                                                
                                                iter_2 = iter_2->next;
                                        }
                                }
                        }
                }
                
                iter_1 = iter_1->next;
        }
}

void deserializec(const char *clist, struct pmppcorreslist_t **holder)
{
        if ( clist &&
             holder &&
             strlen(clist) > 0 ) {
                char *tmp  = strdup(clist);
                
                while ( tmp ) {
                        /*
                         * e_id contains the identifier of a correspondent. We have to
                         * fetch its property & message lists from the disk.
                         */
                        char *e_id = strsep(&tmp, PMPP_PROP_DELIMETER);
                        struct pmppcorres_t *c = fetch_corres(e_id, 0);
                        
                        if ( c ) {
                                enum pmppentity_t type = PMPP_E_SERVER;
                                char *c_id = get_uuid(type, c->plist);
                                
                                if ( !c_id ) {
                                        type = PMPP_E_SERVICE;
                                        c_id = get_uuid(type, c->plist);
                                }
                                
                                if ( !c_id ) {
                                        type = PMPP_E_RVP;
                                        c_id = get_uuid(type, c->plist);
                                }
                                
                                add_corres(c, type, holder);
                        }
                }
                
                if ( tmp ) {
                        free(tmp);
                        
                        tmp = NULL;
                }
        }
}

void deserializem(const char *mlist, const char *key, const char *iv, struct pmppmsglist_t **holder)
{
        if ( mlist &&
             holder &&
             strlen(mlist) > 0 ) {
                char *tmp = strdup(mlist);
                
                while ( tmp ) {
                        /*
                         * m_id contains the identifier of a message. We have to
                         * fetch its property list from the disk.
                         */
                        char *m_id = strsep(&tmp, PMPP_PROP_DELIMETER);
                        struct pmppmsg_t *m = fetch_msg(m_id, key, iv);
                        
                        add_msg(m, holder);
                }
                
                if ( tmp ) {
                        free(tmp);
                        
                        tmp = NULL;
                }
        }
}

/**
 * @param ee Whether encryption should be enforced or not.
 */
void deserializep(const char *plist, const char *key, const char *iv, const int ee, struct pmppproplist_t **holder, char **cipherblock)
{
        if ( plist &&
             holder &&
             strlen(plist) > 0 ) {
                char *tmp            = strdup(plist);
                size_t encoded_len = 0;
                
                while ( tmp ) {
                        /*
                         * p contains the property. We have to split it
                         * into a label & a value.
                         */
                        char *p = strsep(&tmp, PMPP_PROP_DELIMETER);
                        size_t plen = strlen(p);
                        
                        if ( p &&
                             plen > 2 ) {
                                if ( p[0] == '#' &&
                                     p[1] == '!' ) { // This is an encrypted block.
                                        *cipherblock = calloc(1, plen - 2 + 1); // +1 for '\0'.
                                        
                                        memcpy(*cipherblock, &p[2], plen - 2);
                                        
                                        /*
                                         * We leave the encrypted block aside till we're done.
                                         * with the rest of the list because we need the property
                                         * holding the compressed data size.
                                         */
                                } else {
                                        struct pmppprop_t *prop = util_atop(p, 0);
                                        
                                        if ( prop ) {
                                                if ( prop->label == PMPP_L_ENCODE_SIZE )
                                                        encoded_len = atoi(prop->val);
                                                
                                                set_prop(prop, holder);
                                        }
                                }
                        }
                }
                
                // Finish off the encrypted block (if we have one).
                if ( cipherblock &&
                    *cipherblock &&
                     encoded_len != 0 &&
                     iv &&
                     key ) {
                        char *plaintext = NULL;
                        unsigned char *b64          = NULL;
                        unsigned char *decompressed = NULL;
                        size_t b64_len = base64_decode(*cipherblock, encoded_len, &b64);        // Decode.
                        size_t decompressed_len = util_decompress(b64, b64_len, &decompressed); // Decompress.
                        
                        aes_decrypt(decompressed, decompressed_len, key, iv, &plaintext);       // Decrypt.
                        
                        if ( plaintext ) {
                                // The block might be a property list as well.
                                tmp = strdup(plaintext);
                                
                                while ( tmp ) {
                                        char *p = strsep(&tmp, PMPP_PROP_DELIMETER);
                                        size_t plen = strlen(p);
                                        
                                        if ( p &&
                                             plen > 2 ) {
                                                struct pmppprop_t *prop = util_atop(p, 1);
                                                
                                                set_prop(prop, holder);
                                        }
                                }
                        }
                }
                
                if ( tmp ) {
                        free(tmp);
                        
                        tmp = NULL;
                }
                
                if ( ee &&
                     (!*cipherblock || !iv || !key) )
                        *holder = NULL;
        }
}

/**
 * Prepends the string @p t to the string @p s.
 */
void prepend(char *s, const char *t)
{
        /*
         * Assumes s has enough space allocated
         * for the combined string.
         */
        size_t len = strlen(t);
        
        memmove(s + len, s, strlen(s) + 1);
        
        for ( size_t i = 0; i < len; ++i )
                s[i] = t[i];
}

/**
 * Breaks a correspondent into its ASCII string components. Secure properties within the
 * components are encrypted using the key & IV in the correspondent's property list.
 */
void util_ctoa(const struct pmppcorres_t *c, char **clist, char **mlist, char **plist)
{
        if ( c ) {
                char *iv  = NULL;
                char *key = NULL;
                struct pmppproplist_t *p_iv  = proplist(PMPP_L_CRYPTO_IV, 0, c->plist);
                struct pmppproplist_t *p_key = proplist(PMPP_L_CRYPTO_KEY, 0, c->plist);
                
                if ( p_iv )
                        iv = p_iv->prop->val;
                
                if ( p_key )
                        key = p_key->prop->val;
                
                *clist = serializec(c->clist);
                *mlist = serializem(c->mlist, key, iv);
                *plist = serializep(c->plist, NULL, NULL);
        } else {
                wtf(0, "serializing null correspondent", 0);
        }
}

/**
 * Use this function to print errors instead of plain perror.
 */
void wtf(int errcode, const char *message, int kill)
{
        char *error = NULL;
        
        if ( errcode != 0 )
        {
                size_t needed = snprintf(NULL, 0, "✘ Error %d: %s\n", errcode, message) + 1; // +1 for '\0'.
                error = malloc(needed);
                
                if ( error )
                        sprintf(error, "✘ Error %d: %s\n", errcode, message);
        } else {
                size_t needed = snprintf(NULL, 0, "✘ Error: %s\n", message) + 1; // +1 for '\0'.
                error = malloc(needed);
                
                if ( error )
                        sprintf(error, "✘ Error: %s\n", message);
        }
        
        if ( error ) {
                perror(error);
                free(error);
                
                error = NULL;
        }
        
        if ( kill )
                abort();
}

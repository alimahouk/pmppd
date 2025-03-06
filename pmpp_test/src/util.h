//
//  util.h
//  pmppd
//
//  Created on 3/5/16.
//
//

#ifndef util_h
#define util_h

#include "pmpptypes.h"

char *get_uuid(const enum pmppentity_t type, struct pmppproplist_t *list);
char *serializec(const struct pmppcorreslist_t *clist);
char *serializem(const struct pmppmsglist_t *mlist, const char *key, const char *iv);
char *serializep(const struct pmppproplist_t *plist, const char *key, const char *iv);
char *timestamp(void);
char *util_ftoa(const float f);
char *util_itoa(const int i);
char *util_mtoa(const struct pmppmsg_t *m, const char *key, const char *iv);
char *util_ptoa(const struct pmppprop_t *property);
char *uuid(void);

int add_corres(struct pmppcorres_t *c, enum pmppentity_t type, struct pmppcorreslist_t **clist);
int add_msg(struct pmppmsg_t *m, struct pmppmsglist_t **mlist);
int criticality(const struct pmppmsg_t *m);
int dump_clist(const struct pmppcorreslist_t *list);
int dump_corres(const struct pmppcorres_t *c);
int dump_msg(const struct pmppmsg_t *m, const char *key, const char *iv);
int erase_corres(const char *c_id);
int erase_msg(const char *m_id);
int has_prefix(const char *str, const char *pre);
int is_uuid(char *str);
int remove_corres(const char *c_id, enum pmppentity_t type, struct pmppcorreslist_t **clist);
int remove_corres_iaddr(const struct sockaddr_in *addr, struct pmppcorreslist_t **clist);
int remove_msg(const struct pmppmsg_t *msg, struct pmppmsglist_t **mlist);
int remove_prop(const enum pmpplabel_t label, int domain, struct pmppproplist_t **plist);
int set_prop(struct pmppprop_t *property, struct pmppproplist_t **plist);
int uuidcmp(const char *uuid_str1, const char *uuid_str2);

size_t util_compress(const unsigned char *src, size_t len, unsigned char **dest);
size_t util_decompress(const unsigned char *src, size_t len, unsigned char **dest);

struct pmppcorres_t   *corres(const char *c_id, const enum pmppentity_t type, struct pmppcorreslist_t *clist);
struct pmppcorres_t   *fetch_corres(const char *c_id, const int resident);
struct pmppcorres_t   *iaddr_corres(const struct sockaddr_in *addr, const struct pmppcorreslist_t *clist);
struct pmppcorres_t   *make_corres(void);
struct pmppcorres_t   *util_atoc(const char *clist, const char *mlist, const char *plist, const int resident);
struct pmppmsg_t      *fetch_msg(const char *msg_id, const char *key, const char *iv);
struct pmppmsg_t      *make_msg(void);
struct pmppmsg_t      *msg(const char *msg_hash, struct pmppmsglist_t *mlist);
struct pmppmsg_t      *util_atom(const char *plist, const char *key, const char *iv, const int ee);
struct pmppprop_t     *clonep(const struct pmppprop_t *property);
struct pmppprop_t     *get_uuidp(const enum pmppentity_t type, struct pmppproplist_t *list);
struct pmppprop_t     *make_prop(const enum pmpplabel_t label, char *value, int secure, int domain);
struct pmppprop_t     *prop(const enum pmpplabel_t label, int domain, struct pmppproplist_t *plist);
struct pmppprop_t     *util_atop(const char *a, int secure);
struct pmppproplist_t *cloneplist(const struct pmppproplist_t *plist);
struct pmppproplist_t *proplist(const enum pmpplabel_t label, int domain, const struct pmppproplist_t *list);

time_t parse_time(const char *tstr);

unsigned int domain(const enum pmpplabel_t label, const char *val, struct pmppproplist_t *plist);

void clink(struct pmppcorreslist_t *clist);
void deserializec(const char *clist, struct pmppcorreslist_t **holder);
void deserializem(const char *mlist, const char *key, const char *iv, struct pmppmsglist_t **holder);
void deserializep(const char *plist, const char *key, const char *iv, const int ee, struct pmppproplist_t **holder, char **cipherblock);
void prepend(char *s, const char *t);
void util_ctoa(const struct pmppcorres_t *c, char **clist, char **mlist, char **plist);
void wtf(int errcode, const char *message, int kill);

#endif /* util_h */

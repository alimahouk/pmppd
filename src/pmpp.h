//
//  pmpp.h
//  pmppd
//
//  Created on 3/29/16.
//
//

#ifndef pmpp_h
#define pmpp_h

#include "crypto.h"
#include "pmpptypes.h"

int pmpp_dead(struct pmppmsg_t **m);
int pmpp_parse_greet(const struct pmppmsg_t *m, char **key, char **iv, EVP_PKEY **pkey);
int pmpp_parse_hand_ext(const struct pmppmsg_t *m);
int pmpp_parse_hand_shake(const struct pmppmsg_t *m, const char *recipient_id, const enum pmppentity_t recipient_type, char *key, char *iv);
int pmpp_parse_msg_stat(const struct pmppmsg_t *m);
int pmpp_parse_presence(const struct pmppmsg_t *m);
int pmpp_parse_probe(const struct pmppmsg_t *m);
int pmpp_parse_probe_res(const struct pmppmsg_t *m);
int pmpp_parse_reg_req(const struct pmppmsg_t *m);
int pmpp_parse_rvp(const struct pmppmsg_t *m);
int pmpp_parse_sleep(const struct pmppmsg_t *m);
int pmpp_process_fwd(struct pmppmsg_t *m);
int pmpp_process_pmppmsg(struct pmppmsg_t **new_msg);
int pmpp_safekeep(const struct pmppmsg_t *m);

void pmpp_ack_msg(const struct pmppmsg_t *m, const char *sender_id, const enum pmppentity_t sender_type);
void pmpp_broadcast(struct pmppproplist_t *content, const struct pmppcorreslist_t *list, const struct pmppcorres_t *exclude, int ack, enum pmppentity_t type, enum pmppreach_t reachability);
void pmpp_bye(const struct pmppcorres_t *c);
void pmpp_connected(struct pmppcorres_t *c);
void pmpp_delivery_receipt(const struct pmppmsg_t *m);
void pmpp_dist_outbox(const struct pmppcorres_t *c);
void pmpp_dist_outboxes(void);
void pmpp_flush_outbox(const struct pmppcorres_t *c);
void pmpp_fwd_delivery_receipt(const struct pmppmsg_t *m);
void pmpp_greet(const struct pmppcorres_t *c, const char *service_id);
void pmpp_hand_ext(const struct pmppmsg_t *m, const char *recipient_id, const enum pmppentity_t recipient_type, char *key, char *iv, EVP_PKEY *pkey);
void pmpp_hand_shake(const struct pmppmsg_t *m, const char *recipient_id, const enum pmppentity_t recipient_type);
void pmpp_hand_shake_ok(const struct pmppcorres_t *c, const char *recipient_id, const enum pmppentity_t recipient_type);
void pmpp_notif_presence(const struct pmppcorres_t *recipient, const struct pmppcorres_t *c, enum pmppreach_t reachability);
void pmpp_notif_presence_list(struct pmppcorres_t *c, enum pmppreach_t reachability, struct pmppcorres_t *exclude);
void pmpp_ping(const struct pmppcorres_t *c);
void pmpp_ping_list(const struct pmppcorres_t *c);
void pmpp_process_msg(struct pmppmsg_t *m);
void pmpp_probe(struct pmppcorres_t *c);
void pmpp_req_key(const struct pmppcorres_t *c);
void pmpp_resend_msg(struct pmppmsg_t *m);
void pmpp_rvp(struct pmppcorreslist_t *clist, const struct pmppcorres_t *recipient);
void pmpp_season(struct pmppmsg_t *m);
void pmpp_send_msg(const struct pmppcorres_t *recipient, const enum pmppmessage_t type, const int need_ack, struct pmppproplist_t **content, const char *key, const char *iv);
void pmpp_sleep(void);
void pmpp_update_presence(const struct pmppcorres_t *c);

#endif /* pmpp_h */

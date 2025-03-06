//
//  pmpp.h
//  pmpp_test
//
//  Created on 3/29/16.
//
//

#ifndef pmpp_h
#define pmpp_h

#include "pmpptypes.h"

int pmpp_parse_msg_stat(const struct pmppmsg_t *m);
int pmpp_parse_presence(const struct pmppmsg_t *m);
int pmpp_process_pmppmsg(struct pmppmsg_t **new_msg);

void pmpp_ack_msg(const struct pmppmsg_t *m);
void pmpp_add_id(const char *identifier);
void pmpp_add_ip(const char *addr, unsigned int port);
void pmpp_bye(void);
void pmpp_connected(void);
void pmpp_dead(struct pmppmsg_t **m);
void pmpp_greet(void);
void pmpp_hand_shake(const struct pmppmsg_t *m);
void pmpp_parse_hand_ext(const struct pmppmsg_t *m);
void pmpp_ping_local(void);
void pmpp_resend_msg(struct pmppmsg_t *m);
void pmpp_season(struct pmppmsg_t *m);
void pmpp_send_msg(const enum pmppmessage_t type, const int need_ack, struct pmppproplist_t **content);
void pmpp_sleep(void);

#endif /* pmpp_h */

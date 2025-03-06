//
//  net.h
//  pmpp_test
//
//  Created on 3/4/16.
//
//

#ifndef net_h
#define net_h

#include <netinet/in.h>

#include "pmpptypes.h"

#define LOCALHOST       "127.0.0.1"
#define PMPP_PORT       1992

char *net_addr2ascii(int af, const void *addrp, size_t len, char *buf);
char *net_ntoa(const struct in_addr addr);

int net_ascii2addr(int af, const char *ascii, void *result);
int net_aton(const char *str, struct in_addr *addr);
int net_valid_ip(const char *addr);
int setup_sock(void);
int sock_addr_cmp_addr(const struct sockaddr_in *sa, const struct sockaddr_in *sb);
int sock_addr_cmp_port(const struct sockaddr_in *sa, const struct sockaddr_in *sb);

struct sockaddr_in make_iaddr(const char *addr, const unsigned int port);
struct sockaddr_in net_iaddr(struct pmppproplist_t *list, const int public_addr);

unsigned short net_ntohs(const struct sockaddr_in in);

void  close_sock();
void *flush_outbox();
void *read_udp();
void *send_udp(struct pmppmsg_t *m, const int need_ack);


#endif /* net_h */

//
//  net.h
//  pmppd
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
int sock_addr_cmp_addr(const struct sockaddr_in *sa, const struct sockaddr_in *sb);
int sock_addr_cmp_port(const struct sockaddr_in *sa, const struct sockaddr_in *sb);

struct sockaddr_in make_iaddr(const char *addr, const unsigned int port);
struct sockaddr_in net_iaddr(struct pmppproplist_t *list, const int public_addr);

unsigned short net_ntohs(const struct sockaddr_in in);

void *check_addrs();
void  clear_local_addr();
void  close_sock();
void *flush_outboxes();
void *get_in_addr(struct sockaddr *sa);
void *keep_alive();
void  local_addr(char *holder[]);
void *read_tcp();
void *read_udp();
void *send_udp(struct pmppmsg_t *m, const struct sockaddr_in destination, const int need_ack);
void  set_laddr(const char *addr, const unsigned int port, struct pmppcorres_t *c);
void  set_paddr(const char *addr, const unsigned int port, struct pmppcorres_t *c);
void  setup_sock(void);
void  sigchld_handler(int s);

#endif /* net_h */

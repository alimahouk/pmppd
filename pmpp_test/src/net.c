//
//  net.c
//  pmpp_test
//
//  Created on 3/4/16.
//
//

#include "net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "crypto.h"
#include "main.h"
#include "pmpp.h"
#include "util.h"

#define SOCK_ADDR_IN_PTR(sa)	((struct sockaddr_in *)(sa))
#define SOCK_ADDR_IN_ADDR(sa)	SOCK_ADDR_IN_PTR(sa)->sin_addr
#define SOCK_ADDR_IN_PORT(sa)	SOCK_ADDR_IN_PTR(sa)->sin_port
#define SOCK_ADDR_PORT(sa)	SOCK_ADDR_IN_PORT(sa))
#define UDP_BUFFER_SIZE         1500 // i.e. the MTU

// Globals
int socket_udp = 0;

/**
 * Copyright 1996 Massachusetts Institute of Technology
 */
char *net_addr2ascii(int af, const void *addrp, size_t len, char *buf)
{
        static char staticbuf[64]; // 64 for AF_LINK > 16 for AF_INET.
        
        if ( !buf )
                buf = staticbuf;
        
        switch( af ) {
                case AF_INET:
                        if ( len != sizeof(struct in_addr) ) {
                                errno = ENAMETOOLONG;
                                
                                return 0;
                        }
                        
                        strcpy(buf, inet_ntoa(*(const struct in_addr *)addrp));
                        
                        break;
                default:
                        errno = EPROTONOSUPPORT;
                        
                        return 0;
        }
        
        return buf;
}

/**
 * Returns an ASCII representation of the IP address
 * in the given socket. It is the sender's responsibility
 * to free the returned string.
 */
char *net_ntoa(const struct in_addr addr)
{
        char *strbuf = malloc(sizeof("123.123.123.123") + 1); // Long enough for IPv4 only.
        
        return net_addr2ascii(AF_INET, &addr, sizeof(addr), strbuf);
}

/**
 * Copyright 1996 Massachusetts Institute of Technology
 */
int net_ascii2addr(int af, const char *ascii, void *result)
{
        struct in_addr *ina;
        char strbuf[4 * sizeof("123")]; // long enough for IPv4 only.
        
        switch ( af ) {
                case AF_INET:
                        ina = result;
                        strbuf[0] = '\0';
                        strncat(strbuf, ascii, (sizeof strbuf) - 1);
                        
                        if ( inet_aton(strbuf, ina) )
                                return sizeof(struct in_addr);
                        
                        errno = EINVAL;
                        
                        break;
                default:
                        errno = EPROTONOSUPPORT;
                        
                        break;
        }
        
        return -1;
}

/**
 * Copies the given string into the given address field.
 */
int net_aton(const char *str, struct in_addr *addr)
{
        if ( str )
                return (net_ascii2addr(AF_INET, strdup(str), addr) == sizeof(*addr));
        
        return -1;
}

int net_valid_ip(const char *addr)
{
        struct sockaddr_in sa;
        int result = inet_pton(AF_INET, addr, &(sa.sin_addr));
        
        return result != 0;
}

int setup_sock(void)
{
        char *portString = "0";
        int ret_val = 0;
        struct addrinfo *p;
        struct addrinfo *info;
        struct addrinfo  hints;
        
        memset(&hints, 0, sizeof(hints));
        
        hints.ai_family   = PF_INET;
        hints.ai_protocol = IPPROTO_UDP;
        hints.ai_socktype = SOCK_DGRAM;
        
        if ( (ret_val = getaddrinfo(NULL, portString, &hints, &info)) != 0 ) {
                char bindError[32];
                
                sprintf(bindError, "getaddrinfo %s", gai_strerror(ret_val));
                wtf(0, bindError, 1);
        }
        
        // Loop through all the results and bind to the first we can.
        for ( p = info; p != NULL; p = p->ai_next ) {
                socket_udp = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
                
                if ( socket_udp < 0 )
                        continue;
                
                if ( bind(socket_udp, p->ai_addr, p->ai_addrlen) < 0 ) {
                        char bindError[32];
                        
                        snprintf(bindError, sizeof(bindError), "binding to UDP port %s", portString);
                        close(socket_udp);
                        wtf(0, bindError, 0);
                        
                        continue;
                }
                
                break;
        }
        
        if ( !p )
                wtf(0, "UDP listener failed to bind socket!", 1);
        
        struct sockaddr_in sin;
        socklen_t len = sizeof(sin);
        
        if ( getsockname(socket_udp, (struct sockaddr *)&sin, &len) == 0 )
                printf("✔ Opened UDP port %hu\n", ntohs(sin.sin_port));
        
        freeaddrinfo(info);
        
        return socket_udp;
}

/**
 * Compare addresses for equality.
 * @attention only supports IPv4.
 * @return 0 if the addresses are equal, -1 otherwise.
 */
int sock_addr_cmp_addr(const struct sockaddr_in *sa, const struct sockaddr_in *sb)
{
        char *addr_a = net_ntoa(sa->sin_addr);
        char *addr_b = net_ntoa(sb->sin_addr);
        int ret = -1;
        
        if ( strcmp(addr_a, addr_b) == 0 )
                ret = 0;
        
        free(addr_a);
        free(addr_b);
        
        addr_a = NULL;
        addr_b = NULL;
        
        return ret;
}


/**
 * Compare ports for equality.
 * @attention only supports IPv4.
 * @return 0 if the ports are equal, -1 otherwise.
 */
int sock_addr_cmp_port(const struct sockaddr_in *sa, const struct sockaddr_in *sb)
{
        unsigned int port_a = ntohs(sa->sin_port);
        unsigned int port_b = ntohs(sb->sin_port);
        
        if ( port_a == port_b )
                return 0;
        
        return -1;
}

struct sockaddr_in make_iaddr(const char *addr, const unsigned int port)
{
        struct sockaddr_in s;
        
        memset(&s, 0, sizeof(s));
        
        s.sin_family = AF_INET;
        s.sin_port = htons(port);
        
        if ( addr &&
             strlen(addr) > 0 ) {
                if (inet_aton(addr, &s.sin_addr) == 0)
                        fprintf(stderr, "make_iaddr: inet_aton() failed\n");
        }
        
        return s;
}

/**
 * Creates a socket address struct using info provided by the given property list.
 * @param public_addr A flag indicating whether you need the a public address. Setting
 * this to 0 will return a private address (if available).
 */
struct sockaddr_in net_iaddr(struct pmppproplist_t *list, const int public_addr)
{
        if ( public_addr ) {
                char *paddr = NULL;
                struct pmppproplist_t *p_paddr = proplist(PMPP_L_INET_PADDR, 0, list);
                struct pmppproplist_t *p_pport = proplist(PMPP_L_INET_PPORT, 0, list);
                unsigned int pport = 0;
                
                if ( p_paddr )
                        paddr = p_paddr->prop->val;
                
                if ( p_pport )
                        pport = atoi(p_pport->prop->val);
                
                return make_iaddr(paddr, pport);
        } else {
                char *laddr = NULL;
                struct pmppproplist_t *p_laddr = proplist(PMPP_L_INET_LADDR, 0, list);
                struct pmppproplist_t *p_lport = proplist(PMPP_L_INET_LPORT, 0, list);
                unsigned int lport = 0;
                
                if ( p_laddr )
                        laddr = p_laddr->prop->val;
                
                if ( p_lport )
                        lport = atoi(p_lport->prop->val);
                
                return make_iaddr(laddr, lport);
        }
}

unsigned short net_ntohs(const struct sockaddr_in in)
{
        return ntohs(in.sin_port);
}

void close_sock()
{
        close(socket_udp);
}

void *flush_outbox()
{
        struct pmppmsglist_t *iter = outbox;
        
        while ( iter ) {
                if ( iter->msg ) {
                        if ( iter->msg->attempts < PMPP_REACH_ATTEMPT_THRESHOLD ) {
                                pmpp_resend_msg(iter->msg);
                        } else if ( iter->msg->attempts == PMPP_REACH_ATTEMPT_THRESHOLD ) {
                                iter->msg->attempts++; // Increment to avoid infinitely hitting this condition.
                                
                                // This function can modify the mlist. Reset the pointer.
                                pmpp_dead(&iter->msg);
                                
                                iter = outbox;
                                
                                continue;
                        }
                }
                
                iter = iter->next;
        }
        
        return 0;
}

void *read_udp()
{
        char  buf[UDP_BUFFER_SIZE];
        char *peer_addr            = NULL;
        struct sockaddr_in peer_iaddr;
        socklen_t peer_len = sizeof(peer_iaddr);
        unsigned int peer_port = 0;
        
        while ( 1 ) {
                peer_addr = NULL;
                peer_port = 0;
                
                memset(buf, 0, sizeof(buf));
                recvfrom(socket_udp, buf, UDP_BUFFER_SIZE - 1 , 0, (struct sockaddr *)&peer_iaddr, &peer_len);
                
                peer_addr = inet_ntoa(peer_iaddr.sin_addr);
                peer_port = ntohs(peer_iaddr.sin_port);
                
                //printf("Received packet from %s:%d\n", peer_addr, peer_port);
                //printf("Data: %s\n" , buf);
                
                char *msg_str = strdup(buf);
                struct pmppmsg_t *new_msg = util_atom(msg_str, NULL, NULL, 0);
                
                if ( new_msg ) {
                        struct pmppcorres_t *sender = make_corres();
                        
                        if ( !sender ) {
                                wtf(0, "could not create new correspondent", 0);
                        } else {
                                sender->laddr = peer_iaddr;
                                new_msg->sender = sender;
                                
                                // Spawn a new thread to handle the message.
                                pthread_t t_msg_handler;
                                
                                pthread_create(&t_msg_handler, 0, recv_msg, new_msg);
                        }
                        
                } else {
                        printf("LOG: received non-PMPP message\n");
                }
                
                free(msg_str);
        }
        
        return 0;
}

void *send_udp(struct pmppmsg_t *m, const int need_ack)
{
        if ( !m )
                return 0;
        
        struct sockaddr_in destination;
        destination.sin_family = AF_INET;
        destination.sin_port = htons(PMPP_PORT);
        
        m->attempts++;
        
        if ( need_ack)
                add_msg(m, &outbox);
        
        inet_aton(LOCALHOST, &destination.sin_addr);
        sendto(socket_udp, m->pkg, strlen(m->pkg) + 1, 0, (struct sockaddr *)&destination, sizeof(destination));
        //printf("Sent (%ld) to %s:%d\n", strlen(msg->pkg) + 1, inet_ntoa(destination.sin_addr), ntohs(destination.sin_port));
        
        return 0;
}

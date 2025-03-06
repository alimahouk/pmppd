//
//  net.c
//  pmppd
//
//  Created on 3/4/16.
//
//

#include "net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "main.h"
#include "pmpp.h"
#include "util.h"

#define SOCK_ADDR_IN_PTR(sa)	((struct sockaddr_in *)(sa))
#define SOCK_ADDR_IN_ADDR(sa)	SOCK_ADDR_IN_PTR(sa)->sin_addr
#define SOCK_ADDR_IN_PORT(sa)	SOCK_ADDR_IN_PTR(sa)->sin_port
#define SOCK_ADDR_PORT(sa)	SOCK_ADDR_IN_PORT(sa))
#define TCP_BACKLOG             10
#define UDP_BUFFER_SIZE         1500 // i.e. the MTU

// Globals
int socket_tcp = 0;
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
        char *strbuf = malloc(strlen("123.123.123.123") + 1); // Long enough for IPv4 only.
        
        return net_addr2ascii(AF_INET, &addr, sizeof(addr), strbuf);
}

/**
 * Copyright 1996 Massachusetts Institute of Technology
 */
int net_ascii2addr(int af, const char *ascii, void *result)
{
        struct in_addr *ina;
        char strbuf[strlen("123.123.123.123") + 1]; // long enough for IPv4 only.
        
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

/**
 * Checks the current machine's public & private (if available) IP
 * addresses. If a discrepancy is detected between what gets returned
 * & what's currently saved, a flag is raised.
 */
void *check_addrs()
{
        char *local_addrs[] = {"", "", "", "", NULL};
        char *addr_curr     = net_ntoa(local->laddr.sin_addr);
        char *addr          = NULL;
        unsigned int lport = net_ntohs(local->laddr);
        
        // Private address check.
        local_addr(local_addrs);
        
        for ( int i = 0; i < 4 ; i++ ) {
                if ( strlen(local_addrs[i]) > 0 )
                        addr = local_addrs[i];
        }
        
        if ( net_valid_ip(addr) != 1 )
                return 0;
        
        if ( strcmp(addr_curr, "0.0.0.0") == 0 ||
             (addr && strcmp(addr, addr_curr) != 0) ) { // Private address changed.
                enum pmppreach_t reach = PMPP_R_ONLINE;
                
                if ( strcmp(addr, LOCALHOST) == 0 ) { // If our new address is the loopback, that means we're unreachable.
                        reach = PMPP_R_OFFLINE;
                        
                        clear_local_addr();
                } else {
                        set_laddr(addr, lport, local);
                }
                
                printf("Private IP address changed: %s\n", addr);
                pmpp_notif_presence_list(local, reach, NULL);
                dump_corres(local);
        } else if ( !addr ) {
                clear_local_addr();
        } else if ( strcmp(addr_curr, "0.0.0.0") != 0 ) { // Address unchanged, but reachable.
                local->reachability = PMPP_R_ONLINE;
        }
        
        net_aton(addr, &local->laddr.sin_addr);
        
        return 0;
}

void clear_local_addr()
{
        int dom_laddr = 0;
        int dom_paddr = 0;
        struct pmppproplist_t *plist_laddr = proplist(PMPP_L_INET_LADDR, 0, local->plist);
        struct pmppproplist_t *plist_paddr = proplist(PMPP_L_INET_PADDR, 0, local->plist);
        
        if ( plist_laddr )
                dom_laddr = plist_laddr->prop->domain;
        
        if ( plist_paddr )
                dom_paddr = plist_paddr->prop->domain;
        
        struct pmppprop_t *p_laddr = make_prop(PMPP_L_INET_LADDR, "", 0, dom_laddr);
        struct pmppprop_t *p_paddr = make_prop(PMPP_L_INET_PADDR, "", 0, dom_paddr);
        
        set_prop(p_laddr, &local->plist);
        
        struct pmppprop_t *p_lport = make_prop(PMPP_L_INET_LPORT, "", 0, p_laddr->domain);
        struct pmppprop_t *p_pport = make_prop(PMPP_L_INET_PPORT, "", 0, p_paddr->domain);
        
        set_prop(p_lport, &local->plist);
        set_prop(p_paddr, &local->plist);
        set_prop(p_pport, &local->plist);
}

void close_sock()
{
        close(socket_udp);
}

/**
 * Attempts to send any pending messages in correspondents' outboxes.
 */
void *flush_outboxes()
{
        while ( pthread_mutex_trylock(&mutex_net) != 0 ); // Wait to obtain a lock.
        
        struct pmppcorreslist_t *iter_1 = local->clist;
        
        while ( iter_1 ) {
                if ( iter_1->corres ) {
                        struct pmppmsglist_t *iter_2 = iter_1->corres->mlist;
                        
                        while ( iter_2 ) {
                                if ( iter_2->msg ) {
                                        enum pmppmessage_t msg_type = PMPP_MT_UNKNOWN;
                                        struct pmppproplist_t *p_msg_type = proplist(PMPP_L_MESSAGE_TYPE, 0, iter_2->msg->plist);
                                        
                                        if ( p_msg_type ) {
                                                msg_type = atoi(p_msg_type->prop->val);
                                                
                                                /*
                                                 * Don't bother sending to correspondents who are offline unless
                                                 * the message being sent is a greeting/ping (which is used to discover
                                                 * reachability).
                                                 */
                                                if ( iter_2->msg->recipient->reachability != PMPP_R_OFFLINE ||
                                                     msg_type == PMPP_MT_GREET ||
                                                     msg_type == PMPP_MT_PING ) {
                                                        if ( iter_2->msg->attempts < PMPP_REACH_ATTEMPT_THRESHOLD ) {
                                                                pmpp_resend_msg(iter_2->msg);
                                                        } else if ( iter_2->msg->attempts == PMPP_REACH_ATTEMPT_THRESHOLD ) {
                                                                iter_2->msg->attempts++; // Increment to avoid infinitely hitting this condition.
                                                                
                                                                // This function can modify the clist AND the mlist.
                                                                int dead_ret = pmpp_dead(&iter_2->msg);
                                                                
                                                                if ( dead_ret != 0 ) { // Reset the outer pointer.
                                                                        iter_1 = local->clist;
                                                                        
                                                                        break;
                                                                }
                                                        }
                                                }
                                        }
                                }
                                
                                iter_2 = iter_2->next;
                        }
                }
                
                iter_1 = iter_1->next;
        }
        
        pthread_mutex_unlock(&mutex_net);
        
        return 0;
}

void *get_in_addr(struct sockaddr *sa)
{
        return sa->sa_family == AF_INET
        ? (void *) &(((struct sockaddr_in*)sa)->sin_addr)
        : (void *) &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/**
 * Pings correspondents at a regular interval to detect when our
 * public IP address has changed.
 * @note The purpose of this function is more to detect the local
 * machine's public IP address changing rather than peers being
 * unreachable (that happens to be an added bonus).
 */
void *keep_alive()
{
        /*
         * In order to be efficient, we won't be pinging everyone.
         * We will randomly pick only 1 remote server to ping.
         * To reduce traffic, this should happen once for every
         * 2 timeouts.
         */
        static int i = 0;
        struct pmppcorreslist_t *iter = local->clist;
        
        if ( i == 1 ) {
                while ( iter ) {
                        if ( iter->corres  ) {
                                // We only want to ping verified, reachable (for all we know) servers.
                                if ( iter->corres->verified == 1 &&
                                     iter->corres->reachability == PMPP_R_ONLINE ) {
                                        struct pmppproplist_t *plist_type = proplist(PMPP_L_UUIDTYPE, 0, iter->corres->plist);
                                        
                                        if ( plist_type &&
                                             atoi(plist_type->prop->val) == PMPP_E_SERVER ) {
                                                int to_ping = random() % 2; // 0 or 1.
                                                
                                                if ( to_ping ) {
                                                        pmpp_ping(iter->corres);
                                                        
                                                        break;
                                                }
                                        }
                                }
                        }
                        
                        iter = iter->next;
                }
                
                i = 0; // Reset.
        } else {
                i++;
        }
        
        return 0;
}

/**
 * This function expects a null-terminated array.
 * It will populate the array with all the local
 * IP addresses of the device (excluding localhost).
 */
void local_addr(char *holder[])
{
        struct ifaddrs *interfaces = NULL;
        struct ifaddrs *temp_addr  = NULL;
        int i       = 0;
        int success = 0;
        
        // Retrieve the current interfaces - returns 0 on success.
        success = getifaddrs(&interfaces);
        
        if ( success == 0 ) {
                temp_addr = interfaces;
                
                while ( temp_addr ) {
                        
                        if ( !holder[i] ) {
                                break;
                        } else if ( temp_addr->ifa_addr ) {
                                if ( temp_addr->ifa_addr->sa_family == AF_INET ) {
                                        holder[i] = net_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr);
                                        
                                        i++;
                                }
                        }
                        
                        temp_addr = temp_addr->ifa_next;
                }
        }
        
        freeifaddrs(interfaces);
}

void *read_tcp()
{
        char s[INET6_ADDRSTRLEN];
        struct sockaddr_storage client_addr;
        socklen_t sin_size = sizeof(client_addr);
        
        while ( 1 ) {
                int new_fd = accept(socket_tcp, (struct sockaddr *)&client_addr, &sin_size);
                
                if ( new_fd == -1 ) {
                        perror("accept");
                        continue;
                }
                
                inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr *)&client_addr), s, sizeof(s));
                printf("LOG: got connection from %s\n", s);
                
                if ( !fork() ) { // this is the child process
                        close(socket_tcp); // child doesn't need the listener
                        
                        if ( send(new_fd, "Hello, world!", 13, 0) == -1 )
                                perror("send");
                        
                        close(new_fd);
                        exit(0);
                }
                
                close(new_fd);  // parent doesn't need this
        }
        
        return 0;
}

void *read_udp()
{
        char  buf[UDP_BUFFER_SIZE];
        char *peer_addr = NULL;
        struct sockaddr_in peer_iaddr;
        socklen_t peer_len = sizeof(peer_iaddr);
        unsigned int peer_port = 0;
        
        while ( 1 ) {
                peer_addr = NULL;
                peer_port = 0;
                
                memset(buf, 0, sizeof(buf));
                recvfrom(socket_udp, buf, UDP_BUFFER_SIZE - 1 , 0, (struct sockaddr *)&peer_iaddr, &peer_len);
                
                peer_addr = net_ntoa(peer_iaddr.sin_addr);
                peer_port = net_ntohs(peer_iaddr);
                
                /*
                 * inet_ntoa() is f'ing notorious for failing.
                 * If it keeps failing, we have no choice but to
                 * drop the message.
                 */
                if ( net_valid_ip(peer_addr) != 1 ) { // Try again!
                        sleep(1);
                        peer_addr = net_ntoa(peer_iaddr.sin_addr);
                }
                
                if ( net_valid_ip(peer_addr) != 1 ) {
                        wtf(0, "inet_ntoa error", 0);
                } else {
                        //printf("Received packet from %s:%d\n", peer_addr, peer_port);
                        //printf("Data: %s\n" , buf);
                        
                        char *msg_str = strdup(buf);
                        struct pmppmsg_t *new_msg = util_atom(msg_str, NULL, NULL, 0);
                        
                        if ( new_msg ) {
                                enum pmppentity_t sender_type = PMPP_E_ANY;
                                enum pmppmessage_t msg_type = PMPP_MT_UNKNOWN;
                                struct pmppcorres_t *sender = NULL;
                                struct pmppprop_t *p_laddr      = NULL;
                                struct pmppprop_t *p_lport      = NULL;
                                struct pmppprop_t *p_paddr      = NULL;
                                struct pmppprop_t *p_pport      = NULL;
                                struct pmppprop_t *p_sender_id  = NULL;
                                struct pmppprop_t *p_server_id  = get_uuidp(PMPP_E_SERVER_SENDER, new_msg->plist);
                                struct pmppprop_t *p_service_id = get_uuidp(PMPP_E_SERVICE, new_msg->plist);
                                struct pmppproplist_t *plist_msg_type = proplist(PMPP_L_MESSAGE_TYPE, 0, new_msg->plist);
                                unsigned int dom_laddr = 0;
                                unsigned int dom_paddr = 0;
                                
                                if ( plist_msg_type )
                                        msg_type = atoi(plist_msg_type->prop->val);
                                
                                if ( msg_type == PMPP_MT_PROBE_RES ) {
                                        printf("");
                                }
                                
                                if ( p_server_id ) {
                                        p_sender_id = p_server_id;
                                        sender_type = PMPP_E_SERVER;
                                        sender = corres(p_sender_id->val, sender_type, local->clist);
                                        
                                        if ( !sender ) { // A newly-added server won't have an ID associated with it yet. Search by IP address in this case.
                                                sender = iaddr_corres(&peer_iaddr, local->clist);
                                                
                                                if ( sender ) {
                                                        // Set their ID.
                                                        set_prop(p_server_id, &sender->plist);
                                                        
                                                        struct pmppprop_t *p_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(sender_type), 0, p_server_id->domain);
                                                        
                                                        set_prop(p_id_type, &sender->plist);
                                                }
                                        }
                                        
                                        if ( sender ) {
                                                struct pmppproplist_t *plist_s_laddr = proplist(PMPP_L_INET_LADDR, 0, sender->plist);
                                                struct pmppproplist_t *plist_s_paddr = proplist(PMPP_L_INET_PADDR, 0, sender->plist);
                                                
                                                // Get the domain of existing address records; use to overwrite them.
                                                if ( plist_s_laddr )
                                                        dom_laddr = plist_s_laddr->prop->domain;
                                                
                                                if ( plist_s_paddr )
                                                        dom_paddr = plist_s_paddr->prop->domain;
                                        }
                                        
                                        // Get their public IP address.
                                        p_paddr = make_prop(PMPP_L_INET_PADDR, peer_addr, 0, dom_paddr);
                                        p_pport = make_prop(PMPP_L_INET_PPORT, util_itoa(peer_port), 0, p_paddr->domain);
                                        
                                        // Get their private IP address from the message itself.
                                        struct pmppproplist_t *plist_laddr = proplist(PMPP_L_INET_LADDR, p_server_id->domain, new_msg->plist);
                                        struct pmppproplist_t *plist_lport = proplist(PMPP_L_INET_LPORT, p_server_id->domain, new_msg->plist);
                                        
                                        if ( plist_laddr ) {
                                                if ( net_valid_ip(plist_laddr->prop->val) == 1 ) {
                                                        p_laddr = clonep(plist_laddr->prop);
                                                        p_laddr->domain = dom_laddr;
                                                        
                                                        if ( plist_lport ) {
                                                                p_lport = clonep(plist_lport->prop);
                                                                p_lport->domain = p_laddr->domain;
                                                        }
                                                }
                                        }
                                        
                                        // Insert the sender's public address.
                                        struct pmppprop_t *pc_paddr = clonep(p_paddr);
                                        struct pmppprop_t *pc_pport = clonep(p_pport);
                                        
                                        pc_paddr->domain = p_server_id->domain;
                                        pc_pport->domain = p_server_id->domain;
                                        
                                        set_prop(pc_paddr, &new_msg->plist);
                                        set_prop(pc_pport, &new_msg->plist);
                                        
                                        char *a_p_paddr = util_ptoa(pc_paddr);
                                        char *a_p_pport = util_ptoa(pc_pport);
                                        
                                        new_msg->pkg = realloc(new_msg->pkg, strlen(new_msg->pkg) + strlen(a_p_paddr) + strlen(a_p_pport) + 1);
                                        
                                        strcat(new_msg->pkg, a_p_paddr);
                                        strcat(new_msg->pkg, a_p_pport);
                                }
                                
                                /*
                                 * Messages coming from local services won't have an identifier.
                                 * Assign one here, along with a timestamp.
                                 */
                                if ( strcmp(peer_addr, LOCALHOST) == 0 &&
                                     p_service_id ) {
                                        p_sender_id = p_service_id;
                                        sender_type = PMPP_E_SERVICE;
                                        
                                        char *tmp_id = uuid();
                                        unsigned int dom_service = domain(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVICE), new_msg->plist);
                                        
                                        sender = corres(p_sender_id->val, sender_type, local->clist);
                                        
                                        struct pmppprop_t *p_id    = make_prop(PMPP_L_UUID, tmp_id, 0, 0);
                                        p_laddr = make_prop(PMPP_L_INET_LADDR, peer_addr, 0, dom_service);
                                        p_lport = make_prop(PMPP_L_INET_LPORT, util_itoa(peer_port), 0, dom_service);
                                        
                                        set_prop(p_id, &new_msg->plist);
                                        
                                        struct pmppprop_t *p_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_MESSAGE), 0, p_id->domain);
                                        struct pmppprop_t *p_time    = make_prop(PMPP_L_TIME, timestamp(), 0, p_id->domain);
                                        
                                        set_prop(p_id_type, &new_msg->plist);
                                        set_prop(p_time, &new_msg->plist);
                                        
                                        // Now, we need to append the new properties to the original message text.
                                        char *a_p_id      = util_ptoa(p_id);
                                        char *a_p_id_type = util_ptoa(p_id_type);
                                        char *a_p_time    = util_ptoa(p_time);
                                        
                                        new_msg->pkg = realloc(new_msg->pkg, strlen(new_msg->pkg) + strlen(a_p_id) + strlen(a_p_id_type) + strlen(a_p_time) + 1);
                                        
                                        strcat(new_msg->pkg, a_p_id);
                                        strcat(new_msg->pkg, a_p_id_type);
                                        strcat(new_msg->pkg, a_p_time);
                                }
                                
                                if ( !sender ) {
                                        /* 
                                         * Unknown Server Guard
                                         * --
                                         * Messages should only be accepted if they're related
                                         * to a service registered with this server. The only
                                         * exceptions are probes.
                                         */
                                        struct pmppcorres_t *s_reg = NULL;
                                        
                                        if ( p_service_id ||
                                             msg_type == PMPP_MT_PROBE ||
                                             msg_type == PMPP_MT_PROBE_RES ) {
                                                s_reg = corres(p_service_id->val, PMPP_E_SERVICE, local->clist);
                                                
                                                if ( sender_type == PMPP_E_SERVER &&
                                                     msg_type != PMPP_MT_PROBE &&
                                                     msg_type != PMPP_MT_PROBE_RES &&
                                                    (!p_service_id || !s_reg) ) {
                                                        printf("LOG: message to an unregistered service; dropping…\n");
                                                } else if ( p_sender_id ) {
                                                        // Make a new correspondent at this point.
                                                        sender = make_corres();
                                                        sender->reachability = PMPP_R_ONLINE;
                                                        
                                                        if ( sender ) {
                                                                set_prop(p_sender_id, &sender->plist);
                                                                
                                                                struct pmppprop_t *p_sender_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(sender_type), 0, p_sender_id->domain);
                                                                
                                                                set_prop(p_sender_id_type, &sender->plist);
                                                                printf("LOG: created a new correspondent\n");
                                                        } else {
                                                                wtf(0, "could not create new correspondent", 0);
                                                        }
                                                }
                                        } else {
                                                printf("LOG: message from an unknown server & missing a service identifier; dropping…\n");
                                        }
                                }
                                
                                if ( sender ) {
                                        // Check if their any of their IP addresses changed.
                                        int ip_changed = 0;
                                        struct pmppproplist_t *plist_laddr = proplist(PMPP_L_INET_LADDR, 0, sender->plist);
                                        struct pmppproplist_t *plist_lport = proplist(PMPP_L_INET_LPORT, 0, sender->plist);
                                        struct pmppproplist_t *plist_paddr = proplist(PMPP_L_INET_PADDR, 0, sender->plist);
                                        struct pmppproplist_t *plist_pport = proplist(PMPP_L_INET_PPORT, 0, sender->plist);
                                        struct sockaddr_in peer_laddr = peer_iaddr;
                                        
                                        if ( plist_laddr &&
                                             p_laddr &&
                                             net_valid_ip(plist_laddr->prop->val) == 1 )
                                                if ( strcmp(plist_laddr->prop->val, p_laddr->val) != 0)
                                                        ip_changed = 1;
                                        
                                        if ( ip_changed == 0 &&
                                             plist_lport &&
                                             p_lport )
                                                if ( atoi(plist_lport->prop->val) != atoi(p_lport->val) )
                                                        ip_changed = 1;
                                        
                                        if ( ip_changed == 0 &&
                                             plist_paddr &&
                                             p_paddr &&
                                             net_valid_ip(plist_paddr->prop->val) == 1 )
                                                if ( strcmp(plist_paddr->prop->val, p_paddr->val) != 0)
                                                        ip_changed = 1;
                                        
                                        if ( ip_changed == 0 &&
                                             plist_pport &&
                                             p_pport )
                                                if ( atoi(plist_pport->prop->val) != atoi(p_pport->val) )
                                                        ip_changed = 1;
                                        
                                        // Set the new IP address info.
                                        if ( p_laddr ) {
                                                set_prop(p_laddr, &sender->plist);
                                                
                                                if ( p_lport ) {
                                                        p_lport->domain = p_laddr->domain;
                                                        
                                                        set_prop(p_lport, &sender->plist);
                                                }
                                        }
                                        
                                        if ( p_paddr ) {
                                                set_prop(p_paddr, &sender->plist);
                                                
                                                if ( p_pport ) {
                                                        p_pport->domain = p_paddr->domain;
                                                        
                                                        set_prop(p_pport, &sender->plist);
                                                }
                                        }
                                        
                                        if ( p_laddr &&
                                             p_lport ) // Make a socket struct for the local address if it's available.
                                                peer_laddr = make_iaddr(p_laddr->val, atoi(p_lport->val));
                                        
                                        sender->laddr = peer_laddr;
                                        sender->paddr = peer_iaddr; // The address detected by the socket is always considered the public one (relative to this machine).
                                        new_msg->sender = sender;   // Store a reference to the sender.
                                        
                                        // Dump if the IP address has changed.
                                        if ( ip_changed != 0 ) {
                                                dump_corres(sender);
                                                pmpp_notif_presence_list(sender, sender->reachability, NULL);
                                        }
                                        
                                        // Spawn a new thread to handle the message.
                                        pthread_t t_msg_handler;
                                        
                                        pthread_create(&t_msg_handler, 0, recv_msg, new_msg);
                                }
                        } else {
                                printf("LOG: received non-PMPP message\n");
                        }
                        
                        free(msg_str);
                }
        }
        
        return 0;
}

/**
 * Sends the given message to the given recipient over UDP.
 * @param need_ack A flag indicating whether this message should be periodically
 * resent until an acknowledgement is received.
 */
void *send_udp(struct pmppmsg_t *m, const struct sockaddr_in destination, const int need_ack)
{
        if ( !m )
                return 0;
        
        enum pmppmessage_t msg_type = PMPP_MT_UNKNOWN;
        struct pmppproplist_t *plist_msg_type = proplist(PMPP_L_MESSAGE_TYPE, 0, m->plist); // Check if the message type is already included.
        
        if ( plist_msg_type )
                msg_type = atoi(plist_msg_type->prop->val);
        
        if ( need_ack )
                add_msg(m, &m->recipient->mlist);
        
        if ( !m->pkg ) {
                wtf(0, "send_udp: sending a message that has no ASCII representation", 0);
                
                return 0;
        }
        
        if ( msg_type == PMPP_MT_PING ||
             msg_type == PMPP_MT_GREET ||
             msg_type == PMPP_MT_HAND_EXTEND ||
             m->recipient->rvp == 1 ||
            (m->recipient &&
             m->recipient->reachability != PMPP_R_OFFLINE) ) {
                sendto(socket_udp, m->pkg, strlen(m->pkg) + 1, 0, (struct sockaddr *)&destination, sizeof(destination));
        } else if ( m->recipient &&
                    m->critical != 0 ) {
                dump_corres(m->recipient);
        } else if ( m->critical != 0 ) {
                wtf(0, "send_udp: could not send message", 0);
        }
        
        return 0;
}

/**
 * @attention This function does not change anything in the given correspondent's
 * socket struct. It only modifies its property list.
 */
void set_laddr(const char *addr, const unsigned int port, struct pmppcorres_t *c)
{
        int dom = 0;
        struct pmppproplist_t *plist_laddr = proplist(PMPP_L_INET_LADDR, 0, c->plist);
        
        if ( plist_laddr )
                dom = plist_laddr->prop->domain;
        
        struct pmppprop_t *p_laddr = make_prop(PMPP_L_INET_LADDR, (char *)addr, 0, dom);
        
        set_prop(p_laddr, &c->plist);
        
        struct pmppprop_t *p_lport = make_prop(PMPP_L_INET_LPORT, util_itoa(port), 0, p_laddr->domain);
        
        set_prop(p_lport, &c->plist);
}

/**
 * @attention This function does not change anything in the given correspondent's
 * socket struct. It only modifies its property list.
 */
void set_paddr(const char *addr, const unsigned int port, struct pmppcorres_t *c)
{
        int dom = 0;
        struct pmppproplist_t *plist_paddr = proplist(PMPP_L_INET_PADDR, 0, c->plist);
        
        if ( plist_paddr )
                dom = plist_paddr->prop->domain;
        
        struct pmppprop_t *p_paddr = make_prop(PMPP_L_INET_PADDR, (char *)addr, 0, dom);
        
        set_prop(p_paddr, &c->plist);
        
        struct pmppprop_t *p_pport = make_prop(PMPP_L_INET_PPORT, util_itoa(port), 0, p_paddr->domain);
        
        set_prop(p_pport, &c->plist);
}

void setup_sock(void)
{
        char port_str[8] = {0};
        int ret_val = 0;
        int yes     = 1;
        struct addrinfo *p_tcp;
        struct addrinfo *p_udp;
        struct addrinfo *info_tcp;
        struct addrinfo *info_udp;
        struct addrinfo  hints_tcp;
        struct addrinfo  hints_udp;
        struct sigaction sa;
        
        sprintf(port_str, "%d", PMPP_PORT);
        memset(&hints_tcp, 0, sizeof(hints_tcp));
        memset(&hints_udp, 0, sizeof(hints_udp));
        
        hints_tcp.ai_family   = PF_INET;
        hints_tcp.ai_flags    = AI_PASSIVE;
        hints_tcp.ai_protocol = IPPROTO_TCP;
        hints_tcp.ai_socktype = SOCK_STREAM;
        
        hints_udp.ai_family   = PF_INET;
        hints_udp.ai_flags    = AI_PASSIVE;
        hints_udp.ai_protocol = IPPROTO_UDP;
        hints_udp.ai_socktype = SOCK_DGRAM;
        
        if ( (ret_val = getaddrinfo(NULL, port_str, &hints_tcp, &info_tcp)) != 0 ) {
                char bindError[32];
                
                sprintf(bindError, "getaddrinfo %s", gai_strerror(ret_val));
                wtf(0, bindError, 1);
        }
        
        if ( (ret_val = getaddrinfo(NULL, port_str, &hints_udp, &info_udp)) != 0 ) {
                char bindError[32];
                
                sprintf(bindError, "getaddrinfo %s", gai_strerror(ret_val));
                wtf(0, bindError, 1);
        }
        
        // Loop through all the results and bind to the first we can.
        for ( p_tcp = info_tcp; p_tcp != NULL; p_tcp = p_tcp->ai_next ) {
                if ( (socket_tcp = socket(p_tcp->ai_family, p_tcp->ai_socktype, p_tcp->ai_protocol)) == -1 ) {
                        perror("server: socket");
                        continue;
                }
                
                if ( setsockopt(socket_tcp, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) {
                        char sock_err[32];
                        
                        snprintf(sock_err, sizeof(sock_err), "setup_sock: TCP setsockopt, port %s", port_str);
                        wtf(0, sock_err, 0);
                }
                
                if ( bind(socket_tcp, p_tcp->ai_addr, p_tcp->ai_addrlen) == -1 ) {
                        char bindError[32];
                        
                        snprintf(bindError, sizeof(bindError), "setup_sock: binding to TCP port %s", port_str);
                        close(socket_tcp);
                        wtf(0, bindError, 0);
                        continue;
                }
                
                break;
        }
        
        for ( p_udp = info_udp; p_udp != NULL; p_udp = p_udp->ai_next ) {
                socket_udp = socket(p_udp->ai_family, p_udp->ai_socktype, p_udp->ai_protocol);
                
                if ( socket_udp < 0 )
                        continue;
                
                if ( bind(socket_udp, p_udp->ai_addr, p_udp->ai_addrlen) < 0 ) {
                        char sock_err[32];
                        
                        snprintf(sock_err, sizeof(sock_err), "setup_sock: binding to UDP port %s", port_str);
                        close(socket_udp);
                        wtf(0, sock_err, 0);
                        
                        continue;
                }
                
                break;
        }
        
        if ( !p_tcp )
                wtf(0, "setup_sock: TCP socket failed to bind", 1);
        
        if ( !p_udp )
                wtf(0, "setup_sock: UDP socket failed to bind", 1);
        
        if ( listen(socket_tcp, TCP_BACKLOG) == -1 )
                wtf(0, "setup_sock: TCP socket failed to listen", 1);
        
        sa.sa_handler = sigchld_handler; // Reap all dead processes.
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        
        if ( sigaction(SIGCHLD, &sa, NULL) == -1 )
                wtf(0, "setup_sock: sigaction", 1);
        
        struct sockaddr_in sin_tcp;
        struct sockaddr_in sin_udp;
        socklen_t len_tcp = sizeof(sin_tcp);
        socklen_t len_udp = sizeof(sin_udp);
        
        if ( getsockname(socket_tcp, (struct sockaddr *)&sin_tcp, &len_tcp) == 0 )
                printf("✔ Opened TCP port %hu for PMPP services\n", net_ntohs(sin_tcp));
        
        if ( getsockname(socket_udp, (struct sockaddr *)&sin_udp, &len_udp) == 0 )
                printf("✔ Opened UDP port %hu for PMPP servers\n", net_ntohs(sin_udp));
        
        local->laddr.sin_port = sin_udp.sin_port;
        
        freeaddrinfo(info_tcp);
        freeaddrinfo(info_udp);
}

void sigchld_handler(int s)
{
        // waitpid() might overwrite errno, so we save and restore it.
        int saved_errno = errno;
        
        while ( waitpid(-1, NULL, WNOHANG) > 0 );
        
        errno = saved_errno;
}

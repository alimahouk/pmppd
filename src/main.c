//
//  main.c
//  pmppd
//
//  Created on 3/4/16.
//
//

#include "main.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "crypto.h"
#include "io.h"
#include "net.h"
#include "pmpp.h"
#include "util.h"

pthread_mutex_t mutex_net  = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_util = PTHREAD_MUTEX_INITIALIZER;
struct pmppcorres_t *local = NULL;

int main(int argc, const char *argv[])
{
        signal(SIGINT, handle_signals);
        signal(SIGTERM, handle_signals); // Catch termination signals to clean up first.
        atexit(cleanup);
        crypto_init();
        printf("–––––––––––––––––––\n");
        printf("| PMPP SERVER %s |\n", PMPPD_VER);
        printf("–––––––––––––––––––\n");
        printf("%s\n--\n", timestamp());
        start_pmppd();
        main_loop();
        
        return 0;
}

/**
 * Called when pmppd detects no previous configuration files.
 * Performs initial setup & creates configuration files.
 * @return 0 if initialization succeeds, -1 otherwise.
 */
int setup_pmppd(void)
{
        char *key = NULL;
        char *iv = NULL;
        char *lid = uuid();
        
        if ( lid ) {
                local = make_corres();
                local->verified = 1;
                
                struct pmppprop_t *p_id = make_prop(PMPP_L_UUID, lid, 0, 0);
                
                set_prop(p_id, &local->plist);
                aes_gen(&key, AES256_KEY_SIZE);
                aes_gen(&iv, AES256_IV_SIZE);
                rsa_gen(lid);
                printf("Generated UUID: %s\n", lid);
                
                int ret_boot = io_dump(PMPP_BOOT, lid, 'b');
                
                // Set the local server's identifier & crypto keys.
                struct pmppprop_t *p_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVER), 0, p_id->domain);
                struct pmppprop_t *p_iv = make_prop(PMPP_L_CRYPTO_IV, iv, 0, p_id->domain);
                struct pmppprop_t *p_key = make_prop(PMPP_L_CRYPTO_KEY, key, 0, p_id->domain);
                struct pmppprop_t *p_laddr = make_prop(PMPP_L_INET_LADDR, "", 0, p_id->domain);
                struct pmppprop_t *p_lport = make_prop(PMPP_L_INET_LPORT, "", 0, p_id->domain);
                struct pmppprop_t *p_paddr = make_prop(PMPP_L_INET_PADDR, "", 0, p_id->domain);
                struct pmppprop_t *p_pport = make_prop(PMPP_L_INET_PPORT, "", 0, p_id->domain);
                
                set_prop(p_id_type, &local->plist);
                set_prop(p_iv, &local->plist);
                set_prop(p_key, &local->plist);
                set_prop(p_laddr, &local->plist);
                set_prop(p_lport, &local->plist);
                set_prop(p_paddr, &local->plist);
                set_prop(p_pport, &local->plist);
                
                int ret_corres = dump_corres(local);
                
                if ( ret_boot != 0 )
                        return -1;
                
                if ( ret_corres != 0 )
                        return -1;
                
                return 0;
        }
        
        return -1;
}

/**
 * Called when the program terminates. Perform cleanups here.
 */
void cleanup(void)
{
        printf("\npmppd is shutting down…\a\n");
        pmpp_dist_outboxes();   // Distribute pending messages to the RVPs.
        pmpp_sleep();           // Signal that we're going offline.
        dump_corres(local);     // Save state.
        close_sock();
        crypto_cleanup();
        pthread_mutex_destroy(&mutex_net);
        pthread_mutex_destroy(&mutex_util);
}

void handle_signals(int signal)
{
        switch ( signal ) {
                case SIGINT:
                case SIGTERM:
                        exit(0);
                        
                        break;
                        
                default:
                        break;
        }
}

void main_loop(void)
{
        pthread_t t_sched;
        pthread_t t_tcp_read;
        pthread_t t_udp_read;
        
        setup_sock();
        check_addrs();
        pthread_mutex_init(&mutex_net, NULL);
        pthread_mutex_init(&mutex_util, NULL);
        pthread_create(&t_tcp_read, 0, read_tcp, 0); // socket listening happens on their own threads.
        pthread_create(&t_udp_read, 0, read_udp, 0);
        pthread_create(&t_sched, 0, schedule, 0);
        pmpp_ping_list(local);
        pthread_join(t_udp_read, 0);
}

void *recv_msg(void *m)
{
        struct pmppmsg_t *m_pmpp = m;
        
        pmpp_process_pmppmsg(&m_pmpp);
        
        return 0;
}

void *schedule()
{
        /*
         * SCHEDULING
         * --
         * Upon SIGALRM, call time_out().
         * Set interval timer. We want frequency in ms,
         * but the setitimer call needs seconds and useconds.
         * For every activity that needs to be called after an
         * interval, spawn a thread for it in time_out().
         */
        struct itimerval it_val;
        
        if ( signal(SIGALRM, (void (*)(int))time_out) == SIG_ERR )
                wtf(0, "unable to catch SIGALRM", 1);
        
        it_val.it_value.tv_sec  = PMPP_HEARTBEAT_INTERVAL / 1000;
        it_val.it_value.tv_usec = (PMPP_HEARTBEAT_INTERVAL * 1000) % 1000000;
        it_val.it_interval      = it_val.it_value;
        
        if ( setitimer(ITIMER_REAL, &it_val, NULL) == -1 )
                wtf(0, "error calling setitimer()", 1);
        
        return 0;
}

void start_pmppd(void)
{
        char *l_id = NULL;
        
        io_fetch(PMPP_BOOT, &l_id, 'b');
        
        if ( !l_id ) {
                if ( setup_pmppd() != 0 )
                       wtf(0, "setup error", 1);
        } else {
                if ( is_uuid(l_id) == 0 ) {
                        printf("LOG: local UUID is %s\n", l_id);
                        
                        local = fetch_corres(l_id, 1);
                        
                        if ( !local )
                                wtf(0, "could not load local", 1);
                                
                        clink(local->clist); // Establish associations between the correspondents.
                } else {
                        /*
                         * Ideally, we would like to handle this case more gracefully.
                         * For now, let it crash.
                         */
                        wtf(0, "boot failed", 1);
                }
        }
}

void time_out(void)
{
        pthread_t t_chkaddr;
        pthread_t t_flush;
        pthread_t t_heartbeat;
        
        pthread_create(&t_chkaddr, 0, check_addrs, 0);
        pthread_create(&t_flush, 0, flush_outboxes, 0);
        pthread_create(&t_heartbeat, 0, keep_alive, 0);
}

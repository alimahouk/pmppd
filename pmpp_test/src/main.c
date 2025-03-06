//
//  main.c
//  pmpp_test
//
//  Created on 3/15/16.
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

#define INPUT_BUFFER_SIZE       2048
#define COM_BYE                 "bye:"
#define COM_DROP                "to:"
#define COM_REGISTER_ID         "addid:"
#define COM_REGISTER_IP         "addip:"

char *app_iv  = NULL;
char *app_key = NULL;
pthread_mutex_t mutex_util = PTHREAD_MUTEX_INITIALIZER;
struct pmppcorres_t *local = NULL;
struct pmppmsglist_t *inbox  = NULL;
struct pmppmsglist_t *outbox = NULL;

int main(int argc, const char * argv[])
{
        signal(SIGINT, handle_signals);
        signal(SIGTERM, handle_signals); // Catch termination signals to clean up first.
        atexit(cleanup);
        crypto_init();
        printf("––––––––––––––––––––––––––––\n");
        printf("| PMPP SERVER DEMO SERVICE |\n");
        printf("––––––––––––––––––––––––––––\n");
        printf("%s\n\n", timestamp());
        printf("Welcome! This sample program attempts to make use of the PMPP daemon to communicate with its instances on other machines.\n--\n");
        start();
        main_loop();
        
        return 0;
}

/**
 * Called when pmppd detects no previous configuration files.
 * Performs initial setup & creates configuration files.
 * @return 0 if initialization succeeds, -1 otherwise.
 */
int setup(void)
{
        local = make_corres();
        local->verified = 1;
        
        struct pmppprop_t *p_id = make_prop(PMPP_L_UUID, UUID, 0, 0);
        
        set_prop(p_id, &local->plist);
        rsa_gen(UUID);
        printf("Service UUID: %s\n", UUID);
        
        int ret_boot = io_dump(PMPP_BOOT, UUID, 'b');
        
        // Set the local server's identifier & crypto keys.
        struct pmppprop_t *p_id_type = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVICE), 0, p_id->domain);
        
        set_prop(p_id_type, &local->plist);
        
        int ret_corres = dump_corres(local);
        
        if ( ret_boot != 0 )
                return -1;
        
        if ( ret_corres != 0 )
                return -1;
        
        return 0;
}

/**
 * Called when the program terminates. Perform cleanups here.
 */
void cleanup(void)
{
        printf("\nShutting down…\a\n");
        pmpp_sleep();
        dump_corres(local); // Save state.
        close_sock();
        crypto_cleanup();
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
        char buff[INPUT_BUFFER_SIZE + 1];
        pthread_t t_sched;
        pthread_t t_udp_read;
        
        setup_sock();
        pthread_mutex_init(&mutex_util, NULL);
        pthread_create(&t_udp_read, 0, read_udp, 0); // UDP listening happens on a different thread.
        pthread_create(&t_sched, 0, schedule, 0);
        
        if ( app_iv &&
             app_key )
                pmpp_ping_local();
        else
                pmpp_greet();
        
        while ( 1 ) {
                memset(buff, 0, sizeof(buff));  // Clear the buffer.
                fgets(buff, INPUT_BUFFER_SIZE, stdin);
                strtok(buff, "\n");             // Get rid of the trailing newline from fgets.
                
                if ( has_prefix(buff, COM_BYE) ) {
                        /* Informs the local server that we won't be using it anymore. */
                        
                        pmpp_bye();
                } else if ( has_prefix(buff, COM_DROP) ) {
                        /* Drop a message. */
                        
                        long size = strlen(buff) - strlen(COM_DROP);
                        char *tmp  = malloc(size + 1);
                        
                        memcpy(tmp, &buff[strlen(COM_DROP)], strlen(buff) - strlen(COM_DROP));
                        
                        tmp[size] = '\0';
                        char *arg = strsep(&tmp, " "); // Once the command is extracted, tmp will contain the argument.
                        
                        /* Once the argument is extracted, tmp will contain the remainder of the string for sending. */
                        
                        struct pmppproplist_t *plist   = NULL;
                        struct pmppprop_t *p_content   = make_prop(PMPP_L_PAYLOAD, tmp, 1, 0);
                        
                        set_prop(p_content, &plist);
                        
                        struct pmppprop_t *p_recipient = make_prop(PMPP_L_UUID, arg, 1, p_content->domain);
                        struct pmppprop_t *p_recipient_t = make_prop(PMPP_L_UUIDTYPE, util_itoa(PMPP_E_SERVER), 1, p_content->domain);
                        
                        set_prop(p_recipient, &plist);
                        set_prop(p_recipient_t, &plist);
                        pmpp_send_msg(PMPP_MT_MESSAGE, 1, &plist);
                } else if ( has_prefix(buff, COM_REGISTER_ID) ) {
                        /* Request to register with a remote server using its identifier. */
                        
                        long size = strlen(buff) - strlen(COM_REGISTER_ID);
                        char *tmp  = malloc(size + 1);
                        
                        memcpy(tmp, &buff[strlen(COM_REGISTER_ID)], strlen(buff) - strlen(COM_REGISTER_ID));
                        tmp[size] = '\0';
                        
                        char *arg = strsep(&tmp, "\0"); // Once the IP address is extracted, tmp will contain the port number.
                        
                        if ( strlen(arg) > 0 ) {
                                pmpp_add_id(arg);
                        }
                } else if ( has_prefix(buff, COM_REGISTER_IP) ) {
                        /* Request to register with a remote server using its IP address. */
                        
                        long size = strlen(buff) - strlen(COM_REGISTER_IP);
                        char *tmp  = malloc(size + 1);
                        
                        memcpy(tmp, &buff[strlen(COM_REGISTER_IP)], strlen(buff) - strlen(COM_REGISTER_IP));
                        tmp[size] = '\0';
                        
                        char *arg = strsep(&tmp, ":"); // Once the IP address is extracted, tmp will contain the port number.
                        
                        if ( strlen(arg) > 0 ) {
                                pmpp_add_ip(arg, atoi(tmp));
                        }
                }
        }
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

void start(void)
{
        char *l_id = NULL;
        
        io_fetch(PMPP_BOOT, &l_id, 'b');
        
        if ( !l_id ) {
                if ( setup() != 0 )
                        wtf(0, "setup error", 1);
        } else {
                if ( is_uuid(l_id) == 0 ) {
                        printf("LOG: service UUID is %s\n", l_id);
                        
                        local = fetch_corres(l_id, 1);
                        
                        if ( !local )
                                wtf(0, "could not load service", 1);
                        
                        struct pmppproplist_t *plist_iv = proplist(PMPP_L_CRYPTO_IV, 0, local->plist);
                        struct pmppproplist_t *plist_key = proplist(PMPP_L_CRYPTO_KEY, 0, local->plist);
                        
                        if ( plist_iv )
                                app_iv = plist_iv->prop->val;
                        
                        if ( plist_key )
                                app_key = plist_key->prop->val;
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
        pthread_t t_flush;
        
        pthread_create(&t_flush, 0, flush_outbox, 0);
}

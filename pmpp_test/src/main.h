//
//  main.h
//  pmpp_test
//
//  Created on 3/5/16.
//
//

#ifndef main_h
#define main_h

#include <pthread.h>

#include "pmpptypes.h"

#define AUXILIARY_IP    "192.168.0.123"
#define UUID            "f89c3675-9dae-41fd-baa6-6bd16c68985c"

extern char *app_iv;
extern char *app_key;
extern pthread_mutex_t mutex_util;
extern struct pmppcorres_t *local;
extern struct pmppmsglist_t *inbox;
extern struct pmppmsglist_t *outbox;

int setup(void);

void  cleanup(void);
void  handle_signals(int signal);
void  main_loop(void);
void *recv_msg(void *m);
void *schedule();
void  start(void);
void  time_out(void);

#endif /* main_h */

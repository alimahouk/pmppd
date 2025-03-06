//
//  main.h
//  pmppd
//
//  Created on 3/5/16.
//
//

#ifndef main_h
#define main_h

#include <pthread.h>

#include "pmpptypes.h"

#define PMPPD_VER       "0.1"

extern pthread_mutex_t mutex_net;
extern pthread_mutex_t mutex_util;
extern struct pmppcorres_t *local;

int setup_pmppd(void);

void  cleanup(void);
void  handle_signals(int signal);
void  main_loop(void);
void *recv_msg(void *m);
void *schedule();
void  start_pmppd(void);
void  time_out(void);

#endif /* main_h */

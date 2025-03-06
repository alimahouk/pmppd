//
//  io.h
//  pmppd
//
//  Created on 3/4/16.
//
//

#ifndef io_h
#define io_h

#include <stdio.h>

int io_dump(const char *filename, const char *contents, const char type);
int io_fetch(const char *filename, char **contents, const char type);
int io_remove(const char *filename, const char type);

FILE *io_file(const char *filename, const char type);
FILE *io_make_file(const char *filename, const char type);

#endif /* io_h */

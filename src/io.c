//
//  io.c
//  pmppd
//
//  Created on 3/4/16.
//
//

#include "io.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"

#define CHUNK                   1024            // Read 1024 bytes at a time.
#define PMPP_DIR_CORRES         "pmppdat_c"
#define PMPP_DIR_CRYPTO         "pmppdat_s"
#define PMPP_DIR_MSG            "pmppdat_m"
#define PMPP_DIR_PROP           "pmppdat_p"
#define PMPP_DIR_PERMS          0777
#define PMPP_FILE_EXTENSION     "pmpp"

/**
 * Writes the given text to the given file. This function will overwrite
 * the given file if it exists, otherwise a new file is created.
 *
 * Type Guide:
 *
 * @p b = boot item
 *
 * @p c = correspondent list
 *
 * @p m = message list
 *
 * @p p = property list
 * @return 0 if the operation succeeded.
 */
int io_dump(const char *filename, const char *contents, const char type)
{
        if ( !filename ) {
                wtf(0, "io_dump: bad filename", 0);
                
                return -1;
        }
        
        char *dir  = NULL;
        char *path = NULL;
        
        switch ( type ) {
                        /* Account for space to be taken up by the '/' */
                case 'c':
                        dir = calloc(strlen(PMPP_DIR_CORRES) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_CORRES);
                        
                        break;
                        
                case 'm':
                        dir = calloc(strlen(PMPP_DIR_MSG) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_MSG);
                        
                        break;
                        
                case 'p':
                        dir = calloc(strlen(PMPP_DIR_PROP) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_PROP);
                        
                        break;
                        
                default:
                        break;
        }
        
        if ( type == 'b' ) {
                path = calloc(strlen(filename) + strlen(PMPP_FILE_EXTENSION) + 2, sizeof(char)); // 1 for the '.' before the extension, 1 for '\0'.
                
                strcpy(path, filename);
        } else {
                path = calloc(strlen(dir) + strlen(filename) + strlen(PMPP_FILE_EXTENSION) + 3, sizeof(char)); // 1 for the '/' after the dir, 1 for the '.' before the extension, 1 for '\0'.
                
                /*
                 * First check if the PMPP data directory exists.
                 * If not, create it.
                 */
                struct stat st = {0};
                
                if ( stat(dir, &st) == -1 ) {
                        mkdir(dir, PMPP_DIR_PERMS);
                }
                
                strcpy(path, dir);
                strcat(path, "/");
                strcat(path, filename);
        }
        
        strcat(path, ".pmpp");
        
        FILE *fpointer = fopen(path, "w+");
        
        if ( fpointer ) {
                fputs(contents, fpointer);
                fclose(fpointer);
                
                return 0;
        }
        
        return -1;
}

/**
 * This function will return the text contents of the given
 * file (if it exists) for reading.
 *
 * Type Guide:
 *
 * @p b = boot item
 *
 * @p c = correspondent list
 *
 * @p m = message list
 *
 * @p p = property list
 * @return 0 if the operation succeeded.
 */
int io_fetch(const char *filename, char **buf, const char type)
{
        if ( !filename )
                return -1;
        
        char *dir  = NULL;
        char *path = NULL;
        
        switch ( type ) {
                        /* Account for space to be taken up by the '/' */
                case 'c':
                        dir = calloc(strlen(PMPP_DIR_CORRES) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_CORRES);
                        
                        break;
                        
                case 'm':
                        dir = calloc(strlen(PMPP_DIR_MSG) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_MSG);
                        
                        break;
                        
                case 'p':
                        dir = calloc(strlen(PMPP_DIR_PROP) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_PROP);
                        
                        break;
                        
                default:
                        break;
        }
        
        if ( type == 'b' ) {
                path = calloc(strlen(filename) + strlen(PMPP_FILE_EXTENSION) + 2, sizeof(char)); // 1 for the '.' before the extension, 1 for '\0'.
                
                strcpy(path, filename);
        } else {
                path = calloc(strlen(dir) + strlen(filename) + strlen(PMPP_FILE_EXTENSION) + 3, sizeof(char)); // 1 for the '/' after the dir, 1 for the '.' before the extension, 1 for '\0'.
                
                /*
                 * First check if the PMPP data directory exists.
                 * If not, create it.
                 */
                struct stat st = {0};
                
                if ( stat(dir, &st) == -1 ) {
                        mkdir(dir, PMPP_DIR_PERMS);
                }
                
                strcpy(path, dir);
                strcat(path, "/");
                strcat(path, filename);
        }
        
        strcat(path, ".pmpp");
        
        int fd = open(path, O_RDONLY, 0);
        
        if ( fd != -1 ) {
                off_t len = lseek(fd, 0, SEEK_END); // Get offset at end of file.
                
                lseek(fd, 0, SEEK_SET); // Seek back to beginning.
                
                *buf = calloc((size_t)len + 1, sizeof(char));
                
                if ( *buf ) {
                        ssize_t n = read(fd, *buf, (size_t)len);
                        
                        if ( n == len ) {
                                close(fd);
                                
                                return 0;
                        }
                }
                
                close(fd);
        }
        
        return -1;
}

/**
 * This function will remove the file with the given name.
 *
 * Type Guide:
 *
 * @p b = boot item
 *
 * @p c = correspondent list
 *
 * @p m = message list
 *
 * @p p = property list
 *
 * @p s = RSA key
 * @return 0 on success, -1 otherwise.
 */
int io_remove(const char *filename, const char type)
{
        if ( !filename )
                return -1;
        
        char *dir  = NULL;
        char *path = NULL;
        
        switch ( type ) {
                        /* Account for space to be taken up by the '/' */
                case 'c':
                        dir = calloc(strlen(PMPP_DIR_CORRES) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_CORRES);
                        
                        break;
                        
                case 'm':
                        dir = calloc(strlen(PMPP_DIR_MSG) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_MSG);
                        
                        break;
                        
                case 'p':
                        dir = calloc(strlen(PMPP_DIR_PROP) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_PROP);
                        
                        break;
                        
                case 's':
                        dir = calloc(strlen(PMPP_DIR_CRYPTO) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_CRYPTO);
                        
                        break;
                        
                default:
                        break;
        }
        
        if ( type == 'b' ) {
                path = calloc(strlen(filename) + strlen(PMPP_FILE_EXTENSION) + 2, sizeof(char)); // 1 for the '.' before the extension, 1 for '\0'.
                
                strcpy(path, filename);
        } else {
                path = calloc(strlen(dir) + strlen(filename) + strlen(PMPP_FILE_EXTENSION) + 3, sizeof(char)); // 1 for the '/' after the dir, 1 for the '.' before the extension, 1 for '\0'.
                
                /*
                 * First check if the PMPP data directory exists.
                 * If not, create it.
                 */
                struct stat st = {0};
                
                if ( stat(dir, &st) == -1 ) {
                        mkdir(dir, PMPP_DIR_PERMS);
                }
                
                strcpy(path, dir);
                strcat(path, "/");
                strcat(path, filename);
        }
        
        if ( type == 's' )
                strcat(path, ".pem");
        else
                strcat(path, ".pmpp");
        
        return remove(path);
}

/**
 * This function will return the handle of the given
 * file (if it exists) for reading.
 *
 * Type Guide:
 *
 * @p b = boot item
 *
 * @p c = correspondent list
 *
 * @p m = message list
 *
 * @p p = property list
 *
 * @p s = RSA key
 * @return The file handle.
 */
FILE *io_file(const char *filename, const char type)
{
        if ( !filename )
                return NULL;
        
        char *dir  = NULL;
        char *path = NULL;
        
        switch ( type ) {
                        /* Account for space to be taken up by the '/' */
                case 'c':
                        dir = calloc(strlen(PMPP_DIR_CORRES) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_CORRES);
                        
                        break;
                        
                case 'm':
                        dir = calloc(strlen(PMPP_DIR_MSG) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_MSG);
                        
                        break;
                        
                case 'p':
                        dir = calloc(strlen(PMPP_DIR_PROP) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_PROP);
                        
                        break;
                        
                case 's':
                        dir = calloc(strlen(PMPP_DIR_CRYPTO) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_CRYPTO);
                        
                        break;
                        
                default:
                        break;
        }
        
        if ( type == 'b' ) {
                path = calloc(strlen(filename) + strlen(PMPP_FILE_EXTENSION) + 2, sizeof(char)); // 1 for the '.' before the extension, 1 for '\0'.
                
                strcpy(path, filename);
        } else {
                path = calloc(strlen(dir) + strlen(filename) + strlen(PMPP_FILE_EXTENSION) + 3, sizeof(char)); // 1 for the '/' after the dir, 1 for the '.' before the extension, 1 for '\0'.
                
                /*
                 * First check if the PMPP data directory exists.
                 * If not, create it.
                 */
                struct stat st = {0};
                
                if ( stat(dir, &st) == -1 ) {
                        mkdir(dir, PMPP_DIR_PERMS);
                }
                
                strcpy(path, dir);
                strcat(path, "/");
                strcat(path, filename);
        }
        
        if ( type == 's' )
                strcat(path, ".pem");
        else
                strcat(path, ".pmpp");
        
        FILE *fpointer = fopen(path, "r");
        
        return fpointer;
}

/**
 * Creates a new file & returns its handle. This function will 
 * overwrite the given file if it already exists.
 *
 * Type Guide:
 *
 * @p b = boot item
 *
 * @p c = correspondent list
 *
 * @p m = message list
 *
 * @p p = property list
 *
 * @p s = RSA key
 * @return The file handle.
 */
FILE *io_make_file(const char *filename, const char type)
{
        if ( !filename )
                return NULL;
        
        char *dir  = NULL;
        char *path = NULL;
        
        switch ( type ) {
                        /* Account for space to be taken up by the '/' */
                case 'c':
                        dir = calloc(strlen(PMPP_DIR_CORRES) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_CORRES);
                        
                        break;
                        
                case 'm':
                        dir = calloc(strlen(PMPP_DIR_MSG) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_MSG);
                        
                        break;
                        
                case 'p':
                        dir = calloc(strlen(PMPP_DIR_PROP) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_PROP);
                        
                        break;
                        
                case 's':
                        dir = calloc(strlen(PMPP_DIR_CRYPTO) + 2, sizeof(char));
                        strcpy(dir, PMPP_DIR_CRYPTO);
                        
                        break;
                        
                default:
                        break;
        }
        
        if ( type == 'b' ) {
                path = calloc(strlen(filename) + strlen(PMPP_FILE_EXTENSION) + 2, sizeof(char)); // 1 for the '.' before the extension, 1 for '\0'.
                
                strcpy(path, filename);
        } else {
                path = calloc(strlen(dir) + strlen(filename) + strlen(PMPP_FILE_EXTENSION) + 3, sizeof(char)); // 1 for the '/' after the dir, 1 for the '.' before the extension, 1 for '\0'.
                
                /*
                 * First check if the PMPP data directory exists.
                 * If not, create it.
                 */
                struct stat st = {0};
                
                if ( stat(dir, &st) == -1 ) {
                        mkdir(dir, PMPP_DIR_PERMS);
                }
                
                strcpy(path, dir);
                strcat(path, "/");
                strcat(path, filename);
        }
        
        if ( type == 's' )
                strcat(path, ".pem");
        else
                strcat(path, ".pmpp");
        
        FILE *fpointer = fopen(path, "w+");
        
        return fpointer;
}
